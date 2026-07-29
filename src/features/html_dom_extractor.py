"""
HTML DOM feature extractor and text cleaner for phishing detection.

Two outputs:
  1. DOM feature vector (ndarray shape 64,) — exactly 64 structural features
  2. Clean text (str) — plain text stripped of HTML/script/style

Feature groups (64 total):
  [0-6]   Basic tag counts: script, iframe, form, input, password, button, a
  [7-12]  External references: external script, external link ratio,
          external image ratio, favicon external, total links, total images
  [13-18] Security indicators: hidden count, meta refresh, eval count,
          document.write, suspicious JS, empty links
  [19-24] Structural tags: meta, div, p, table, span, ul, li, h*, br
  [25-30] Special tags: comment, noscript, style, link, object/embed,
          sectioning (nav/header/footer)
  [31-38] JS syntactic counts (8): http, https, ., =, +, [, {, (
  [39-54] JS keyword counts (16): function, var, let, const, return,
          if, for, while, try, catch, new, this., null, undefined,
          true, false
  [55-62] JS modern counts (8): Promise, async, await, import, export,
          class, =>, //, /*, 
  [63]    Total HTML attributes
"""

import re
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from bs4 import BeautifulSoup, Comment


SUSPICIOUS_JS_PATTERNS = [
    r"\batob\s*\(",
    r"\bonmouseover\s*=",
    r"\bonclick\s*=",
    r"\bwindow\.location\b",
    r"\bdocument\.location\b",
    r"\btop\.location\b",
]

EVENT_HANDLERS = [
    "onclick", "ondblclick", "onmousedown", "onmouseup",
    "onmouseover", "onmouseout", "onmousemove",
    "onkeydown", "onkeypress", "onkeyup",
    "onsubmit", "onreset", "onfocus", "onblur",
    "onload", "onunload", "onchange", "onselect",
    "onscroll", "onresize", "onerror", "onabort",
    "oncontextmenu", "oninput", "oninvalid",
    "ontouchstart", "ontouchend", "ontouchmove",
]

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img",
    "input", "link", "meta", "param", "source", "track", "wbr",
}


def extract_dom_features(html: str, base_url: str = "") -> np.ndarray:
    """
    Extract a 64-dimensional DOM feature vector from HTML.

    Args:
        html: Raw HTML string.
        base_url: Page URL (used to resolve relative links and detect
                  external references). If empty, relative links count as internal.

    Returns:
        numpy array of shape (64,).
    """
    soup = BeautifulSoup(html, "html.parser")
    base_domain = urlparse(base_url).hostname.lower() if base_url else ""

    def _is_external(href: str) -> bool:
        if not href or href.startswith("#") or href.startswith("javascript:"):
            return False
        parsed = urlparse(href)
        if not parsed.hostname:
            return False
        if base_domain and parsed.hostname.lower() != base_domain:
            return True
        return False

    # ── Tag counts (7) ──
    all_scripts = soup.find_all("script")
    script_count = len(all_scripts)
    iframe_count = len(soup.find_all("iframe"))
    form_count = len(soup.find_all("form"))
    input_elements = soup.find_all("input")
    input_count = len(input_elements)
    password_input_count = sum(1 for i in input_elements if i.get("type") == "password")
    button_count = len(soup.find_all("button"))
    all_links = soup.find_all("a", href=True)
    total_links = len(all_links)
    all_forms = soup.find_all("form", action=True)

    # ── External references (6) ──
    external_script_count = sum(
        1 for s in all_scripts
        if s.get("src") and _is_external(s["src"])
    )
    external_links = sum(1 for a in all_links if _is_external(a["href"]))
    external_forms = sum(1 for f in all_forms if _is_external(f["action"]))
    external_refs = external_links + external_forms
    external_ref_total = total_links + len(all_forms)
    external_link_ratio = round(external_refs / max(external_ref_total, 1), 4)

    all_imgs = soup.find_all("img", src=True)
    total_imgs = len(all_imgs)
    external_imgs = sum(1 for img in all_imgs if _is_external(img["src"]))
    image_external_ratio = round(external_imgs / max(total_imgs, 1), 4)

    favicon_external = 0
    favicon_link = soup.find("link", rel=lambda v: v and "icon" in v.lower())
    if favicon_link and favicon_link.get("href"):
        favicon_external = 1 if _is_external(favicon_link["href"]) else 0

    # ── Security indicators (6) ──
    hidden_count = 0
    for tag in soup.find_all(True):
        style = tag.get("style", "")
        if "display:none" in style.replace(" ", "") or \
           "visibility:hidden" in style.replace(" ", ""):
            hidden_count += 1
        if tag.get("hidden") is not None:
            hidden_count += 1
        if tag.get("type") == "hidden":
            hidden_count += 1

    meta_refresh = 0
    for meta in soup.find_all("meta", attrs={"http-equiv": True}):
        if meta.get("http-equiv", "").lower() == "refresh":
            meta_refresh = 1
            break

    inline_js = " ".join(s.get_text() for s in all_scripts if s.get_text())
    eval_count = len(re.findall(r"\beval\s*\(", inline_js))
    document_write_count = len(re.findall(r"\bdocument\.write\s*\(", inline_js))

    suspicious_js_count = 0
    for pattern in SUSPICIOUS_JS_PATTERNS:
        suspicious_js_count += len(re.findall(pattern, inline_js, re.IGNORECASE))

    empty_link_count = sum(
        1 for a in all_links
        if not a.get("href") or a["href"].strip() in ("#", "")
    )

    # ── Structural tags (12) ──
    meta_tag_count = len(soup.find_all("meta"))
    div_count = len(soup.find_all("div"))
    p_count = len(soup.find_all("p"))
    table_count = len(soup.find_all("table"))
    span_count = len(soup.find_all("span"))
    ul_count = len(soup.find_all("ul"))
    li_count = len(soup.find_all("li"))
    h_count = len(soup.find_all(re.compile(r"^h[1-6]$")))
    br_count = len(soup.find_all("br"))
    comment_count = len(soup.find_all(string=lambda s: isinstance(s, Comment)))
    noscript_count = len(soup.find_all("noscript"))
    style_tag_count = len(soup.find_all("style"))

    # ── Special tags (6) ──
    link_tag_count = len(soup.find_all("link"))
    obj_count = len(soup.find_all(["object", "embed", "applet", "video", "audio", "canvas", "svg"]))
    section_count = len(soup.find_all(["nav", "header", "footer", "section", "article", "aside", "main"]))
    void_count = sum(1 for tag in soup.find_all(True) if tag.name.lower() in VOID_ELEMENTS)
    all_tags = soup.find_all(True)
    avg_attrs = round(sum(len(tag.attrs) for tag in all_tags) / max(len(all_tags), 1), 4)

    # Event handler attributes count
    event_count = 0
    attr_count = 0
    for tag in all_tags:
        for attr_name in tag.attrs:
            attr_count += 1
            if attr_name.lower() in EVENT_HANDLERS:
                event_count += 1

    # ── JS syntactic counts (8) ──
    js_http = inline_js.count("http")
    js_https = inline_js.count("https")
    js_dot = inline_js.count(".")
    js_eq = inline_js.count("=")
    js_plus = inline_js.count("+")
    js_bracket = inline_js.count("[")
    js_brace = inline_js.count("{")
    js_paren = inline_js.count("(")

    # ── JS keyword counts (16) ──
    js_function = inline_js.count("function")
    js_var = inline_js.count("var ")
    js_let = inline_js.count("let ")
    js_const = inline_js.count("const ")
    js_return = inline_js.count("return")
    js_if = inline_js.count("if (")
    js_for = inline_js.count("for (")
    js_while = inline_js.count("while (")
    js_try = inline_js.count("try ")
    js_catch = inline_js.count("catch ")
    js_new = inline_js.count("new ")
    js_this = inline_js.count("this.")
    js_null = inline_js.count("null")
    js_undefined = inline_js.count("undefined")
    js_true = inline_js.count("true")
    js_false = inline_js.count("false")

    # ── JS modern counts (8) ──
    js_promise = inline_js.count("Promise")
    js_async = inline_js.count("async")
    js_await = inline_js.count("await")
    js_import = inline_js.count("import ")
    js_export = inline_js.count("export ")
    js_class = inline_js.count("class ")
    js_arrow = inline_js.count("=>")
    js_comment_single = inline_js.count("//")
    js_comment_multi = inline_js.count("/*")

    # ── Build 64-dim vector ──
    features = np.zeros(64, dtype=np.float32)

    # Group 1: Basic tag counts (7)
    f = [script_count, iframe_count, form_count, input_count,
         password_input_count, button_count, total_links]
    features[0:7] = f

    # Group 2: External references (6)
    f = [external_script_count, external_link_ratio,
         image_external_ratio, favicon_external, total_imgs, external_links]
    features[7:13] = f

    # Group 3: Security indicators (6)
    f = [hidden_count, meta_refresh, eval_count, document_write_count,
         suspicious_js_count, empty_link_count]
    features[13:19] = f

    # Group 4: Structural tags (6)
    f = [meta_tag_count, div_count, p_count, table_count, span_count, ul_count]
    features[19:25] = f

    # Group 5: Special tags (6)
    f = [li_count, h_count, br_count, comment_count, noscript_count, style_tag_count]
    features[25:31] = f

    # Group 6: Link/Object tags (4)
    f = [link_tag_count, obj_count, section_count, void_count]
    features[31:35] = f

    # Group 7: Event/Attr (3)
    f = [event_count, attr_count, avg_attrs]
    features[35:38] = f

    # Group 8: JS syntactic (8)
    f = [js_http, js_https, js_dot, js_eq, js_plus, js_bracket, js_brace, js_paren]
    features[38:46] = f

    # Group 9: JS keywords (12)
    f = [js_function, js_var, js_let, js_const, js_return,
         js_if, js_for, js_while, js_try, js_catch, js_new, js_this]
    features[46:58] = f

    # Group 10: JS values (4)
    f = [js_null, js_undefined, js_true, js_false]
    features[58:62] = f

    # Group 11: JS modern (2)
    f = [js_promise, js_async]
    features[62:64] = f

    return features


def extract_clean_text(html: str, max_chars: int = 8192) -> str:
    """
    Extract clean plain text from HTML.

    Strips script, style, noscript, comments; collapses whitespace;
    truncates to max_chars (default 8192 for ModernBERT long context).

    Args:
        html: Raw HTML string.
        max_chars: Maximum character length.

    Returns:
        Clean text string.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()
    text = text[:max_chars]
    return text


def extract_html_features(html: str, base_url: str = "", max_chars: int = 8192):
    """
    Full extraction: DOM vector + clean text.

    Args:
        html: Raw HTML string.
        base_url: Page URL for external link detection.
        max_chars: Maximum clean text length.

    Returns:
        Tuple of (dom_vector: np.ndarray shape (64,), clean_text: str)
    """
    dom_vec = extract_dom_features(html, base_url)
    clean_text = extract_clean_text(html, max_chars)
    return dom_vec, clean_text


def extract_html_features_from_file(
    html_path: str | Path, base_url: str = "", max_chars: int = 8192,
    fallback_on_error: bool = True,
):
    """
    Read HTML from file and extract features.

    Args:
        html_path: Path to .html file.
        base_url: Page URL (usually from dataset index).
        max_chars: Maximum clean text length.
        fallback_on_error: If True, return zero vector + empty string on
                           read error (e.g. Windows Defender blocking).

    Returns:
        Tuple of (dom_vector: np.ndarray shape (64,), clean_text: str)
    """
    try:
        html = Path(html_path).read_text(encoding="utf-8", errors="replace")
        return extract_html_features(html, base_url, max_chars)
    except OSError:
        if fallback_on_error:
            return np.zeros(64, dtype=np.float32), ""
        raise


if __name__ == "__main__":
    sample_html = """<!DOCTYPE html>
<html><head><title>Test</title></head>
<body>
    <form action="/login" method="POST">
        <input type="text" name="user" />
        <input type="password" name="pass" />
        <input type="submit" />
    </form>
    <script>document.write("<p>test</p>");</script>
    <iframe src="https://evil.com/steal.html"></iframe>
    <a href="https://external.com/phish">click</a>
    <div style="display:none">hidden</div>
</body></html>"""
    dom_vec, clean_text = extract_html_features(sample_html, "https://example.com")
    print(f"DOM vector shape: {dom_vec.shape}")
    print(f"Non-zero features: {np.count_nonzero(dom_vec)}")
    print(f"Clean text: {clean_text[:200]}")
