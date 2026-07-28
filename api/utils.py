import re
from urllib.parse import urlparse

TWO_PART_TLDS = {
    "co.uk", "com.au", "co.nz", "co.jp", "co.kr",
    "or.jp", "ac.uk", "gov.uk", "org.uk", "net.au",
    "com.vn", "co.vn", "com.sg", "com.hk", "com.tw",
    "co.id", "or.id", "ac.id", "go.id",
}


def get_registered_domain(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.hostname or "").lower()
        domain = domain.split(":")[0]
        if not domain:
            return None
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return domain
        parts = domain.split(".")
        if len(parts) < 2:
            return domain
        if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    except Exception:
        return None


def get_subdomain_info(url: str) -> dict | None:
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or parsed.hostname or "").lower().split(":")[0]
        if not hostname:
            return None
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            return None
        reg_domain = get_registered_domain(url)
        if not reg_domain or hostname == reg_domain:
            return None
        subdomain = hostname[:-(len(reg_domain) + 1)]
        if subdomain:
            sub_parts = subdomain.split(".")
            if sub_parts and sub_parts[-1] in (
                "www", "mail", "smtp", "api", "cdn", "ftp",
                "webmail", "m", "app", "dev", "test", "beta",
            ):
                return None
            return {
                "full_hostname": hostname,
                "registered_domain": reg_domain,
                "subdomain": subdomain,
                "parts": sub_parts,
            }
    except Exception:
        return None
    return None
