const FEATURE_LABELS = {
  url_length: 'URL Length',
  domain_length: 'Domain Length',
  path_length: 'Path Length',
  entropy: 'Entropy',
  special_char_ratio: 'Special Chars Ratio',
  digit_ratio: 'Digit Ratio',
  subdomain_count: 'Subdomain Count',
  has_https: 'Uses HTTPS',
  has_ip_address: 'IP Address',
  suspicious_keywords: 'Suspicious Keywords',
  url_depth: 'URL Depth',
  tld_in_path: 'TLD in Path',
}

const FEATURE_TOOLTIPS = {
  url_length: 'Total number of characters in the URL. Phishing URLs are often excessively long to hide malicious intent.',
  domain_length: 'Length of the domain name. Unusually long domains can indicate subdomain tricks used by attackers.',
  path_length: 'Number of characters in the URL path. Long paths with random segments are common in phishing links.',
  entropy: 'Measures randomness of the URL string. High entropy suggests obfuscated or randomly generated phishing URLs.',
  special_char_ratio: 'Proportion of special characters (@, -, _, ., etc). Phishing URLs often abuse these to mimic legitimate sites.',
  digit_ratio: 'Proportion of digits in the URL. Phishing domains often contain random numbers to evade detection.',
  subdomain_count: 'Number of subdomain levels. Attackers use many subdomains to hide the real domain (e.g., google.com.attacker.xyz).',
  has_https: 'Whether the URL uses HTTPS protocol. HTTPS alone does not guarantee safety — phishing sites now widely use it.',
  has_ip_address: 'Whether the domain is an IP address instead of a name. Legitimate services rarely use raw IP addresses.',
  suspicious_keywords: 'Count of security-related keywords (login, verify, secure, etc). Phishing pages heavily use these to appear legitimate.',
  url_depth: 'Number of path segments (/a/b has depth 2). Deep nested paths can hide the true nature of the destination.',
  tld_in_path: 'Whether a top-level domain (.com, .org) appears in the path. This tricks users into misreading the URL structure.',
}

const FEATURE_IMPORTANCE = [
  'suspicious_keywords', 'has_ip_address', 'has_https', 'tld_in_path',
  'entropy', 'subdomain_count', 'digit_ratio', 'special_char_ratio',
  'domain_length', 'url_length', 'url_depth', 'path_length',
]

function formatFeatureValue(name, value) {
  if (name === 'has_https' || name === 'has_ip_address' || name === 'tld_in_path') {
    return value === 1 ? 'Yes' : 'No'
  }
  if (name === 'suspicious_keywords' || name === 'subdomain_count' || name === 'url_depth') {
    return String(Math.round(value))
  }
  if (name === 'digit_ratio' || name === 'special_char_ratio') {
    return (value * 100).toFixed(1) + '%'
  }
  if (Number.isInteger(value)) return String(value)
  return value.toFixed(3)
}

function TooltipIcon({ text }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      width: '14px', height: '14px', borderRadius: '50%',
      background: '#475569', color: '#cbd5e1', fontSize: '10px',
      cursor: 'help', marginLeft: '4px', flexShrink: 0, lineHeight: '14px',
    }} title={text}>?</span>
  )
}

function ResultCard({ result }) {
  if (!result) return null

  const confidence = result.phishing_probability
  const isPhishing = confidence >= 0.5
  const pct = (confidence * 100).toFixed(1)

  let barColor, badgeBg, badgeColor
  if (confidence < 0.3) {
    barColor = '#22c55e'
    badgeBg = '#14532d'
    badgeColor = '#86efac'
  } else if (confidence < 0.6) {
    barColor = '#eab308'
    badgeBg = '#713f12'
    badgeColor = '#fde047'
  } else {
    barColor = '#ef4444'
    badgeBg = '#7f1d1d'
    badgeColor = '#fca5a5'
  }

  const barWidth = `${pct}%`
  const rawFeatures = result.features || result.top_features || {}
  const featureArray = Array.isArray(rawFeatures)
    ? rawFeatures
    : Object.entries(rawFeatures).map(([name, value]) => ({ name, value }))

  const features = featureArray
    .slice()
    .sort((a, b) => FEATURE_IMPORTANCE.indexOf(a.name) - FEATURE_IMPORTANCE.indexOf(b.name))

  return (
    <div style={{
      background: '#1e293b',
      borderRadius: '12px',
      padding: '1.5rem',
      maxWidth: '600px',
      width: '100%',
      marginTop: '1.5rem',
      border: `1px solid ${barColor}`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem', color: '#f1f5f9' }}>
          Analysis Result
        </h2>
        <span style={{
          padding: '0.25rem 0.75rem',
          borderRadius: '999px',
          fontSize: '0.85rem',
          fontWeight: 600,
          background: badgeBg,
          color: badgeColor,
        }}>
          {isPhishing ? '\u26A0 PHISHING' : '\u2713 SAFE'}
        </span>
      </div>

      {result.whitelisted && (
        <div style={{
          marginBottom: '0.75rem', padding: '0.5rem 0.75rem',
          borderRadius: '8px', background: '#0f172a',
          border: '1px solid #22c55e',
        }}>
          <p style={{ margin: 0, color: '#86efac', fontSize: '0.8rem' }}>
            \u2713 This domain is in the trusted whitelist of known legitimate websites.
          </p>
        </div>
      )}

      <div style={{ marginBottom: '0.75rem' }}>
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.25rem' }}>URL</p>
        <p style={{
          margin: 0,
          color: '#e2e8f0',
          wordBreak: 'break-all',
          fontSize: '0.9rem',
          fontFamily: 'monospace',
        }}>
          {result.url}
        </p>
      </div>

      <div style={{ marginBottom: '0.75rem' }}>
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.25rem' }}>
          Phishing Probability
        </p>
        <div style={{
          width: '100%',
          height: '24px',
          background: '#334155',
          borderRadius: '12px',
          overflow: 'hidden',
          position: 'relative',
        }}>
          <div style={{
            width: barWidth,
            height: '100%',
            background: barColor,
            borderRadius: '12px',
            transition: 'width 0.5s ease',
          }} />
          <span style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            fontSize: '0.8rem',
            fontWeight: 600,
            color: '#f8fafc',
            textShadow: '0 1px 2px rgba(0,0,0,0.5)',
          }}>
            {pct}%
          </span>
        </div>
        <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0.25rem 0 0', textAlign: 'right' }}>
          0-30% safe \u00B7 30-60% suspicious \u00B7 60-100% phishing
        </p>
      </div>

      {features.length > 0 && (
        <div style={{ marginBottom: '0.75rem' }}>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.5rem' }}>
            Top URL Features
            <span style={{ color: '#64748b', fontSize: '0.7rem', marginLeft: '0.5rem' }}>
              (sorted by importance)
            </span>
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {features.slice(0, 6).map((f, i) => {
              const label = FEATURE_LABELS[f.name] || f.name
              const tooltip = FEATURE_TOOLTIPS[f.name] || ''
              const formatted = formatFeatureValue(f.name, f.value)
              const isRisk = f.name === 'suspicious_keywords' ? f.value > 0
                : f.name === 'has_https' ? f.value === 0
                : f.name === 'has_ip_address' ? f.value === 1
                : f.name === 'tld_in_path' ? f.value === 1
                : f.name === 'entropy' ? f.value > 4
                : f.name === 'subdomain_count' ? f.value > 1
                : f.value > 0.5
              return (
                <div key={i} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.3rem 0.5rem', borderRadius: '6px',
                  background: '#0f172a', fontSize: '0.8rem',
                }}>
                  <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center' }}>
                    {label}
                    {tooltip && <TooltipIcon text={tooltip} />}
                  </span>
                  <span style={{ color: isRisk ? '#fca5a5' : '#86efac', fontWeight: 600 }}>
                    {formatted}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {result.brand_analysis?.has_brand_impersonation && (
        <div style={{
          marginBottom: '0.75rem', padding: '0.5rem 0.75rem',
          borderRadius: '8px', background: '#0f172a',
          border: '1px solid #fca5a5',
        }}>
          <p style={{ color: '#fca5a5', fontSize: '0.85rem', margin: '0 0 0.25rem', fontWeight: 600 }}>
            {'\u26A0'} Brand Impersonation Detected
          </p>
          <p style={{ margin: '0 0 0.25rem', color: '#f1f5f9', fontWeight: 600 }}>
            {result.brand_analysis.brands_detected?.join(', ') || 'Unknown brand'}
          </p>
          {result.brand_analysis.contexts?.map((ctx, i) => (
            <p key={i} style={{ margin: '0.25rem 0 0', color: '#94a3b8', fontSize: '0.8rem', lineHeight: '1.4' }}>
              {ctx}
            </p>
          ))}
          {result.brand_analysis.techniques?.length > 0 && (
            <p style={{ margin: '0.25rem 0 0', color: '#64748b', fontSize: '0.75rem' }}>
              Technique: {result.brand_analysis.techniques.join(', ')}
            </p>
          )}
          <p style={{ margin: '0.25rem 0 0', color: '#94a3b8', fontSize: '0.8rem' }}>
            Risk score: {result.brand_analysis.risk_score?.toFixed(2) || 'N/A'}
          </p>
        </div>
      )}

      <p style={{ color: '#64748b', fontSize: '0.8rem', margin: 0 }}>
        HTML content: {result.html_provided ? '\u2713 Provided' : '\u2717 Not provided'}
      </p>
    </div>
  )
}

export default ResultCard
