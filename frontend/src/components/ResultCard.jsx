const FEATURE_LABELS = {
  url_length: 'URL Length',
  domain_length: 'Domain Length',
  path_length: 'Path Length',
  entropy: 'URL Entropy',
  special_char_ratio: 'Special Chars Ratio',
  digit_ratio: 'Digit Ratio',
  subdomain_count: 'Subdomain Count',
  has_https: 'HTTPS Enabled',
  has_ip_address: 'IP in Domain',
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

function getFeatureRisk(name, value) {
  if (name === 'suspicious_keywords') return value > 0
  if (name === 'has_https') return value === 0
  if (name === 'has_ip_address') return value === 1
  if (name === 'tld_in_path') return value === 1
  if (name === 'entropy') return value > 4
  if (name === 'subdomain_count') return value > 1
  if (name === 'digit_ratio') return value > 0.3
  if (name === 'special_char_ratio') return value > 0.3
  return value > 0.5
}

function ProgressBar({ value, color, height = '20px', showLabel = true }) {
  const pct = Math.min(Math.max(value * 100, 0), 100).toFixed(1)
  return (
    <div style={{
      width: '100%',
      height,
      background: '#1a2332',
      borderRadius: '10px',
      overflow: 'hidden',
      position: 'relative',
    }}>
      <div style={{
        width: `${pct}%`,
        height: '100%',
        background: color,
        borderRadius: '10px',
        transition: 'width 0.5s ease',
      }} />
      {showLabel && (
        <span style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          fontSize: '0.75rem',
          fontWeight: 700,
          color: '#fff',
          textShadow: '0 1px 3px rgba(0,0,0,0.6)',
        }}>
          {pct}%
        </span>
      )}
    </div>
  )
}

function Badge({ children, color, bg }) {
  return (
    <span style={{
      padding: '0.2rem 0.6rem',
      borderRadius: '6px',
      fontSize: '0.75rem',
      fontWeight: 600,
      background: bg || '#1a2332',
      color: color || '#8892b0',
    }}>
      {children}
    </span>
  )
}

function TooltipIcon({ text }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      width: '14px', height: '14px', borderRadius: '50%',
      background: '#1e2a45', color: '#64748b', fontSize: '10px',
      cursor: 'help', marginLeft: '4px', flexShrink: 0, lineHeight: '14px',
    }} title={text}>?</span>
  )
}

function ResultCard({ result }) {
  if (!result) return null

  const confidence = result.phishing_probability
  const isPhishing = confidence >= 0.5
  const pct = (confidence * 100).toFixed(1)

  const barColor = confidence >= 0.6 ? '#ef4444' : confidence >= 0.3 ? '#eab308' : '#10b981'
  const barBg = confidence >= 0.6 ? '#2a1515' : confidence >= 0.3 ? '#2a2415' : '#142a15'
  const badgeBg = confidence >= 0.6 ? '#2a1515' : confidence >= 0.3 ? '#2a2415' : '#142a15'
  const badgeColor = confidence >= 0.6 ? '#ef4444' : confidence >= 0.3 ? '#eab308' : '#10b981'
  const badgeLabel = confidence >= 0.6 ? 'PHISHING' : confidence >= 0.3 ? 'SUSPICIOUS' : 'SAFE'
  const badgeIcon = confidence >= 0.6 ? '\u26A0' : '\u2713'

  const rawFeatures = result.features || result.top_features || {}
  const featureArray = Array.isArray(rawFeatures)
    ? rawFeatures
    : Object.entries(rawFeatures).map(([name, value]) => ({ name, value }))

  const features = featureArray
    .slice()
    .sort((a, b) => FEATURE_IMPORTANCE.indexOf(a.name) - FEATURE_IMPORTANCE.indexOf(b.name))

  const brand = result.brand_analysis
  const scanTime = new Date().toLocaleString()

  return (
    <div style={{
      width: '100%',
      maxWidth: '800px',
      marginTop: '1.5rem',
      borderRadius: '12px',
      overflow: 'hidden',
      boxShadow: `0 0 0 1px ${barColor}44`,
    }}>
      {/* Dynamic Top Strip */}
      <div style={{ height: '5px', background: `linear-gradient(90deg, ${barColor}, ${barColor}88)` }} />

      <div style={{ background: '#131b2a', padding: '1.5rem' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Analyzed URL
            </p>
            <p style={{
              margin: 0, color: '#fff', wordBreak: 'break-all', fontSize: '0.9rem',
              fontFamily: 'monospace',
            }}>
              {result.url}
            </p>
          </div>
          <span style={{
            padding: '0.3rem 0.85rem',
            borderRadius: '8px',
            fontSize: '0.85rem',
            fontWeight: 700,
            background: badgeBg,
            color: badgeColor,
            whiteSpace: 'nowrap',
            marginLeft: '1rem',
            flexShrink: 0,
          }}>
            {badgeIcon} {badgeLabel}
          </span>
        </div>

        {/* Whitelist notice */}
        {result.whitelisted && (
          <div style={{
            marginBottom: '1rem', padding: '0.5rem 0.75rem',
            borderRadius: '8px', background: '#142a15',
            border: '1px solid #10b98144',
          }}>
            <p style={{ margin: 0, color: '#10b981', fontSize: '0.8rem' }}>
              {'\u2713'} This domain is in the trusted whitelist of known legitimate websites.
            </p>
          </div>
        )}

        {/* Probability Bar */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
            <span style={{ color: '#8892b0', fontSize: '0.8rem' }}>Phishing Probability</span>
            <span style={{ color: barColor, fontWeight: 700, fontSize: '0.9rem' }}>{pct}%</span>
          </div>
          <ProgressBar value={confidence} color={barColor} />
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
            <span style={{ color: '#10b981', fontSize: '0.7rem' }}>Safe</span>
            <span style={{ color: '#eab308', fontSize: '0.7rem' }}>Suspicious</span>
            <span style={{ color: '#ef4444', fontSize: '0.7rem' }}>Phishing</span>
          </div>
        </div>

        {/* 2-Column Analytics */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '1rem',
        }}>
          {/* Left Column: URL Features */}
          <div>
            <p style={{
              color: '#fff', fontSize: '0.85rem', fontWeight: 600,
              margin: '0 0 0.5rem',
            }}>
              URL Feature Signals
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              {features.slice(0, 6).map((f, i) => {
                const label = FEATURE_LABELS[f.name] || f.name
                const tooltip = FEATURE_TOOLTIPS[f.name] || ''
                const formatted = formatFeatureValue(f.name, f.value)
                const isRisk = getFeatureRisk(f.name, f.value)
                return (
                  <div key={i} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '0.35rem 0.5rem', borderRadius: '6px',
                    background: isRisk ? '#2a1515' : '#0b0f19',
                  }}>
                    <span style={{ color: '#8892b0', fontSize: '0.78rem', display: 'flex', alignItems: 'center' }}>
                      {label}
                      {tooltip && <TooltipIcon text={tooltip} />}
                    </span>
                    <Badge color={isRisk ? '#ef4444' : '#10b981'} bg={isRisk ? '#2a1515' : '#142a15'}>
                      {formatted}
                    </Badge>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Right Column: Advanced Analysis */}
          <div>
            <p style={{
              color: '#fff', fontSize: '0.85rem', fontWeight: 600,
              margin: '0 0 0.5rem',
            }}>
              Advanced Analysis
            </p>

            {/* Brand Impersonation */}
            {brand?.has_brand_impersonation ? (
              <div style={{
                padding: '0.75rem', borderRadius: '8px',
                background: '#2a1515', border: '1px solid #ef444444',
                marginBottom: '0.75rem',
              }}>
                <p style={{ margin: 0, color: '#ef4444', fontSize: '0.8rem', fontWeight: 600 }}>
                  {'\u26A0'} Brand Impersonation
                </p>
                <p style={{ margin: '0.35rem 0', color: '#fff', fontSize: '0.9rem', fontWeight: 600 }}>
                  {brand.brands_detected?.join(', ')}
                </p>
                {brand.contexts?.slice(0, 1).map((ctx, i) => (
                  <p key={i} style={{ margin: '0 0 0.5rem', color: '#94a3b8', fontSize: '0.75rem', lineHeight: '1.4' }}>
                    {ctx}
                  </p>
                ))}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ color: '#8892b0', fontSize: '0.75rem' }}>Risk</span>
                  <div style={{ flex: 1 }}>
                    <ProgressBar
                      value={brand.risk_score}
                      color={brand.risk_score > 0.7 ? '#ef4444' : '#eab308'}
                      height="14px"
                      showLabel={false}
                    />
                  </div>
                  <span style={{ color: '#ef4444', fontSize: '0.8rem', fontWeight: 700, minWidth: '36px', textAlign: 'right' }}>
                    {(brand.risk_score * 100).toFixed(0)}%
                  </span>
                </div>
                {brand.techniques?.length > 0 && (
                  <p style={{ margin: '0.35rem 0 0', color: '#64748b', fontSize: '0.7rem' }}>
                    Technique: {brand.techniques.join(', ')}
                  </p>
                )}
              </div>
            ) : (
              <div style={{
                padding: '0.75rem', borderRadius: '8px',
                background: '#0b0f19', border: '1px solid #1e2a45',
                marginBottom: '0.75rem',
              }}>
                <p style={{ margin: 0, color: '#10b981', fontSize: '0.8rem' }}>
                  {'\u2713'} No brand impersonation detected
                </p>
              </div>
            )}

            {/* Analysis Details */}
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: '#0b0f19', border: '1px solid #1e2a45',
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                <tbody>
                  {[
                    { label: 'AI Confidence', value: `${pct}%`, color: barColor },
                    { label: 'HTML Content', value: result.html_provided ? 'Provided' : 'Not provided', color: result.html_provided ? '#10b981' : '#64748b' },
                    { label: 'Features Extracted', value: `${features.length} signals`, color: '#c4d1ec' },
                    { label: 'Model', value: 'Gated Fusion v2', color: '#c4d1ec' },
                    { label: 'Scan Time', value: scanTime, color: '#64748b' },
                  ].map((row, i) => (
                    <tr key={i}>
                      <td style={{ padding: '0.3rem 0.5rem 0.3rem 0', color: '#64748b', borderBottom: i < 4 ? '1px solid #1e2a45' : 'none' }}>
                        {row.label}
                      </td>
                      <td style={{ padding: '0.3rem 0', color: row.color, fontWeight: 600, textAlign: 'right', borderBottom: i < 4 ? '1px solid #1e2a45' : 'none' }}>
                        {row.value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ResultCard
