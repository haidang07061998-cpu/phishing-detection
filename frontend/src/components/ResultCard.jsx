import { useState } from 'react'

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

const DETAIL_LABELS = {
  a_record_count: 'A Records',
  mx_record_count: 'MX Records',
  ns_record_count: 'NS Records',
  ttl: 'TTL (seconds)',
  domain_age_days: 'Domain Age',
  registrar: 'Registrar',
  is_privacy_protected: 'Privacy Protected',
  country: 'Country',
  ssl_valid: 'SSL Valid',
  ssl_age_days: 'SSL Age',
  ssl_issuer_trusted: 'SSL Issuer Trusted',
  redirect_count: 'Redirect Count',
  cross_domain_redirect: 'Cross-Domain Redirect',
}

const SIGNAL_LABELS = {
  script_count: 'Script Tags',
  iframe_count: 'iframes',
  form_count: 'Forms',
  input_count: 'Input Fields',
  password_input: 'Password Fields',
  button_count: 'Buttons',
  total_links: 'Total Links',
  external_scripts: 'External Scripts',
  external_link_ratio: 'External Link Ratio',
  hidden_elements: 'Hidden Elements',
  meta_refresh: 'Meta Refresh',
  eval_count: 'eval() Calls',
  document_write: 'document.write()',
  suspicious_js: 'Suspicious JS Patterns',
  empty_links: 'Empty Links',
}

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
  if (name === 'external_link_ratio') {
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

function formatDetailValue(key, value) {
  if (value === -1 || value === '' || value === undefined) return 'N/A'
  if (key === 'domain_age_days') {
    if (value < 30) return `${value} days`
    if (value < 365) return `${Math.round(value / 30)} months`
    return `${(value / 365).toFixed(1)} years`
  }
  if (key === 'ssl_age_days') return `${value} days`
  if (key === 'ssl_valid' || key === 'ssl_issuer_trusted' || key === 'is_privacy_protected') {
    return value === 1 ? 'Yes' : 'No'
  }
  if (key === 'cross_domain_redirect') {
    if (value === -1) return 'N/A'
    return value === 1 ? 'Yes' : 'No'
  }
  return String(value)
}

function getDetailColor(key, value) {
  if (value === -1 || value === '' || value === undefined) return '#64748b'
  if (key === 'ssl_valid') return value === 1 ? '#10b981' : '#ef4444'
  if (key === 'domain_age_days') return value < 30 ? '#ef4444' : value < 365 ? '#eab308' : '#10b981'
  if (key === 'redirect_count') return value > 2 ? '#ef4444' : '#10b981'
  if (key === 'cross_domain_redirect') return value === 1 ? '#ef4444' : '#10b981'
  if (key === 'is_privacy_protected') return value === 1 ? '#eab308' : '#10b981'
  return '#c4d1ec'
}

function formatSignalRisk(key, value) {
  if (key === 'iframe_count') return value > 0
  if (key === 'eval_count') return value > 0
  if (key === 'document_write') return value > 0
  if (key === 'suspicious_js') return value > 0
  if (key === 'meta_refresh') return value > 0
  if (key === 'password_input') return value > 0
  if (key === 'hidden_elements') return value > 2
  if (key === 'external_scripts') return value > 3
  if (key === 'empty_links') return value > 5
  if (key === 'external_link_ratio') return value > 0.5
  return false
}

function ProgressBar({ value, color, height = '20px', showLabel = true }) {
  const pct = Math.min(Math.max(value * 100, 0), 100).toFixed(1)
  return (
    <div style={{
      width: '100%', height, background: '#1a2332', borderRadius: '10px',
      overflow: 'hidden', position: 'relative',
    }}>
      <div style={{
        width: `${pct}%`, height: '100%', background: color,
        borderRadius: '10px', transition: 'width 0.5s ease',
      }} />
      {showLabel && (
        <span style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)', fontSize: '0.75rem',
          fontWeight: 700, color: '#fff', textShadow: '0 1px 3px rgba(0,0,0,0.6)',
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
      padding: '0.2rem 0.6rem', borderRadius: '6px', fontSize: '0.75rem',
      fontWeight: 600, background: bg || '#1a2332', color: color || '#8892b0',
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

function TabButton({ active, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      padding: '0.4rem 1rem', borderRadius: '6px', border: 'none',
      background: active ? '#3b82f6' : 'transparent',
      color: active ? '#fff' : '#8892b0', fontSize: '0.8rem',
      fontWeight: active ? 600 : 400, cursor: 'pointer',
      transition: 'all 0.15s',
    }}>
      {children}
    </button>
  )
}

function OverviewTab({ result, features, brand, pct, barColor, badgeLabel, badgeIcon, badgeBg, badgeColor, scanTime }) {
  return (
    <>
      <div style={{
        display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem',
      }}>
        <div>
          <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
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

        <div>
          <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
            Advanced Analysis
          </p>

          {brand?.has_brand_impersonation ? (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: '#2a1515', border: '1px solid #ef444444', marginBottom: '0.75rem',
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
                  <ProgressBar value={brand.risk_score} color={brand.risk_score > 0.7 ? '#ef4444' : '#eab308'} height="14px" showLabel={false} />
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
              background: '#0b0f19', border: '1px solid #1e2a45', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: 0, color: '#10b981', fontSize: '0.8rem' }}>
                {'\u2713'} No brand impersonation detected
              </p>
            </div>
          )}

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
    </>
  )
}

function DetailsTab({ dns, ssl }) {
  if (!dns && !ssl) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b', fontSize: '0.9rem' }}>
        No network data available — DNS/WHOIS/SSL extraction requires network access.
      </div>
    )
  }

  const details = { ...dns, ...ssl }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
      <div>
        <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          DNS & WHOIS
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {dns && Object.entries(dns).map(([key, value]) => {
            const label = DETAIL_LABELS[key] || key
            const formatted = formatDetailValue(key, value)
            const color = getDetailColor(key, value)
            return (
              <div key={key} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '0.35rem 0.5rem', borderRadius: '6px', background: '#0b0f19',
              }}>
                <span style={{ color: '#8892b0', fontSize: '0.78rem' }}>{label}</span>
                <span style={{ color, fontSize: '0.78rem', fontWeight: 600, textAlign: 'right' }}>{formatted}</span>
              </div>
            )
          })}
        </div>
      </div>
      <div>
        <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          SSL & Redirect
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {ssl && Object.entries(ssl).map(([key, value]) => {
            const label = DETAIL_LABELS[key] || key
            const formatted = formatDetailValue(key, value)
            const color = getDetailColor(key, value)
            return (
              <div key={key} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '0.35rem 0.5rem', borderRadius: '6px', background: '#0b0f19',
              }}>
                <span style={{ color: '#8892b0', fontSize: '0.78rem' }}>{label}</span>
                <span style={{ color, fontSize: '0.78rem', fontWeight: 600, textAlign: 'right' }}>{formatted}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function BehaviorTab({ domSignals, features }) {
  if (!domSignals || Object.keys(domSignals).length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b', fontSize: '0.9rem' }}>
        No DOM data available — submit an HTML file to see page behavior signals.
      </div>
    )
  }

  const allSignals = [
    ...Object.entries(domSignals).map(([key, value]) => ({ key, value, group: 'DOM' })),
    ...features.filter(f => ['has_https', 'has_ip_address', 'subdomain_count', 'suspicious_keywords', 'entropy'].includes(f.name)).map(f => ({ key: f.name, value: f.value, group: 'URL' })),
  ]

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
      <div>
        <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          DOM Structure
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {['script_count', 'iframe_count', 'form_count', 'input_count', 'password_input', 'button_count', 'total_links', 'hidden_elements', 'meta_refresh'].map(key => {
            if (!(key in domSignals)) return null
            const value = domSignals[key]
            const label = SIGNAL_LABELS[key] || key
            const isRisk = formatSignalRisk(key, value)
            const formatted = formatFeatureValue(key, value)
            return (
              <div key={key} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '0.35rem 0.5rem', borderRadius: '6px',
                background: isRisk ? '#2a1515' : '#0b0f19',
              }}>
                <span style={{ color: '#8892b0', fontSize: '0.78rem' }}>{label}</span>
                <Badge color={isRisk ? '#ef4444' : '#10b981'} bg={isRisk ? '#2a1515' : '#142a15'}>
                  {formatted}
                </Badge>
              </div>
            )
          })}
        </div>
      </div>
      <div>
        <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          JavaScript Signals
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {['external_scripts', 'eval_count', 'document_write', 'suspicious_js', 'empty_links', 'external_link_ratio'].map(key => {
            if (!(key in domSignals)) return null
            const value = domSignals[key]
            const label = SIGNAL_LABELS[key] || key
            const isRisk = formatSignalRisk(key, value)
            const formatted = formatFeatureValue(key, value)
            return (
              <div key={key} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '0.35rem 0.5rem', borderRadius: '6px',
                background: isRisk ? '#2a1515' : '#0b0f19',
              }}>
                <span style={{ color: '#8892b0', fontSize: '0.78rem' }}>{label}</span>
                <Badge color={isRisk ? '#ef4444' : '#10b981'} bg={isRisk ? '#2a1515' : '#142a15'}>
                  {formatted}
                </Badge>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function ResultCard({ result }) {
  const [tab, setTab] = useState('overview')

  if (!result) return null

  const confidence = result.phishing_probability
  const pct = (confidence * 100).toFixed(1)

  const barColor = confidence >= 0.6 ? '#ef4444' : confidence >= 0.3 ? '#eab308' : '#10b981'
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
  const dns = result.dns_whois
  const ssl = result.ssl_redirect
  const domSignals = result.dom_signals
  const scanTime = new Date().toLocaleString()

  return (
    <div style={{
      width: '100%', marginTop: '1.5rem', borderRadius: '12px',
      overflow: 'hidden', boxShadow: `0 0 0 1px ${barColor}44`,
    }}>
      <div style={{ height: '5px', background: `linear-gradient(90deg, ${barColor}, ${barColor}88)` }} />

      <div style={{ background: '#131b2a', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Analyzed URL
            </p>
            <p style={{ margin: 0, color: '#fff', wordBreak: 'break-all', fontSize: '0.9rem', fontFamily: 'monospace' }}>
              {result.url}
            </p>
          </div>
          <span style={{
            padding: '0.3rem 0.85rem', borderRadius: '8px', fontSize: '0.85rem',
            fontWeight: 700, background: badgeBg, color: badgeColor,
            whiteSpace: 'nowrap', marginLeft: '1rem', flexShrink: 0,
          }}>
            {badgeIcon} {badgeLabel}
          </span>
        </div>

        {result.whitelisted && (
          <div style={{
            marginBottom: '1rem', padding: '0.5rem 0.75rem',
            borderRadius: '8px', background: '#142a15', border: '1px solid #10b98144',
          }}>
            <p style={{ margin: 0, color: '#10b981', fontSize: '0.8rem' }}>
              {'\u2713'} This domain is in the trusted whitelist of known legitimate websites.
            </p>
          </div>
        )}

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

        <div style={{
          display: 'flex', gap: '0.25rem', background: '#1a2332',
          borderRadius: '8px', padding: '2px', marginBottom: '1rem',
        }}>
          <TabButton active={tab === 'overview'} onClick={() => setTab('overview')}>Overview</TabButton>
          <TabButton active={tab === 'details'} onClick={() => setTab('details')}>Details</TabButton>
          <TabButton active={tab === 'behavior'} onClick={() => setTab('behavior')}>Behavior</TabButton>
        </div>

        {tab === 'overview' && <OverviewTab {...{ result, features, brand, pct, barColor, badgeLabel, badgeIcon, badgeBg, badgeColor, scanTime }} />}
        {tab === 'details' && <DetailsTab dns={dns} ssl={ssl} />}
        {tab === 'behavior' && <BehaviorTab domSignals={domSignals} features={features} />}
      </div>
    </div>
  )
}

export default ResultCard