import { useState } from 'react'

const WHITELIST_DOMAINS = [
  'google.com', 'googleapis.com', 'googleusercontent.com',
  'gmail.com', 'youtube.com', 'youtu.be', 'blogspot.com',
  'google.vn',
  'microsoft.com', 'office.com', 'office365.com',
  'live.com', 'outlook.com', 'azure.com',
  'github.com', 'githubusercontent.com',
  'facebook.com', 'fb.com', 'fbcdn.net',
  'instagram.com', 'whatsapp.com',
  'apple.com', 'icloud.com',
  'amazon.com', 'aws.amazon.com',
  'twitter.com', 'x.com', 'linkedin.com',
  'telegram.org', 'discord.com', 'slack.com',
  'gitlab.com', 'bitbucket.org', 'npmjs.com',
  'docker.com', 'stackoverflow.com',
  'wikipedia.org', 'wikimedia.org',
  'netflix.com', 'spotify.com', 'adobe.com',
  'paypal.com', 'ebay.com',
  'zoom.us', 'dropbox.com',
  'cloudflare.com',
]

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
  final_url: 'Final URL',
  resolved_ips: 'Resolved IPs',
  ptr_record: 'Reverse DNS (PTR)',
  asn: 'ASN',
  asn_description: 'ISP',
  asn_country: 'ASN Country',
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
  if (name === 'entropy') return value > 4.5
  if (name === 'subdomain_count') return value > 2
  if (name === 'digit_ratio') return value > 0.3
  if (name === 'special_char_ratio') return value > 0.25
  if (name === 'url_length') return value > 75
  if (name === 'domain_length') return value > 30
  if (name === 'path_length') return value > 50
  return value > 0.5
}

function formatDetailValue(key, value, extra) {
  if (value === -1 || value === '' || value === undefined || value === null) return 'N/A'
  if (key === 'domain_age_days') {
    if (value < 30) return `${value} days`
    if (value < 365) return `${Math.round(value / 30)} months`
    return `${(value / 365).toFixed(1)} years`
  }
  if (key === 'ssl_age_days') return `${value} days`
  if (key === 'ssl_valid') return value === 1 ? 'Yes' : 'No'
  if (key === 'ssl_issuer_trusted') {
    const trusted = value === 1 || extra?.trustedCAOverride
    return trusted ? 'Yes' : 'No'
  }
  if (key === 'is_privacy_protected') return value === 1 ? 'Yes' : 'No'
  if (key === 'cross_domain_redirect') {
    if (value === -1) return 'N/A'
    return value === 1 ? 'Yes' : 'No'
  }
  if (key === 'resolved_ips') {
    if (Array.isArray(value)) return value.join(', ') || 'N/A'
    return String(value)
  }
  if (key === 'ptr_record') return value || 'N/A'
  if (key === 'asn') return value ? `AS${value}` : 'N/A'
  if (key === 'asn_description') return value || 'N/A'
  if (key === 'asn_country') return value || 'N/A'
  return String(value)
}

function getDetailColor(key, value, extra) {
  if (value === -1 || value === '' || value === undefined) return '#64748b'
  if (key === 'ssl_valid') return value === 1 ? '#10b981' : '#ef4444'
  if (key === 'ssl_issuer_trusted') {
    const trusted = value === 1 || extra?.trustedCAOverride
    return trusted ? '#10b981' : '#eab308'
  }
  if (key === 'domain_age_days') {
    if (value < 30) return '#ef4444'
    if (value < 365) return '#eab308'
    return '#10b981'
  }
  if (key === 'redirect_count') return value > 4 ? '#ef4444' : value > 2 ? '#eab308' : '#c4d1ec'
  if (key === 'cross_domain_redirect') {
    if (value !== 1) return '#10b981'
    const dest = extra?.finalUrl || ''
    const isKnown = WHITELIST_DOMAINS.some(d => dest.includes(d))
    return isKnown ? '#10b981' : '#ef4444'
  }
  if (key === 'is_privacy_protected') return '#8892b0'
  if (key === 'ttl') {
    if (value < 300 && extra?.whitelisted) return '#c4d1ec'
    if (value < 300) return '#eab308'
    return '#c4d1ec'
  }
  if (key === 'asn_description') return '#c4d1ec'
  if (key === 'asn' || key === 'asn_country') return '#c4d1ec'
  if (key === 'final_url') return '#c4d1ec'
  return '#c4d1ec'
}

function getDetailBadge(key, value, extra) {
  if (key === 'domain_age_days' && value >= 0) {
    if (value < 30) return { text: 'New Domain \u00B7 High Risk', color: '#ef4444', bg: '#2a1515' }
    if (value < 365) return { text: 'Young Domain \u00B7 Suspicious', color: '#eab308', bg: '#2a2415' }
    return { text: 'Established \u00B7 Safe', color: '#10b981', bg: '#142a15' }
  }
  if (key === 'ttl' && value >= 0) {
    if (value < 300 && extra?.whitelisted) return { text: 'Low TTL (CDN/Load Balancing)', color: '#c4d1ec', bg: '#0b0f19' }
    if (value < 300) return { text: 'Low TTL \u00B7 Suspicious', color: '#eab308', bg: '#2a2415' }
  }
  if (key === 'cross_domain_redirect') {
    if (value !== 1) {
      return {
        text: 'No',
        color: '#10b981',
        bgColor: 'rgba(16, 185, 129, 0.1)',
        borderColor: 'rgba(16, 185, 129, 0.4)',
      }
    }
    const dest = (extra?.finalUrl || '').toLowerCase()
    const isKnown = WHITELIST_DOMAINS.some(d => dest.includes(d.toLowerCase()))
    if (isKnown) {
      return {
        text: 'Yes (Whitelisted Destination)',
        color: '#10b981',
        bgColor: 'rgba(16, 185, 129, 0.1)',
        borderColor: 'rgba(16, 185, 129, 0.4)',
      }
    }
    return {
      text: 'Yes (Unknown Destination)',
      color: '#ef4444',
      bgColor: 'rgba(239, 68, 68, 0.1)',
      borderColor: 'rgba(239, 68, 68, 0.4)',
    }
  }
  return null
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

function Gauge({ value, whitelisted }) {
  const pct = Math.min(Math.max(value * 100, 0), 100)
  const r = 85, cx = 102, cy = 96, stroke = 12
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - pct / 100)
  const color = whitelisted ? '#10b981' : (pct >= 60 ? '#ef4444' : pct >= 30 ? '#eab308' : '#10b981')
  const label = whitelisted ? 'SAFE' : (pct >= 60 ? 'PHISHING' : pct >= 30 ? 'SUSPICIOUS' : 'SAFE')
  return (
    <div style={{ textAlign: 'center' }}>
      <svg width="204" height="130" viewBox="0 0 204 130" style={{ display: 'block', margin: '0 auto' }}>
        <path d="M17 122 A 85 85 0 0 1 187 122" fill="none" stroke="#1a2332" strokeWidth={stroke} strokeLinecap="round" />
        <path d="M17 122 A 85 85 0 0 1 187 122" fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 0.6s ease' }} />
        <text x={cx} y={cy - 2} textAnchor="middle" fill="#fff" fontSize="32" fontWeight="bold">{pct.toFixed(0)}%</text>
        <text x={cx} y={cy + 24} textAnchor="middle" fill={color} fontSize="12" fontWeight="700">{label}</text>
      </svg>
      {whitelisted && (
        <span style={{ color: '#10b981', fontSize: '0.65rem', fontWeight: 600, display: 'block', marginTop: '2px' }}>
          {'Bypassed \u00B7 Whitelist'}
        </span>
      )}
    </div>
  )
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

function FeatureImportanceChart({ importance }) {
  if (!importance || Object.keys(importance).length === 0) return null
  const entries = Object.entries(importance)
    .map(([name, val]) => ({ name, val, abs: Math.abs(val) }))
    .sort((a, b) => b.abs - a.abs)
    .slice(0, 8)
  const maxAbs = Math.max(...entries.map(e => e.abs), 0.001)
  return (
    <div style={{ marginTop: '1rem' }}>
      <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
        Feature Impact on Prediction
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
        {entries.map(({ name, val }) => {
          const label = FEATURE_LABELS[name] || name
          const pct = Math.abs(val) / maxAbs * 100
          const isPositive = val > 0
          return (
            <div key={name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ color: '#8892b0', fontSize: '0.72rem', minWidth: '100px', textAlign: 'right', flexShrink: 0 }}>{label}</span>
              <div style={{ flex: 1, height: '16px', background: '#0b0f19', borderRadius: '4px', overflow: 'hidden', position: 'relative' }}>
                <div style={{
                  width: `${pct}%`, height: '100%',
                  background: isPositive ? '#ef4444' : '#10b981',
                  borderRadius: '4px', float: isPositive ? 'left' : 'right',
                  opacity: 0.8, transition: 'width 0.4s ease',
                }} />
              </div>
              <span style={{ color: isPositive ? '#ef4444' : '#10b981', fontSize: '0.72rem', fontWeight: 600, minWidth: '40px', textAlign: 'right' }}>
                {val.toFixed(3)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
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

function formatFeatureBadge(name, value, whitelisted) {
  const formatted = formatFeatureValue(name, value)
  if (name === 'entropy') {
    const label = value > 4.5 ? 'High \u00B7 Suspicious' : value > 3.5 ? 'Medium \u00B7 Neutral' : 'Low \u00B7 Safe'
    const color = whitelisted ? '#8892b0' : (value > 4.5 ? '#ef4444' : value > 3.5 ? '#eab308' : '#10b981')
    return { text: `${formatted} \u00B7 ${label}`, color }
  }
  if (name === 'domain_length') {
    const isLong = value > 20
    return { text: formatted, color: isLong ? '#ef4444' : '#10b981' }
  }
  if (name === 'subdomain_count') {
    const isHigh = value > 2
    return { text: formatted, color: isHigh ? '#ef4444' : '#10b981' }
  }
  if (name === 'digit_ratio') {
    const isHigh = value > 0.3
    return { text: formatted, color: isHigh ? '#ef4444' : '#10b981' }
  }
  return { text: formatted, color: null }
}

function OverviewTab({ result, features, brand, pct, barColor, badgeLabel, badgeIcon, badgeBg, badgeColor, scanTime, importance, confidence }) {
  const suspTld = result.suspicious_tld
  const isShort = result.is_shortener
  const expandedUrl = result.expanded_url

  const morphFeatures = ['url_length', 'domain_length', 'path_length', 'url_depth', 'digit_ratio', 'special_char_ratio']
  const behavFeatures = ['suspicious_keywords', 'has_ip_address', 'tld_in_path', 'has_https', 'subdomain_count', 'entropy']

  const featureMap = {}
  features.forEach(f => { featureMap[f.name] = f })

  const isWhitelisted = result.whitelisted

  return (
    <>
      <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1.25rem', alignItems: 'flex-start' }}>
        <div style={{ flexShrink: 0 }}>
          <Gauge value={confidence} whitelisted={isWhitelisted} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          {!isWhitelisted && importance && <FeatureImportanceChart importance={importance} />}
          {isWhitelisted && (
            <div style={{
              padding: '1rem', borderRadius: '8px', background: '#142a15',
              border: '1px solid #10b98144', marginTop: '1rem',
            }}>
              <p style={{ margin: 0, color: '#10b981', fontSize: '0.85rem', fontWeight: 700 }}>
                {'\u2713'} Whitelisted Domain
              </p>
              <p style={{ margin: '0.35rem 0 0', color: '#94a3b8', fontSize: '0.8rem', lineHeight: '1.4' }}>
                This domain bypassed AI inference — it is in the trusted whitelist of known legitimate websites. The low confidence (0.1%) reflects the whitelist override, not model analysis.
              </p>
            </div>
          )}
        </div>
      </div>
      <div style={{
        display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem',
      }}>
        <div>
          <p style={{ color: '#94a3b8', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.8px', margin: '0 0 0.35rem', borderBottom: '1px solid #1e2a45', paddingBottom: '0.35rem' }}>
            Morphology &amp; Characters
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {morphFeatures.map(key => {
              const f = featureMap[key]
              if (!f) return null
              const label = FEATURE_LABELS[f.name] || f.name
              const tooltip = FEATURE_TOOLTIPS[f.name] || ''
              const { text, color } = formatFeatureBadge(f.name, f.value, isWhitelisted)
              const isRisk = !isWhitelisted && getFeatureRisk(f.name, f.value)
              return (
                <div key={f.name} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.3rem 0.5rem', borderRadius: '6px',
                  background: isRisk ? '#2a1515' : '#0b0f19',
                }}>
                  <span style={{ color: '#8892b0', fontSize: '0.76rem', display: 'flex', alignItems: 'center' }}>
                    {label}
                    {tooltip && <TooltipIcon text={tooltip} />}
                  </span>
                  <Badge color={color || (isRisk ? '#ef4444' : '#10b981')} bg={isRisk ? '#2a1515' : '#142a15'}>
                    {text}
                  </Badge>
                </div>
              )
            })}
          </div>
        </div>

        <div>
          <p style={{ color: '#94a3b8', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.8px', margin: '0 0 0.35rem', borderBottom: '1px solid #1e2a45', paddingBottom: '0.35rem' }}>
            Behavioral &amp; Infrastructure
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {behavFeatures.map(key => {
              const f = featureMap[key]
              if (!f) return null
              const label = FEATURE_LABELS[f.name] || f.name
              const tooltip = FEATURE_TOOLTIPS[f.name] || ''
              const { text, color } = formatFeatureBadge(f.name, f.value, isWhitelisted)
              const isRisk = !isWhitelisted && getFeatureRisk(f.name, f.value)
              return (
                <div key={f.name} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.3rem 0.5rem', borderRadius: '6px',
                  background: isRisk ? '#2a1515' : '#0b0f19',
                }}>
                  <span style={{ color: '#8892b0', fontSize: '0.76rem', display: 'flex', alignItems: 'center' }}>
                    {label}
                    {tooltip && <TooltipIcon text={tooltip} />}
                  </span>
                  <Badge color={color || (isRisk ? '#ef4444' : '#10b981')} bg={isRisk ? '#2a1515' : '#142a15'}>
                    {text}
                  </Badge>
                </div>
              )
            })}
            <div style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '0.3rem 0.5rem', borderRadius: '6px',
              background: suspTld && !isWhitelisted ? '#2a1515' : '#0b0f19',
            }}>
              <span style={{ color: '#8892b0', fontSize: '0.76rem', display: 'flex', alignItems: 'center' }}>
                Suspicious TLD
                <TooltipIcon text="Certain TLD extensions (.xyz, .top, .loan ...) are disproportionately used by phishing campaigns due to low registration cost." />
              </span>
              <Badge color={suspTld && !isWhitelisted ? '#ef4444' : '#10b981'} bg={suspTld && !isWhitelisted ? '#2a1515' : '#142a15'}>
                {suspTld ? 'Yes' : 'No'}
              </Badge>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem' }}>
        <div>
          <p style={{ color: '#8892b0', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px', margin: '0 0 0.5rem' }}>
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
        </div>

        <div>
          <p style={{ color: '#8892b0', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px', margin: '0 0 0.5rem' }}>
            Analysis Details
          </p>
          <div style={{
            padding: '0.75rem', borderRadius: '8px',
            background: '#0b0f19', border: '1px solid #1e2a45',
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
              <tbody>
                {[
                  { label: 'AI Confidence', value: `${pct}%`, color: barColor, tooltip: 'Raw output from Gated Fusion model. Sigmoid activation never returns absolute 0 — final decision is determined by the Whitelist Override Layer.' },
                  { label: 'Whitelisted', value: isWhitelisted ? 'Yes' : 'No', color: isWhitelisted ? '#10b981' : '#64748b' },
                  { label: 'URL Shortener', value: isShort ? 'Yes' : 'No', color: isShort ? '#eab308' : '#10b981' },
                  { label: 'Redirect', value: (() => {
                    const cr = result.ssl_redirect?.cross_domain_redirect
                    if (cr !== 1) return 'No'
                    const fu = (result.ssl_redirect?.final_url || '').toLowerCase()
                    const known = WHITELIST_DOMAINS.some(d => fu.includes(d.toLowerCase()))
                    return known ? 'Whitelisted Redirect' : 'Unknown Redirect'
                  })(), color: (() => {
                    const cr = result.ssl_redirect?.cross_domain_redirect
                    if (cr !== 1) return '#10b981'
                    const fu = (result.ssl_redirect?.final_url || '').toLowerCase()
                    const known = WHITELIST_DOMAINS.some(d => fu.includes(d.toLowerCase()))
                    return known ? '#10b981' : '#ef4444'
                  })() },
                  { label: 'Final Destination', value: expandedUrl || 'Same as input', color: '#10b981' },
                  { label: 'HTML Content', value: result.html_provided ? 'Provided' : 'Not provided', color: result.html_provided ? '#10b981' : '#64748b' },
                  { label: 'Features Extracted', value: `${features.length} signals`, color: '#c4d1ec' },
                  { label: 'Model', value: 'Gated Fusion v2', color: '#c4d1ec' },
                  { label: 'Scan Time', value: scanTime, color: '#64748b' },
                ].map((row, i) => (
                  <tr key={i}>
                    <td style={{ padding: '0.25rem 0.5rem 0.25rem 0', color: '#64748b', borderBottom: i < 7 ? '1px solid #1e2a45' : 'none' }}>
                      {row.label}
                      {row.tooltip && <TooltipIcon text={row.tooltip} />}
                    </td>
                    <td style={{ padding: '0.25rem 0', color: row.color, fontWeight: 600, textAlign: 'right', borderBottom: i < 7 ? '1px solid #1e2a45' : 'none', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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

function DetailsTab({ dns, ssl, whitelisted, result }) {
  const trustedCAOverride = result?.url ? /google\.com|youtube\.com|gmail\.com|github\.com|facebook\.com|microsoft\.com|apple\.com|amazon\.com/i.test(result.url) : false
  const finalUrl = ssl?.final_url || ''
  const extra = { whitelisted, trustedCAOverride, finalUrl }

  if (!dns && !ssl) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b', fontSize: '0.9rem' }}>
        No network data available — DNS/WHOIS/SSL extraction requires network access.
      </div>
    )
  }

  const renderRow = (key, value) => {
    const label = DETAIL_LABELS[key] || key
    const formatted = formatDetailValue(key, value, extra)
    const color = getDetailColor(key, value, extra)
    const badge = getDetailBadge(key, value, extra)
    return (
      <div key={key} style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '0.35rem 0.5rem', borderRadius: '6px', background: '#0b0f19', gap: '0.5rem',
      }}>
        <span style={{ color: '#8892b0', fontSize: '0.78rem', flexShrink: 0 }}>{label}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', textAlign: 'right', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {badge ? (
            <span style={{
              padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '0.65rem',
              fontWeight: 600, color: badge.color,
              whiteSpace: 'nowrap',
              backgroundColor: badge.bgColor || badge.bg || 'transparent',
              border: badge.borderColor ? `1px solid ${badge.borderColor}` : 'none',
            }}>{badge.text}</span>
          ) : (
            <span style={{ color, fontSize: '0.78rem', fontWeight: 600 }}>{formatted}</span>
          )}
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
      <div>
        <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          DNS & WHOIS
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {dns && Object.entries(dns).map(([key, value]) => renderRow(key, value))}
        </div>
      </div>
      <div>
        <p style={{ color: '#fff', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          SSL & Redirect
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {ssl && Object.entries(ssl).map(([key, value]) => renderRow(key, value))}
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

function DomainResult({ result }) {
  const dns = result.dns_whois
  return (
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 0 0 1px #3b82f644' }}>
      <div style={{ height: '5px', background: 'linear-gradient(90deg, #3b82f6, #3b82f688)' }} />
      <div style={{ background: '#131b2a', padding: '1.5rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Domain Lookup
          </p>
          <p style={{ margin: 0, color: '#fff', fontSize: '0.9rem', fontFamily: 'monospace' }}>
            {result.domain}
          </p>
        </div>
        <p style={{ color: '#8892b0', fontSize: '0.85rem', margin: '0 0 1rem' }}>
          DNS &amp; WHOIS records — no AI analysis (domain-only lookup)
        </p>
        <DetailsTab dns={dns} ssl={result.ssl_redirect} />
      </div>
    </div>
  )
}

function IpResult({ result }) {
  const dns = result.dns_whois
  const ssl = result.ssl_redirect
  return (
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 0 0 1px #3b82f644' }}>
      <div style={{ height: '5px', background: 'linear-gradient(90deg, #3b82f6, #3b82f688)' }} />
      <div style={{ background: '#131b2a', padding: '1.5rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            IP Lookup
          </p>
          <p style={{ margin: 0, color: '#fff', fontSize: '0.9rem', fontFamily: 'monospace' }}>
            {result.ip}
          </p>
        </div>
        <p style={{ color: '#8892b0', fontSize: '0.85rem', margin: '0 0 1rem' }}>
          Reverse DNS &amp; WHOIS — no AI analysis (IP-only lookup)
        </p>
        <DetailsTab dns={dns} ssl={ssl} />
      </div>
    </div>
  )
}

function ResultCard({ result }) {
  const [tab, setTab] = useState('overview')

  if (!result) return null

  if (result.type === 'domain') return <DomainResult result={result} />
  if (result.type === 'ip') return <IpResult result={result} />

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

        <div style={{
          display: 'flex', gap: '0.25rem', background: '#1a2332',
          borderRadius: '8px', padding: '2px', marginBottom: '1rem',
        }}>
          <TabButton active={tab === 'overview'} onClick={() => setTab('overview')}>Overview</TabButton>
          <TabButton active={tab === 'details'} onClick={() => setTab('details')}>Details</TabButton>
          <TabButton active={tab === 'behavior'} onClick={() => setTab('behavior')}>Behavior</TabButton>
        </div>

        {tab === 'overview' && <OverviewTab {...{ result, features, brand, pct, barColor, badgeLabel, badgeIcon, badgeBg, badgeColor, scanTime, importance: result.feature_importance, confidence }} />}
        {tab === 'details' && <DetailsTab dns={dns} ssl={ssl} whitelisted={result.whitelisted} result={result} />}
        {tab === 'behavior' && <BehaviorTab domSignals={domSignals} features={features} />}
      </div>
    </div>
  )
}

export default ResultCard