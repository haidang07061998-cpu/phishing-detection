import { useState, useEffect } from 'react'
import { getApiHeaders, getApiUrl } from '../api'

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
  'vietnamnet.vn', 'vnexpress.net', 'tuoitre.vn',
  'thanhnien.vn', 'dantri.com.vn', 'nguoiduatin.vn',
  'vov.vn', 'baomoi.com', 'cafef.vn', 'cafebiz.vn',
  'zalo.me', 'chotot.com', 'batdongsan.com.vn',
  'tiki.vn', 'shopee.vn', 'thegioididong.com',
  'vietcombank.com.vn', 'techcombank.com.vn',
  'acb.com.vn', 'vpbank.com.vn', 'mbbank.com.vn',
  'vietinbank.vn', 'bidv.com.vn',
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
  if (value === -1 || value === '' || value === undefined) return 'var(--text-muted)'
  if (key === 'ssl_valid') return value === 1 ? 'var(--success)' : 'var(--danger)'
  if (key === 'ssl_issuer_trusted') {
    const trusted = value === 1 || extra?.trustedCAOverride
    return trusted ? 'var(--success)' : 'var(--warning)'
  }
  if (key === 'domain_age_days') {
    if (value < 30) return 'var(--danger)'
    if (value < 365) return 'var(--warning)'
    return 'var(--success)'
  }
  if (key === 'redirect_count') return value > 4 ? 'var(--danger)' : value > 2 ? 'var(--warning)' : 'var(--text-primary)'
  if (key === 'cross_domain_redirect') {
    if (value !== 1) return 'var(--success)'
    const dest = extra?.finalUrl || ''
    const isKnown = WHITELIST_DOMAINS.some(d => dest.includes(d))
    return isKnown ? 'var(--success)' : 'var(--danger)'
  }
  if (key === 'is_privacy_protected') return 'var(--text-secondary)'
  if (key === 'ttl') {
    if (value < 300 && extra?.whitelisted) return 'var(--text-primary)'
    if (value < 300) return 'var(--warning)'
    return 'var(--text-primary)'
  }
  if (key === 'asn_description') return 'var(--text-primary)'
  if (key === 'asn' || key === 'asn_country') return 'var(--text-primary)'
  if (key === 'final_url') return 'var(--text-primary)'
  return 'var(--text-primary)'
}

function getDetailBadge(key, value, extra) {
  if (key === 'domain_age_days' && value >= 0) {
    if (value < 30) return { text: 'New Domain \u00B7 High Risk', color: 'var(--danger)', bg: 'var(--danger-bg)' }
    if (value < 365) return { text: 'Young Domain \u00B7 Suspicious', color: 'var(--warning)', bg: 'var(--warning-bg)' }
    return { text: 'Established \u00B7 Safe', color: 'var(--success)', bg: 'var(--success-bg)' }
  }
  if (key === 'ttl' && value >= 0) {
    if (value < 300 && extra?.whitelisted) return { text: 'Low TTL (CDN/Load Balancing)', color: 'var(--text-primary)', bg: 'var(--bg-page)' }
    if (value < 300) return { text: 'Low TTL \u00B7 Suspicious', color: 'var(--warning)', bg: 'var(--warning-bg)' }
  }
  if (key === 'cross_domain_redirect') {
    if (value !== 1) {
      return {
        text: 'No',
        color: 'var(--success)',
        bgColor: 'rgba(16, 185, 129, 0.1)',
        borderColor: 'rgba(16, 185, 129, 0.4)',
      }
    }
    const dest = (extra?.finalUrl || '').toLowerCase()
    const isKnown = WHITELIST_DOMAINS.some(d => dest.includes(d.toLowerCase()))
    if (isKnown) {
      return {
        text: 'Yes (Reputable Destination)',
        color: 'var(--warning)',
        bgColor: 'rgba(234, 179, 8, 0.1)',
        borderColor: 'rgba(234, 179, 8, 0.4)',
      }
    }
    return {
      text: 'Yes (Unknown Destination)',
      color: 'var(--danger)',
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
  const color = pct >= 60 ? 'var(--danger)' : pct >= 30 ? 'var(--warning)' : 'var(--success)'
  const label = pct >= 60 ? 'PHISHING' : pct >= 30 ? 'SUSPICIOUS' : 'SAFE'
  return (
    <div style={{ textAlign: 'center' }}>
      <div role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct.toFixed(0)} aria-label={`Risk score ${pct.toFixed(0)} percent, ${label.toLowerCase()}`}>
      <svg width="204" height="130" viewBox="0 0 204 130" style={{ display: 'block', margin: '0 auto' }}>
        <path d="M17 122 A 85 85 0 0 1 187 122" fill="none" stroke="var(--bg-tab)" strokeWidth={stroke} strokeLinecap="round" />
        <path d="M17 122 A 85 85 0 0 1 187 122" fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 0.6s ease' }} />
        <text x={cx} y={cy - 2} textAnchor="middle" fill="var(--text-bright)" fontSize="32" fontWeight="bold">{pct.toFixed(0)}%</text>
        <text x={cx} y={cy + 24} textAnchor="middle" fill={color} fontSize="12" fontWeight="700">{label}</text>
      </svg>
      </div>
      {whitelisted && (
        <span style={{ color: 'var(--success)', fontSize: '0.65rem', fontWeight: 600, display: 'block', marginTop: '2px' }}>
          {'Reputable \u00B7 Analysis Performed'}
        </span>
      )}
    </div>
  )
}

function ProgressBar({ value, color, height = '20px', showLabel = true }) {
  const pct = Math.min(Math.max(value * 100, 0), 100).toFixed(1)
  return (
    <div style={{
      width: '100%', height, background: 'var(--bg-tab)', borderRadius: '10px',
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
      fontWeight: 600, background: bg || 'var(--bg-tab)', color: color || 'var(--text-secondary)',
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
      <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
        Feature Impact on Prediction
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
        {entries.map(({ name, val }) => {
          const label = FEATURE_LABELS[name] || name
          const pct = Math.abs(val) / maxAbs * 100
          const isPositive = val > 0
          return (
            <div key={name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem', minWidth: '100px', textAlign: 'right', flexShrink: 0 }}>{label}</span>
              <div style={{ flex: 1, height: '16px', background: 'var(--bg-page)', borderRadius: '4px', overflow: 'hidden', position: 'relative' }}>
                <div style={{
                  width: `${pct}%`, height: '100%',
                  background: isPositive ? 'var(--danger)' : 'var(--success)',
                  borderRadius: '4px', float: isPositive ? 'left' : 'right',
                  opacity: 0.8, transition: 'width 0.4s ease',
                }} />
              </div>
              <span style={{ color: isPositive ? 'var(--danger)' : 'var(--success)', fontSize: '0.72rem', fontWeight: 600, minWidth: '40px', textAlign: 'right' }}>
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
      background: 'var(--bg-tab)', color: 'var(--text-muted)', fontSize: '10px',
      cursor: 'help', marginLeft: '4px', flexShrink: 0, lineHeight: '14px',
    }} title={text}>?</span>
  )
}

function TabButton({ active, onClick, children }) {
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      style={{
        padding: '0.4rem 1rem', borderRadius: '6px', border: 'none',
        background: active ? 'var(--accent)' : 'transparent',
        color: active ? '#fff' : 'var(--text-secondary)', fontSize: '0.8rem',
        fontWeight: active ? 600 : 400, cursor: 'pointer',
        transition: 'all 0.15s',
      }}
    >
      {children}
    </button>
  )
}

function formatFeatureBadge(name, value, whitelisted, brandInfo) {
  const formatted = formatFeatureValue(name, value)
  if (name === 'entropy') {
    const label = value > 4.5 ? 'High \u00B7 Suspicious' : value > 3.5 ? 'Medium \u00B7 Neutral' : 'Low \u00B7 Safe'
    const color = whitelisted ? 'var(--text-secondary)' : (value > 4.5 ? 'var(--danger)' : value > 3.5 ? 'var(--warning)' : 'var(--success)')
    return { text: `${formatted} \u00B7 ${label}`, color }
  }
  if (name === 'domain_length') {
    const isLong = value > 20
    return { text: formatted, color: isLong ? 'var(--danger)' : 'var(--success)' }
  }
  if (name === 'subdomain_count') {
    const hasBrand = brandInfo?.has_brand_impersonation
    const isHigh = value > 2 || (hasBrand && value > 0)
    return { text: formatted, color: isHigh ? 'var(--danger)' : 'var(--success)' }
  }
  if (name === 'digit_ratio') {
    const isHigh = value > 0.3
    return { text: formatted, color: isHigh ? 'var(--danger)' : 'var(--success)' }
  }
  return { text: formatted, color: null }
}

const ENGINE_LABELS = {
  ai_model: 'AI Model',
  dns_infrastructure: 'DNS Infrastructure',
  url_pattern: 'URL Pattern',
  brand: 'Brand Impersonation',
}

function EngineResultRow({ name, result }) {
  const data = result || {}
  const score = data.score || 0
  const verdict = data.verdict || 'safe'
  const details = data.details || 'No data'
  const color = score >= 60 ? 'var(--danger)' : score >= 30 ? 'var(--warning)' : 'var(--success)'
  const label = ENGINE_LABELS[name] || name
  return (
    <div style={{ marginBottom: '0.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 600 }}>{label}</span>
        <span style={{ color, fontSize: '0.8rem', fontWeight: 700 }}>{score}/100</span>
      </div>
      <div style={{ width: '100%', height: '6px', background: 'var(--bg-tab)', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: '4px', transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>{details}</span>
    </div>
  )
}

function ReputationSection({ reputation }) {
  if (!reputation || !reputation.scans) return null
  const avgScore = reputation.avg_score || 0
  const scanCount = reputation.scans || 0
  const phishingRate = reputation.phishing_rate || 0
  const lastSeen = reputation.last_seen ? new Date(reputation.last_seen).toLocaleString() : 'N/A'
  return (
    <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'var(--bg-page)', border: '1px solid var(--border)', marginTop: '0.75rem' }}>
      <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
        Historical Reputation
      </p>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.78rem' }}>
        <div><span style={{ color: 'var(--text-muted)' }}>Scans: </span><span style={{ color: 'var(--text-bright)', fontWeight: 600 }}>{scanCount}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Avg Score: </span><span style={{ color: avgScore >= 60 ? 'var(--danger)' : avgScore >= 30 ? 'var(--warning)' : 'var(--success)', fontWeight: 600 }}>{avgScore.toFixed(1)}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Phishing Rate: </span><span style={{ color: phishingRate > 0.5 ? 'var(--danger)' : 'var(--success)', fontWeight: 600 }}>{(phishingRate * 100).toFixed(1)}%</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Last: </span><span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{lastSeen}</span></div>
      </div>
    </div>
  )
}

function formatLatency(ms) {
  if (ms == null || Number.isNaN(Number(ms))) return null
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

function getMissingSources(result) {
  const missing = []
  const dns = result?.dns_whois || {}
  const ssl = result?.ssl_redirect || {}
  const dnsMissing = Object.keys(dns).length === 0 || dns.a_record_count === -1 || dns.a_record_count === undefined
  const sslMissing = Object.keys(ssl).length === 0 || ssl.ssl_valid === -1 || ssl.ssl_valid === undefined
  if (!result?.html_provided) missing.push('HTML / DOM')
  else if (result.analysis_quality === 'limited') missing.push('HTML / DOM (parse failed)')
  if (dnsMissing) missing.push('DNS / WHOIS')
  if (sslMissing) missing.push('SSL / Redirect')
  return missing
}

function DataCoverage({ result }) {
  const dns = result?.dns_whois || {}
  const ssl = result?.ssl_redirect || {}
  const items = [
    { key: 'dns', label: 'DNS / WHOIS', ok: Object.keys(dns).length > 0 && dns.a_record_count !== -1 && dns.a_record_count !== undefined },
    { key: 'ssl', label: 'SSL / Redirect', ok: Object.keys(ssl).length > 0 && ssl.ssl_valid !== -1 && ssl.ssl_valid !== undefined },
    { key: 'html', label: 'HTML / DOM', ok: !!result?.html_provided && result?.analysis_quality !== 'limited' },
    { key: 'brand', label: 'Brand Detection', ok: !!(result?.brand_analysis && (result.brand_analysis.brands_detected || []).length > 0) },
  ]
  return (
    <div style={{
      display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '1rem',
    }} role="list" aria-label="Data sources used in this analysis">
      {items.map(it => (
        <span key={it.key} role="listitem" style={{
          display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
          padding: '0.2rem 0.55rem', borderRadius: '999px', fontSize: '0.68rem', fontWeight: 600,
          background: it.ok ? 'var(--success-bg)' : 'var(--bg-tab)',
          color: it.ok ? 'var(--success)' : 'var(--text-muted)',
          border: it.ok ? `1px solid var(--success-border)` : '1px solid var(--border)',
        }}>
          <span aria-hidden="true">{it.ok ? '\u2713' : '\u2013'}</span> {it.label}
        </span>
      ))}
    </div>
  )
}

function ScoreLegend({ result }) {
  const ai = result.phishing_probability
  const agg = result.aggregate_score
  const threat = result.threat_match
  const items = [
    {
      key: 'ai',
      label: 'AI Probability',
      value: ai != null ? `${(ai * 100).toFixed(1)}%` : 'N/A',
      color: ai >= 0.6 ? 'var(--danger)' : ai >= 0.3 ? 'var(--warning)' : 'var(--success)',
      desc: 'Raw Gated-Fusion model output (temperature-scaled sigmoid). Text + URL patterns only.',
    },
    {
      key: 'agg',
      label: 'Aggregate Risk Score',
      value: agg != null ? `${agg}/100` : 'N/A',
      color: agg >= 60 ? 'var(--danger)' : agg >= 30 ? 'var(--warning)' : 'var(--success)',
      desc: 'Weighted vote across AI + DNS + URL + Brand engines. This is the headline verdict.',
    },
    {
      key: 'threat',
      label: 'Threat Intelligence',
      value: threat ? (threat.layer === 'community_feed' ? 'Feed Hit' : 'Blocklist Hit') : 'No Match',
      color: threat ? 'var(--danger)' : 'var(--text-muted)',
      desc: threat
        ? `Matched "${threat.value}" (${threat.source || threat.layer}). A strong signal, not a hard verdict.`
        : 'No known-threat database or blocklist entry matched this URL.',
    },
  ]
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.6rem',
      marginBottom: '1rem', padding: '0.75rem', borderRadius: '8px',
      background: 'var(--bg-page)', border: '1px solid var(--border)',
    }} role="list" aria-label="How the risk numbers differ">
      {items.map(it => (
        <div key={it.key} role="listitem" style={{ padding: '0.4rem 0.6rem', borderRadius: '6px', background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.68rem', fontWeight: 600 }}>{it.label}</span>
            <span style={{ color: it.color, fontSize: '0.78rem', fontWeight: 700 }}>{it.value}</span>
          </div>
          <p style={{ margin: '0.3rem 0 0', color: 'var(--text-muted)', fontSize: '0.68rem', lineHeight: '1.4' }}>{it.desc}</p>
        </div>
      ))}
    </div>
  )
}

function LimitedAnalysisBanner({ result }) {
  const missing = getMissingSources(result)
  if (missing.length === 0) return null
  const reason = result.analysis_reason || ''
  return (
    <div style={{
      marginBottom: '1rem', padding: '0.6rem 0.9rem', borderRadius: '8px',
      background: 'var(--warning-bg)', border: '1px solid var(--warning)44',
    }}>
      <p style={{ margin: 0, color: 'var(--warning)', fontSize: '0.8rem', fontWeight: 700 }}>
        {'\u26A0'} Limited Analysis — missing: {missing.join(', ')}
      </p>
      <p style={{ margin: '0.3rem 0 0', color: 'var(--text-muted)', fontSize: '0.78rem', lineHeight: '1.4' }}>
        {reason
          ? `Reason: ${reason}. `
          : 'Some infrastructure or page signals were unavailable, so the result relies on a subset of evidence. '
          }
        The score still combines the engines that had data.
      </p>
    </div>
  )
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
      <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1.25rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div style={{ flexShrink: 0 }}>
          <Gauge value={confidence} whitelisted={isWhitelisted} />
          <div style={{ textAlign: 'center', marginTop: '0.25rem', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
            Aggregate risk score (0-100)
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
      {!isWhitelisted && importance && <FeatureImportanceChart importance={importance} />}
      <LimitedAnalysisBanner result={result} />
      {isWhitelisted && (
            <div style={{
              padding: '1rem', borderRadius: '8px', background: 'var(--success-bg)',
              border: '1px solid var(--success)44', marginTop: '1rem',
            }}>
              <p style={{ margin: 0, color: 'var(--success)', fontSize: '0.85rem', fontWeight: 700 }}>
                {'\u2713'} Known Reputable Domain
              </p>
              <p style={{ margin: '0.35rem 0 0', color: 'var(--text-muted)', fontSize: '0.8rem', lineHeight: '1.4' }}>
                This domain is known reputable, but a full URL / brand / content analysis was still performed. The risk score reflects the analysis — reputation only lowers it, never overrides it.
              </p>
            </div>
          )}
        </div>
      </div>

      <DataCoverage result={result} />

      <ScoreLegend result={result} />

      {result.explanation && (
        <div style={{
          marginBottom: '1.25rem', padding: '1rem', borderRadius: '8px',
          background: !isWhitelisted && confidence >= 0.6 ? 'var(--danger-bg)' : !isWhitelisted && confidence >= 0.3 ? 'var(--warning-bg)' : 'var(--bg-page)',
          border: `1px solid ${barColor}44`,
        }}>
          <p style={{ margin: '0 0 0.5rem', color: barColor, fontSize: '0.85rem', fontWeight: 700 }}>
            {badgeIcon} Analysis Summary
          </p>
          <p style={{ margin: '0 0 0.75rem', color: 'var(--text-strong)', fontSize: '0.85rem', lineHeight: '1.6' }}>
            {result.explanation.verdict_summary}
          </p>
          {result.explanation.key_findings?.length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Key Findings</p>
              {result.explanation.key_findings.map((f, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.35rem', marginBottom: '0.2rem' }}>
                  <span style={{ color: barColor, fontSize: '0.75rem', flexShrink: 0 }}>{'\u2022'}</span>
                  <span style={{ color: 'var(--text-soft)', fontSize: '0.78rem', lineHeight: '1.4' }}>{f}</span>
                </div>
              ))}
            </div>
          )}
          {result.explanation.recommendations?.length > 0 && (
            <div style={{ padding: '0.5rem 0.6rem', borderRadius: '6px', background: 'var(--bg-subtle)', marginTop: '0.25rem' }}>
              <p style={{ margin: '0 0 0.25rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Recommendations</p>
              {result.explanation.recommendations.map((r, i) => (
                <p key={i} style={{ margin: '0 0 0.15rem', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                  {i + 1}. {r}
                </p>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem',
      }}>
        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.8px', margin: '0 0 0.35rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.35rem' }}>
            Morphology &amp; Characters
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {morphFeatures.map(key => {
              const f = featureMap[key]
              if (!f) return null
              const label = FEATURE_LABELS[f.name] || f.name
              const tooltip = FEATURE_TOOLTIPS[f.name] || ''
              const { text, color } = formatFeatureBadge(f.name, f.value, isWhitelisted, brand)
              const isRisk = !isWhitelisted && getFeatureRisk(f.name, f.value)
              return (
                <div key={f.name} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.3rem 0.5rem', borderRadius: '6px',
                  background: isRisk ? 'var(--danger-bg)' : 'var(--bg-page)',
                }}>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.76rem', display: 'flex', alignItems: 'center' }}>
                    {label}
                    {tooltip && <TooltipIcon text={tooltip} />}
                  </span>
                  <Badge color={color || (isRisk ? 'var(--danger)' : 'var(--success)')} bg={isRisk ? 'var(--danger-bg)' : 'var(--success-bg)'}>
                    {text}
                  </Badge>
                </div>
              )
            })}
          </div>
        </div>

        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.8px', margin: '0 0 0.35rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.35rem' }}>
            Behavioral &amp; Infrastructure
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {behavFeatures.map(key => {
              const f = featureMap[key]
              if (!f) return null
              const label = FEATURE_LABELS[f.name] || f.name
              const tooltip = FEATURE_TOOLTIPS[f.name] || ''
              const { text, color } = formatFeatureBadge(f.name, f.value, isWhitelisted, brand)
              const isRisk = !isWhitelisted && getFeatureRisk(f.name, f.value)
              return (
                <div key={f.name} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.3rem 0.5rem', borderRadius: '6px',
                  background: isRisk ? 'var(--danger-bg)' : 'var(--bg-page)',
                }}>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.76rem', display: 'flex', alignItems: 'center' }}>
                    {label}
                    {tooltip && <TooltipIcon text={tooltip} />}
                  </span>
                  <Badge color={color || (isRisk ? 'var(--danger)' : 'var(--success)')} bg={isRisk ? 'var(--danger-bg)' : 'var(--success-bg)'}>
                    {text}
                  </Badge>
                </div>
              )
            })}
            <div style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '0.3rem 0.5rem', borderRadius: '6px',
              background: suspTld && !isWhitelisted ? 'var(--danger-bg)' : 'var(--bg-page)',
            }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.76rem', display: 'flex', alignItems: 'center' }}>
                Suspicious TLD
                <TooltipIcon text="Certain TLD extensions (.xyz, .top, .loan ...) are disproportionately used by phishing campaigns due to low registration cost." />
              </span>
              <Badge color={suspTld && !isWhitelisted ? 'var(--danger)' : 'var(--success)'} bg={suspTld && !isWhitelisted ? 'var(--danger-bg)' : 'var(--success-bg)'}>
                {suspTld ? 'Yes' : 'No'}
              </Badge>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
        <div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px', margin: '0 0 0.5rem' }}>
            Advanced Analysis
          </p>
          {brand?.has_brand_impersonation ? (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: 'var(--danger-bg)', border: '1px solid var(--danger)44', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: 0, color: 'var(--danger)', fontSize: '0.8rem', fontWeight: 600 }}>
                {'\u26A0'} Brand Impersonation
              </p>
              <p style={{ margin: '0.35rem 0', color: 'var(--text-bright)', fontSize: '0.9rem', fontWeight: 600 }}>
                {brand.brands_detected?.join(', ')}
              </p>
              {brand.contexts?.slice(0, 1).map((ctx, i) => (
                <p key={i} style={{ margin: '0 0 0.5rem', color: 'var(--text-muted)', fontSize: '0.75rem', lineHeight: '1.4' }}>
                  {ctx}
                </p>
              ))}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>Risk</span>
                <div style={{ flex: 1 }}>
                  <ProgressBar value={brand.risk_score} color={brand.risk_score > 0.7 ? 'var(--danger)' : 'var(--warning)'} height="14px" showLabel={false} />
                </div>
                <span style={{ color: 'var(--danger)', fontSize: '0.8rem', fontWeight: 700, minWidth: '36px', textAlign: 'right' }}>
                  {(brand.risk_score * 100).toFixed(0)}%
                </span>
              </div>
              {brand.techniques?.length > 0 && (
                <p style={{ margin: '0.35rem 0 0', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                  Technique: {brand.techniques.join(', ')}
                </p>
              )}
            </div>
          ) : (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: 'var(--bg-page)', border: '1px solid var(--border)', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: 0, color: 'var(--success)', fontSize: '0.8rem' }}>
                {'\u2713'} No brand impersonation detected
              </p>
            </div>
          )}
          {result.engine_results?.engines && Object.keys(result.engine_results.engines).length > 0 && (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: 'var(--bg-page)', border: '1px solid var(--border)', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: '0 0 0.5rem', color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Engine Results ({result.engine_count || Object.keys(result.engine_results.engines).length})
              </p>
              {Object.entries(result.engine_results.engines).map(([name, data]) => (
                <EngineResultRow key={name} name={name} result={data} />
              ))}
            </div>
          )}
          <ReputationSection reputation={result.reputation} />
        </div>

        <div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px', margin: '0 0 0.5rem' }}>
            Analysis Details
          </p>
          <div style={{
            padding: '0.75rem', borderRadius: '8px',
            background: 'var(--bg-page)', border: '1px solid var(--border)',
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
              <tbody>
                {(() => {
                  const rows = [
                  { label: 'Aggregate Risk Score', value: `${pct}%`, color: barColor, tooltip: 'Calibrated multi-engine score (Temperature Scaling + weighted voting across all engines). This is the headline decision value.' },
                  { label: 'AI Model Probability', value: `${((result.phishing_probability ?? 0) * 100).toFixed(1)}%`, color: result.phishing_probability >= 0.6 ? 'var(--danger)' : result.phishing_probability >= 0.3 ? 'var(--warning)' : 'var(--success)', tooltip: 'Raw Gated-Fusion output (sigmoid of temperature-scaled logits), before multi-engine weighting.' },
                  { label: 'Threat Intelligence', value: (() => {
                    const t = result.threat_match
                    if (!t) return 'No known match'
                    return `${t.value} (${t.source || t.layer || 'feed'})`
                  })(), color: result.threat_match ? 'var(--danger)' : 'var(--text-muted)', tooltip: 'Known-threat database / blocklist / community feed match. A strong signal that never overrides the aggregate score.' },
                  { label: 'Scan Duration', value: formatLatency(result.latency_ms) || 'N/A', color: 'var(--text-primary)', tooltip: 'Total backend analysis time for this scan (DNS + SSL + model inference + engines).' },
                  { label: 'Confidence Range', value: (() => {
                    const b = result.probability_band
                    if (!b || b.low == null) return 'N/A'
                    return `${(b.low * 100).toFixed(1)}% \u2013 ${(b.high * 100).toFixed(1)}%`
                  })(), color: 'var(--text-primary)', tooltip: 'Approximate probability band (±1 logit std) — shows model uncertainty around the point estimate.' },
                  { label: 'Reputable', value: isWhitelisted ? 'Yes' : 'No', color: isWhitelisted ? 'var(--success)' : 'var(--text-muted)', tooltip: 'Known reputable domain — a soft signal only. Full URL / brand / content analysis still runs and can override it.' },
                  { label: 'URL Shortener', value: isShort ? 'Yes' : 'No', color: isShort ? 'var(--warning)' : 'var(--success)' },
                  { label: 'Redirect', value: (() => {
                    const cr = result.ssl_redirect?.cross_domain_redirect
                    if (cr !== 1) return 'No'
                    const fu = (result.ssl_redirect?.final_url || '').toLowerCase()
                    const known = WHITELIST_DOMAINS.some(d => fu.includes(d.toLowerCase()))
                    return known ? 'To Reputable Domain' : 'Unknown Destination'
                  })(), color: (() => {
                    const cr = result.ssl_redirect?.cross_domain_redirect
                    if (cr !== 1) return 'var(--success)'
                    const fu = (result.ssl_redirect?.final_url || '').toLowerCase()
                    const known = WHITELIST_DOMAINS.some(d => fu.includes(d.toLowerCase()))
                    return known ? 'var(--warning)' : 'var(--danger)'
                  })() },
                  { label: 'Final Destination', value: expandedUrl || 'Same as input', color: 'var(--success)' },
                  { label: 'Analysis Quality', value: result.analysis_quality === 'full' ? 'Full' : 'Limited', color: result.analysis_quality === 'full' ? 'var(--success)' : 'var(--warning)' },
                  { label: 'HTML Content', value: result.html_provided ? 'Provided' : 'Not provided', color: result.html_provided ? 'var(--success)' : 'var(--text-muted)' },
                  { label: 'Features Extracted', value: `${features.length} signals`, color: 'var(--text-primary)' },
                  { label: 'Model', value: `Multi-Engine (${result.engine_count || 5})`, color: 'var(--text-primary)' },
                  { label: 'Analyzed At', value: result.timestamp ? new Date(result.timestamp).toLocaleString() : scanTime, color: 'var(--text-muted)' },
                  ]
                  return rows.map((row, i) => (
                  <tr key={i}>
                    <td style={{ padding: '0.25rem 0.5rem 0.25rem 0', color: 'var(--text-muted)', borderBottom: i < rows.length - 1 ? '1px solid var(--border)' : 'none' }}>
                      {row.label}
                      {row.tooltip && <TooltipIcon text={row.tooltip} />}
                    </td>
                    <td style={{ padding: '0.25rem 0', color: row.color, fontWeight: 600, textAlign: 'right', borderBottom: i < rows.length - 1 ? '1px solid var(--border)' : 'none', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {row.value}
                    </td>
                  </tr>
                  ))
                })()}
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
  const subInfo = result?.subdomain_info

  if (!dns && !ssl) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
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
        padding: '0.35rem 0.5rem', borderRadius: '6px', background: 'var(--bg-page)', gap: '0.5rem',
      }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', flexShrink: 0 }}>{label}</span>
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
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
      <div>
        <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          DNS & WHOIS
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {subInfo && (
            <div style={{
              padding: '0.5rem 0.6rem', borderRadius: '6px', marginBottom: '0.25rem',
              background: 'var(--warning-bg)', border: '1px solid var(--warning)44',
            }}>
              <p style={{ margin: '0 0 0.25rem', color: 'var(--warning)', fontSize: '0.7rem', fontWeight: 700 }}>
                {'\u26A0'} Subdomain Note
              </p>
              <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.72rem', lineHeight: '1.5' }}>
                WHOIS data above belongs to <strong style={{ color: 'var(--text-bright)' }}>{subInfo.registered_domain}</strong>, not the subdomain <strong style={{ color: 'var(--text-bright)' }}>{subInfo.subdomain}</strong>. Subdomain-based phishing is a common evasion technique.
              </p>
            </div>
          )}
          {dns && Object.entries(dns).map(([key, value]) => renderRow(key, value))}
        </div>
      </div>
      <div>
        <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          SSL & Redirect
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {ssl && Object.entries(ssl).map(([key, value]) => renderRow(key, value))}
        </div>
      </div>
    </div>
  )
}

function BehaviorTab({ domSignals, features, htmlProvided }) {
  if (!htmlProvided) {
    return (
      <div style={{ textAlign: 'center', padding: '2.5rem 1.5rem', borderRadius: '8px', background: 'var(--bg-page)', border: '1px solid var(--border)' }}>
        <p style={{ margin: '0 0 0.5rem', color: 'var(--warning)', fontSize: '1rem', fontWeight: 700 }}>
          {'\u26A0'} HTML Content Not Provided
        </p>
        <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.85rem', lineHeight: '1.5' }}>
          No HTML content was submitted — DOM analysis is unavailable. Upload an HTML file to enable behavioral analysis including script detection, form tracking, and JavaScript signal extraction.
        </p>
      </div>
    )
  }

  const allSignals = [
    ...Object.entries(domSignals).map(([key, value]) => ({ key, value, group: 'DOM' })),
    ...features.filter(f => ['has_https', 'has_ip_address', 'subdomain_count', 'suspicious_keywords', 'entropy'].includes(f.name)).map(f => ({ key: f.name, value: f.value, group: 'URL' })),
  ]

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
      <div>
        <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
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
                background: isRisk ? 'var(--danger-bg)' : 'var(--bg-page)',
              }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{label}</span>
                <Badge color={isRisk ? 'var(--danger)' : 'var(--success)'} bg={isRisk ? 'var(--danger-bg)' : 'var(--success-bg)'}>
                  {formatted}
                </Badge>
              </div>
            )
          })}
        </div>
      </div>
      <div>
        <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
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
                background: isRisk ? 'var(--danger-bg)' : 'var(--bg-page)',
              }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{label}</span>
                <Badge color={isRisk ? 'var(--danger)' : 'var(--success)'} bg={isRisk ? 'var(--danger-bg)' : 'var(--success-bg)'}>
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
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 0 0 1px var(--accent)44' }}>
      <div style={{ height: '5px', background: 'linear-gradient(90deg, var(--accent), var(--accent)88)' }} />
      <div style={{ background: 'var(--bg-card)', padding: '1.5rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Domain Lookup
          </p>
          <p style={{ margin: 0, color: 'var(--text-bright)', fontSize: '0.9rem', fontFamily: 'monospace' }}>
            {result.domain}
          </p>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 1rem' }}>
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
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 0 0 1px var(--accent)44' }}>
      <div style={{ height: '5px', background: 'linear-gradient(90deg, var(--accent), var(--accent)88)' }} />
      <div style={{ background: 'var(--bg-card)', padding: '1.5rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            IP Lookup
          </p>
          <p style={{ margin: 0, color: 'var(--text-bright)', fontSize: '0.9rem', fontFamily: 'monospace' }}>
            {result.ip}
          </p>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 1rem' }}>
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

  const calibratedScore = (result.aggregate_score != null ? result.aggregate_score : result.phishing_probability * 100) / 100
  const confidence = calibratedScore
  const pct = (confidence * 100).toFixed(1)

  const barColor = confidence >= 0.6 ? 'var(--danger)' : confidence >= 0.3 ? 'var(--warning)' : 'var(--success)'
  const badgeBg = confidence >= 0.6 ? 'var(--danger-bg)' : confidence >= 0.3 ? 'var(--warning-bg)' : 'var(--success-bg)'
  const badgeColor = confidence >= 0.6 ? 'var(--danger)' : confidence >= 0.3 ? 'var(--warning)' : 'var(--success)'
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

      <div style={{ background: 'var(--bg-card)', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Analyzed URL
            </p>
            <p style={{ margin: 0, color: 'var(--text-bright)', wordBreak: 'break-all', fontSize: '0.9rem', fontFamily: 'monospace' }}>
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
            borderRadius: '8px', background: 'var(--success-bg)', border: '1px solid var(--success)44',
          }}>
            <p style={{ margin: 0, color: 'var(--success)', fontSize: '0.8rem' }}>
              {'\u2713'} Known reputable domain — full analysis was still performed; reputation only lowers the risk estimate.
            </p>
          </div>
        )}

        <div style={{
          display: 'flex', gap: '0.25rem', background: 'var(--bg-tab)',
          borderRadius: '8px', padding: '2px', marginBottom: '1rem',
        }} role="tablist" aria-label="Analysis tabs">
          <TabButton active={tab === 'overview'} onClick={() => setTab('overview')}>Overview</TabButton>
          <TabButton active={tab === 'details'} onClick={() => setTab('details')}>Details</TabButton>
          <TabButton active={tab === 'behavior'} onClick={() => setTab('behavior')}>Behavior</TabButton>
          {result.explanation && <TabButton active={tab === 'copilot'} onClick={() => setTab('copilot')}>AI Copilot</TabButton>}
        </div>

        {tab === 'overview' && <OverviewTab {...{ result, features, brand, pct, barColor, badgeLabel, badgeIcon, badgeBg, badgeColor, scanTime, importance: result.feature_importance, confidence }} />}
        {tab === 'details' && <DetailsTab dns={dns} ssl={ssl} whitelisted={result.whitelisted} result={result} />}
        {tab === 'behavior' && <BehaviorTab domSignals={domSignals} features={features} htmlProvided={result.html_provided} />}
        {tab === 'copilot' && <CopilotTab result={result} explanation={result.explanation} confidence={confidence} barColor={barColor} />}
        <FeedbackButton result={result} />
      </div>
    </div>
  )
}

function TypewriterText({ text, speed }) {
  const [displayed, setDisplayed] = useState('')
  const [done, setDone] = useState(false)
  useEffect(() => {
    if (!text) { setDisplayed(''); setDone(true); return }
    setDisplayed('')
    setDone(false)
    let i = 0
    const timer = setInterval(() => {
      i++
      setDisplayed(text.slice(0, i))
      if (i >= text.length) { clearInterval(timer); setDone(true) }
    }, speed || 12)
    return () => clearInterval(timer)
  }, [text, speed])
  return <>{displayed}{!done && <span style={{ opacity: 0.6 }}>|</span>}</>
}

function CopilotTab({ result, explanation, confidence, barColor }) {
  const [activeQuestion, setActiveQuestion] = useState(null)
  const [llmAnswers, setLlmAnswers] = useState({})
  const [loading, setLoading] = useState({})
  const [llmStatus, setLlmStatus] = useState(null)
  const exp = explanation || {}
  const verdict = confidence >= 0.6 ? 'phishing' : confidence >= 0.3 ? 'suspicious' : 'safe'

  useEffect(() => {
    const apiUrl = getApiUrl()
    fetch(apiUrl + '/health/llm', { headers: getApiHeaders() })
      .then(r => r.json())
      .then(d => setLlmStatus(d.available ? 'ai' : 'template'))
      .catch(() => setLlmStatus('template'))
  }, [])
  const templateAnswers = [
    exp.verdict_summary || `The URL received a risk score of ${(confidence * 100).toFixed(0)}/100, which places it in the ${verdict} category. ${exp.risk_factors?.length ? 'Key risk factors: ' + exp.risk_factors.join(', ') + '.' : ''}`,
    exp.key_findings?.length ? exp.key_findings.map((f, i) => `${i + 1}. ${f}`).join('. ') : 'No specific findings beyond the aggregate score.',
    exp.recommendations?.length ? exp.recommendations.map((r, i) => `${i + 1}. ${r}`).join('. ') : 'No specific recommendations.',
    (() => {
      const rep = result.reputation || {}
      if (rep.scans > 0) {
        return `This domain has been scanned ${rep.scans} time(s) with an average score of ${rep.avg_score?.toFixed(0) || 'N/A'}/100 and a phishing rate of ${((rep.phishing_rate || 0) * 100).toFixed(0)}%. ${rep.scans > 1 ? 'The historical data provides a baseline for comparison.' : 'More scans will improve confidence in the reputation.'}`
      }
      return 'This is the first scan of this domain. No historical reputation data is available yet — the current score reflects the multi-engine analysis only.'
    })(),
    (() => {
      const parts = []
      const brand = result.brand_analysis || {}
      if (brand.has_brand_impersonation) {
        parts.push('Yes — brand impersonation detected targeting ' + (brand.brands_detected?.join(', ') || 'a known brand'))
      }
      const sub = result.subdomain_info
      if (sub) {
        parts.push(`The URL uses subdomain "${sub.subdomain}" on registered domain "${sub.registered_domain}" — a common technique where attackers host phishing pages on legitimate domain infrastructure`)
      }
      if (result.suspicious_tld) {
        parts.push('The TLD is known to be disproportionately used in phishing campaigns')
      }
      if (result.is_shortener) {
        parts.push('The URL uses a link shortener, which can obscure the final destination')
      }
      return parts.length ? parts.join('. ') + '.' : 'No specific known attack patterns detected beyond the general risk scoring.'
    })(),
  ]

  const faqs = [
    { q: verdict === 'safe' ? 'Why is this URL considered safe?' : 'Why was this URL flagged?' },
    { q: 'What are the key findings?' },
    { q: 'What should I do next?' },
    { q: 'How trustworthy is this domain?' },
    { q: 'Is this a known attack pattern?' },
  ]

  const fetchLlmAnswer = async (i) => {
    if (llmAnswers[i] || loading[i]) return
    setLoading(prev => ({ ...prev, [i]: true }))
    try {
      const apiUrl = getApiUrl()
      const res = await fetch(`${apiUrl}/explain`, {
        method: 'POST',
        headers: getApiHeaders(),
        body: JSON.stringify({ question: faqs[i].q, result }),
      })
      const data = await res.json()
      if (data.source === 'llm') {
        setLlmAnswers(prev => ({ ...prev, [i]: data.answer }))
      }
    } catch (e) { /* fall back to template */ }
    setLoading(prev => ({ ...prev, [i]: false }))
  }

  const handleClick = (i) => {
    if (activeQuestion === i) { setActiveQuestion(null); return }
    setActiveQuestion(i)
    fetchLlmAnswer(i)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
      <style>{`
        @keyframes skeleton-pulse {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 0.8; }
        }
        .skeleton-line {
          animation: skeleton-pulse 1.5s ease-in-out infinite;
        }
      `}</style>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: '0 0 0.5rem' }}>
        <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.75rem', lineHeight: '1.5' }}>
          Ask questions about this analysis. Click a question to expand the answer.
        </p>
        {llmStatus && (
          <span style={{
            fontSize: '0.6rem', fontWeight: 600, padding: '0.15rem 0.45rem', borderRadius: '4px',
            background: llmStatus === 'ai' ? 'var(--success-bg)' : 'var(--bg-tab)',
            color: llmStatus === 'ai' ? 'var(--success)' : 'var(--text-soft)',
            border: llmStatus === 'ai' ? '1px solid var(--success-border)' : 'none',
            whiteSpace: 'nowrap',
          }}>
            {llmStatus === 'ai' ? 'AI Enhanced' : 'Template'}
          </span>
        )}
      </div>
      {faqs.map((faq, i) => {
        const displayText = llmAnswers[i] || templateAnswers[i]
        const isLoading = loading[i]
        return (
          <div key={i} style={{
            borderRadius: '8px', overflow: 'hidden',
            border: `1px solid ${activeQuestion === i ? barColor + '44' : 'var(--border)'}`,
            transition: 'border 0.15s',
          }}>
            <button onClick={() => handleClick(i)} aria-expanded={activeQuestion === i} aria-controls={`faq-answer-${i}`} style={{
              width: '100%', padding: '0.6rem 0.75rem', border: 'none', background: 'var(--bg-page)',
              color: 'var(--text-strong)', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer',
              textAlign: 'left', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <span>{faq.q}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', transform: activeQuestion === i ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>
                {'\u25BC'}
              </span>
            </button>
            {activeQuestion === i && (
              <div id={`faq-answer-${i}`} style={{ padding: '0.6rem 0.75rem', background: 'var(--bg-subtle)', borderTop: '1px solid var(--border)' }}>
                {isLoading ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', padding: '0.1rem 0' }}>
                    <div className="skeleton-line" style={{ width: '85%', height: '0.7rem', borderRadius: '4px', background: 'var(--bg-tab)' }} />
                    <div className="skeleton-line" style={{ width: '60%', height: '0.7rem', borderRadius: '4px', background: 'var(--bg-tab)' }} />
                    <div className="skeleton-line" style={{ width: '45%', height: '0.7rem', borderRadius: '4px', background: 'var(--bg-tab)' }} />
                  </div>
                ) : (
                  <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.8rem', lineHeight: '1.6', whiteSpace: 'pre-wrap' }}>
                    <TypewriterText text={displayText} speed={10} key={llmAnswers[i] ? `llm-${i}` : `tmpl-${i}`} />
                  </p>
                )}
                {llmAnswers[i] && (
                  <p style={{ margin: '0.35rem 0 0', color: 'var(--text-muted)', fontSize: '0.65rem', textAlign: 'right' }}>
                    Llama 3.2
                  </p>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function FeedbackButton({ result }) {
  const [submitted, setSubmitted] = useState(null)
  const [sending, setSending] = useState(false)

  const predicted = result.aggregate_score >= 60 ? 'phishing' : result.aggregate_score >= 30 ? 'suspicious' : 'safe'

  const deriveType = (actual) => {
    if (actual === predicted) return 'correct'
    if (actual === 'safe' && predicted !== 'safe') return 'false_positive'
    if (actual !== 'safe' && predicted === 'safe') return 'false_negative'
    return 'correct'
  }

  const sendFeedback = async (actual) => {
    if (sending || submitted) return
    setSending(true)
    const type = deriveType(actual)
    try {
      const apiUrl = getApiUrl()
      const res = await fetch(`${apiUrl}/feedback`, {
        method: 'POST',
        headers: getApiHeaders(),
        body: JSON.stringify({
          url: result.url,
          feedback_type: type,
          predicted_verdict: predicted,
          actual_verdict: actual,
          score: result.aggregate_score || 0,
        }),
      })
      if (res.ok) setSubmitted(type)
    } catch (e) {
      // silently fail
    }
    setSending(false)
  }

  const options = [
    { actual: 'safe', label: 'Safe', color: 'var(--success)' },
    { actual: 'suspicious', label: 'Suspicious', color: 'var(--warning)' },
    { actual: 'phishing', label: 'Phishing', color: 'var(--danger)' },
  ]

  return (
    <div style={{ marginTop: '1rem', padding: '0.6rem 0.75rem', borderRadius: '8px', background: 'var(--bg-page)', border: '1px solid var(--border)' }}>
      <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        What is the actual verdict of this page?
      </p>
      <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
        Our analysis says: <strong style={{ color: 'var(--text-secondary)' }}>{predicted}</strong>. Tell us what you observed on the page to improve the model.
      </p>
      <div style={{ display: 'flex', gap: '0.4rem' }} role="radiogroup" aria-label="Actual page verdict">
        {options.map((btn) => (
          <button key={btn.actual} onClick={() => sendFeedback(btn.actual)} disabled={!!submitted || sending} aria-pressed={submitted === btn.color} style={{
            padding: '0.3rem 0.6rem', borderRadius: '6px', border: submitted ? `1px solid ${btn.color}` : '1px solid var(--border)',
            background: submitted === btn.color ? btn.color + '22' : 'transparent', color: submitted ? btn.color : 'var(--text-secondary)',
            fontSize: '0.72rem', fontWeight: 500, cursor: submitted ? 'default' : 'pointer',
            opacity: submitted && submitted !== btn.color ? 0.4 : 1, transition: 'all 0.15s',
          }}>
            {submitted === btn.color ? '\u2713 ' : ''}{btn.label}
          </button>
        ))}
      </div>
      {submitted && (
        <p style={{ margin: '0.35rem 0 0', color: 'var(--success)', fontSize: '0.7rem' }}>
          Thanks for the feedback. {submitted === 'correct' ? 'The verdict matched your observation.' : 'This case was recorded for retraining.'}
        </p>
      )}
    </div>
  )
}

export default ResultCard