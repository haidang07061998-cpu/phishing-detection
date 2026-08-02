import { useState, useEffect } from 'react'
import { getApiHeaders, getApiUrl } from '../api'
import { useLanguage } from '../LanguageContext'

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

const FEATURE_LABEL_KEYS = {
  url_length: 'rc.feature.url_length',
  domain_length: 'rc.feature.domain_length',
  path_length: 'rc.feature.path_length',
  entropy: 'rc.feature.entropy',
  special_char_ratio: 'rc.feature.special_char_ratio',
  digit_ratio: 'rc.feature.digit_ratio',
  subdomain_count: 'rc.feature.subdomain_count',
  has_https: 'rc.feature.has_https',
  has_ip_address: 'rc.feature.has_ip_address',
  suspicious_keywords: 'rc.feature.suspicious_keywords',
  url_depth: 'rc.feature.url_depth',
  tld_in_path: 'rc.feature.tld_in_path',
}

const FEATURE_TOOLTIP_KEYS = {
  url_length: 'rc.tip.url_length',
  domain_length: 'rc.tip.domain_length',
  path_length: 'rc.tip.path_length',
  entropy: 'rc.tip.entropy',
  special_char_ratio: 'rc.tip.special_char_ratio',
  digit_ratio: 'rc.tip.digit_ratio',
  subdomain_count: 'rc.tip.subdomain_count',
  has_https: 'rc.tip.has_https',
  has_ip_address: 'rc.tip.has_ip_address',
  suspicious_keywords: 'rc.tip.suspicious_keywords',
  url_depth: 'rc.tip.url_depth',
  tld_in_path: 'rc.tip.tld_in_path',
}

const FEATURE_IMPORTANCE = [
  'suspicious_keywords', 'has_ip_address', 'has_https', 'tld_in_path',
  'entropy', 'subdomain_count', 'digit_ratio', 'special_char_ratio',
  'domain_length', 'url_length', 'url_depth', 'path_length',
]

const DETAIL_LABEL_KEYS = {
  a_record_count: 'rc.detail.a_record_count',
  mx_record_count: 'rc.detail.mx_record_count',
  ns_record_count: 'rc.detail.ns_record_count',
  ttl: 'rc.detail.ttl',
  domain_age_days: 'rc.detail.domain_age_days',
  registrar: 'rc.detail.registrar',
  is_privacy_protected: 'rc.detail.is_privacy_protected',
  country: 'rc.detail.country',
  ssl_valid: 'rc.detail.ssl_valid',
  ssl_age_days: 'rc.detail.ssl_age_days',
  ssl_issuer_trusted: 'rc.detail.ssl_issuer_trusted',
  redirect_count: 'rc.detail.redirect_count',
  cross_domain_redirect: 'rc.detail.cross_domain_redirect',
  final_url: 'rc.detail.final_url',
  resolved_ips: 'rc.detail.resolved_ips',
  ptr_record: 'rc.detail.ptr_record',
  asn: 'rc.detail.asn',
  asn_description: 'rc.detail.asn_description',
  asn_country: 'rc.detail.asn_country',
}

const SIGNAL_LABEL_KEYS = {
  script_count: 'rc.signal.script_count',
  iframe_count: 'rc.signal.iframe_count',
  form_count: 'rc.signal.form_count',
  input_count: 'rc.signal.input_count',
  password_input: 'rc.signal.password_input',
  button_count: 'rc.signal.button_count',
  total_links: 'rc.signal.total_links',
  external_scripts: 'rc.signal.external_scripts',
  external_link_ratio: 'rc.signal.external_link_ratio',
  hidden_elements: 'rc.signal.hidden_elements',
  meta_refresh: 'rc.signal.meta_refresh',
  eval_count: 'rc.signal.eval_count',
  document_write: 'rc.signal.document_write',
  suspicious_js: 'rc.signal.suspicious_js',
  empty_links: 'rc.signal.empty_links',
}

function formatFeatureValue(name, value, t) {
  const yes = t ? t('common.yes') : 'Yes'
  const no = t ? t('common.no') : 'No'
  if (name === 'has_https' || name === 'has_ip_address' || name === 'tld_in_path') {
    return value === 1 ? yes : no
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

function formatDetailValue(key, value, extra, t) {
  const na = 'N/A'
  const yes = t ? t('common.yes') : 'Yes'
  const no = t ? t('common.no') : 'No'
  if (value === -1 || value === '' || value === undefined || value === null) return na
  if (key === 'domain_age_days') {
    if (value < 30) return t ? t('rc.detail.value.days', { value }) : `${value} days`
    if (value < 365) return t ? t('rc.detail.value.months', { value: Math.round(value / 30) }) : `${Math.round(value / 30)} months`
    return t ? t('rc.detail.value.years', { value: (value / 365).toFixed(1) }) : `${(value / 365).toFixed(1)} years`
  }
  if (key === 'ssl_age_days') return t ? t('rc.detail.value.days', { value }) : `${value} days`
  if (key === 'ssl_valid') return value === 1 ? yes : no
  if (key === 'ssl_issuer_trusted') {
    const trusted = value === 1 || extra?.trustedCAOverride
    return trusted ? yes : no
  }
  if (key === 'is_privacy_protected') return value === 1 ? yes : no
  if (key === 'cross_domain_redirect') {
    if (value === -1) return na
    return value === 1 ? yes : no
  }
  if (key === 'resolved_ips') {
    if (Array.isArray(value)) return value.join(', ') || na
    return String(value)
  }
  if (key === 'ptr_record') return value || na
  if (key === 'asn') return value ? `AS${value}` : na
  if (key === 'asn_description') return value || na
  if (key === 'asn_country') return value || na
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

function getDetailBadge(key, value, extra, t) {
  const no = t ? t('common.no') : 'No'
  if (key === 'domain_age_days' && value >= 0) {
    if (value < 30) return { text: t ? t('rc.badge.newDomain') : 'New Domain \u00B7 High Risk', color: 'var(--danger)', bg: 'var(--danger-bg)' }
    if (value < 365) return { text: t ? t('rc.badge.youngDomain') : 'Young Domain \u00B7 Suspicious', color: 'var(--warning)', bg: 'var(--warning-bg)' }
    return { text: t ? t('rc.badge.established') : 'Established \u00B7 Safe', color: 'var(--success)', bg: 'var(--success-bg)' }
  }
  if (key === 'ttl' && value >= 0) {
    if (value < 300 && extra?.whitelisted) return { text: t ? t('rc.badge.lowTtlCdn') : 'Low TTL (CDN/Load Balancing)', color: 'var(--text-primary)', bg: 'var(--bg-page)' }
    if (value < 300) return { text: t ? t('rc.badge.lowTtl') : 'Low TTL \u00B7 Suspicious', color: 'var(--warning)', bg: 'var(--warning-bg)' }
  }
  if (key === 'cross_domain_redirect') {
    if (value !== 1) {
      return {
        text: no,
        color: 'var(--success)',
        bgColor: 'rgba(16, 185, 129, 0.1)',
        borderColor: 'rgba(16, 185, 129, 0.4)',
      }
    }
    const dest = (extra?.finalUrl || '').toLowerCase()
    const isKnown = WHITELIST_DOMAINS.some(d => dest.includes(d.toLowerCase()))
    if (isKnown) {
      return {
        text: t ? t('rc.badge.reputableDest') : 'Yes (Reputable Destination)',
        color: 'var(--warning)',
        bgColor: 'rgba(234, 179, 8, 0.1)',
        borderColor: 'rgba(234, 179, 8, 0.4)',
      }
    }
    return {
      text: t ? t('rc.badge.unknownDest') : 'Yes (Unknown Destination)',
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
  const { t } = useLanguage()
  const pct = Math.min(Math.max(value * 100, 0), 100)
  const r = 85, cx = 102, cy = 96, stroke = 12
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - pct / 100)
  const color = pct >= 60 ? 'var(--danger)' : pct >= 30 ? 'var(--warning)' : 'var(--success)'
  const label = pct >= 60 ? t('rc.verdict.phishing') : pct >= 30 ? t('rc.verdict.suspicious') : t('rc.verdict.safe')
  return (
    <div style={{ textAlign: 'center' }}>
      <div role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct.toFixed(0)} aria-label={t('rc.gauge.aria', { pct: pct.toFixed(0), label: label.toLowerCase() })}>
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
          {t('rc.gauge.reputable')}
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
  const { t } = useLanguage()
  if (!importance || Object.keys(importance).length === 0) return null
  const entries = Object.entries(importance)
    .map(([name, val]) => ({ name, val, abs: Math.abs(val) }))
    .sort((a, b) => b.abs - a.abs)
    .slice(0, 8)
  const maxAbs = Math.max(...entries.map(e => e.abs), 0.001)
  return (
    <div style={{ marginTop: '1rem' }}>
      <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
        {t('rc.featureImpact')}
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
        {entries.map(({ name, val }) => {
          const label = FEATURE_LABEL_KEYS[name] ? t(FEATURE_LABEL_KEYS[name]) : name
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

function formatFeatureBadge(name, value, whitelisted, brandInfo, t) {
  const formatted = formatFeatureValue(name, value, t)
  if (name === 'entropy') {
    const label = value > 4.5 ? t('rc.entropy.high') : value > 3.5 ? t('rc.entropy.medium') : t('rc.entropy.low')
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

const ENGINE_LABEL_KEYS = {
  ai_model: 'rc.engine.ai_model',
  dns_infrastructure: 'rc.engine.dns_infrastructure',
  url_pattern: 'rc.engine.url_pattern',
  brand: 'rc.engine.brand',
}

function EngineResultRow({ name, result }) {
  const { t } = useLanguage()
  const data = result || {}
  const score = data.score || 0
  const verdict = data.verdict || 'safe'
  const details = data.details || t('rc.engine.noData')
  const color = score >= 60 ? 'var(--danger)' : score >= 30 ? 'var(--warning)' : 'var(--success)'
  const label = ENGINE_LABEL_KEYS[name] ? t(ENGINE_LABEL_KEYS[name]) : name
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
  const { t } = useLanguage()
  if (!reputation || !reputation.scans) return null
  const avgScore = reputation.avg_score || 0
  const scanCount = reputation.scans || 0
  const phishingRate = reputation.phishing_rate || 0
  const lastSeen = reputation.last_seen ? new Date(reputation.last_seen).toLocaleString() : 'N/A'
  return (
    <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'var(--bg-page)', border: '1px solid var(--border)', marginTop: '0.75rem' }}>
      <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
        {t('rc.rep.title')}
      </p>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.78rem' }}>
        <div><span style={{ color: 'var(--text-muted)' }}>{t('rc.rep.scans')}</span><span style={{ color: 'var(--text-bright)', fontWeight: 600 }}>{scanCount}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>{t('rc.rep.avg')}</span><span style={{ color: avgScore >= 60 ? 'var(--danger)' : avgScore >= 30 ? 'var(--warning)' : 'var(--success)', fontWeight: 600 }}>{avgScore.toFixed(1)}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>{t('rc.rep.rate')}</span><span style={{ color: phishingRate > 0.5 ? 'var(--danger)' : 'var(--success)', fontWeight: 600 }}>{(phishingRate * 100).toFixed(1)}%</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>{t('rc.rep.last')}</span><span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{lastSeen}</span></div>
      </div>
    </div>
  )
}

function formatLatency(ms) {
  if (ms == null || Number.isNaN(Number(ms))) return null
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

function getMissingSources(result, t) {
  const missing = []
  const dns = result?.dns_whois || {}
  const ssl = result?.ssl_redirect || {}
  const dnsMissing = Object.keys(dns).length === 0 || dns.a_record_count === -1 || dns.a_record_count === undefined
  const sslMissing = Object.keys(ssl).length === 0 || ssl.ssl_valid === -1 || ssl.ssl_valid === undefined
  if (!result?.html_provided) missing.push('HTML / DOM')
  else if (result.analysis_quality === 'limited') missing.push(t ? t('rc.limited.parseFailed') : 'HTML / DOM (parse failed)')
  if (dnsMissing) missing.push('DNS / WHOIS')
  if (sslMissing) missing.push('SSL / Redirect')
  return missing
}

function LimitedAnalysisBanner({ result }) {
  const { t } = useLanguage()
  const missing = getMissingSources(result, t)
  if (missing.length === 0) return null
  const reason = result.analysis_reason || ''
  return (
    <div style={{
      marginBottom: '1rem', padding: '0.6rem 0.9rem', borderRadius: '8px',
      background: 'var(--warning-bg)', border: '1px solid var(--warning)44',
    }}>
      <p style={{ margin: 0, color: 'var(--warning)', fontSize: '0.8rem', fontWeight: 700 }}>
        {'\u26A0'} {t('rc.limited.title', { list: missing.join(', ') })}
      </p>
      <p style={{ margin: '0.3rem 0 0', color: 'var(--text-muted)', fontSize: '0.78rem', lineHeight: '1.4' }}>
        {reason
          ? t('rc.limited.reason', { reason })
          : t('rc.limited.fallback')
        }
        {t('rc.limited.tail')}
      </p>
    </div>
  )
}
function DataCoverage({ result }) {
  const { t } = useLanguage()
  const dns = result?.dns_whois || {}
  const ssl = result?.ssl_redirect || {}
  const items = [
    { key: 'dns', label: t('rc.coverage.dns'), ok: Object.keys(dns).length > 0 && dns.a_record_count !== -1 && dns.a_record_count !== undefined },
    { key: 'ssl', label: t('rc.coverage.ssl'), ok: Object.keys(ssl).length > 0 && ssl.ssl_valid !== -1 && ssl.ssl_valid !== undefined },
    { key: 'html', label: t('rc.coverage.html'), ok: !!result?.html_provided && result?.analysis_quality !== 'limited' },
    { key: 'brand', label: t('rc.coverage.brand'), ok: !!(result?.brand_analysis && (result.brand_analysis.brands_detected || []).length > 0) },
  ]
  return (
    <div style={{
      display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '1rem',
    }} role="list" aria-label={t('rc.coverage.aria')}>
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
  const { t } = useLanguage()
  const ai = result.phishing_probability
  const agg = result.aggregate_score
  const threat = result.threat_match
  const items = [
    {
      key: 'ai',
      label: t('rc.legend.ai.label'),
      value: ai != null ? `${(ai * 100).toFixed(1)}%` : 'N/A',
      color: ai >= 0.6 ? 'var(--danger)' : ai >= 0.3 ? 'var(--warning)' : 'var(--success)',
      desc: t('rc.legend.ai.desc'),
    },
    {
      key: 'agg',
      label: t('rc.legend.agg.label'),
      value: agg != null ? `${agg}/100` : 'N/A',
      color: agg >= 60 ? 'var(--danger)' : agg >= 30 ? 'var(--warning)' : 'var(--success)',
      desc: t('rc.legend.agg.desc'),
    },
    {
      key: 'threat',
      label: t('rc.legend.threat.label'),
      value: threat ? (threat.layer === 'community_feed' ? t('rc.legend.threat.feedHit') : t('rc.legend.threat.blocklistHit')) : t('rc.legend.threat.noMatch'),
      color: threat ? 'var(--danger)' : 'var(--text-muted)',
      desc: threat
        ? t('rc.legend.threat.descHit', { value: threat.value || '', source: threat.source || threat.layer })
        : t('rc.legend.threat.descNone'),
    },
  ]
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.6rem',
      marginBottom: '1rem', padding: '0.75rem', borderRadius: '8px',
      background: 'var(--bg-page)', border: '1px solid var(--border)',
    }} role="list" aria-label={t('rc.legend.aria')}>
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

function OverviewTab({ result, features, brand, pct, barColor, badgeLabel, badgeIcon, badgeBg, badgeColor, scanTime, importance, confidence }) {
  const { t } = useLanguage()
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
            {t('rc.gauge.caption')}
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
                {'\u2713'} {t('rc.whitelisted')}
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
            {badgeIcon} {t('rc.analysisSummary')}
          </p>
          <p style={{ margin: '0 0 0.75rem', color: 'var(--text-strong)', fontSize: '0.85rem', lineHeight: '1.6' }}>
            {result.explanation.verdict_summary}
          </p>
          {result.explanation.key_findings?.length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{t('rc.keyFindings')}</p>
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
              <p style={{ margin: '0 0 0.25rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{t('rc.recommendations')}</p>
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
            {t('rc.section.morphology')}
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {morphFeatures.map(key => {
              const f = featureMap[key]
              if (!f) return null
              const label = FEATURE_LABEL_KEYS[f.name] ? t(FEATURE_LABEL_KEYS[f.name]) : f.name
              const tooltip = FEATURE_TOOLTIP_KEYS[f.name] ? t(FEATURE_TOOLTIP_KEYS[f.name]) : ''
              const { text, color } = formatFeatureBadge(f.name, f.value, isWhitelisted, brand, t)
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
            {t('rc.section.behavioral')}
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {behavFeatures.map(key => {
              const f = featureMap[key]
              if (!f) return null
              const label = FEATURE_LABEL_KEYS[f.name] ? t(FEATURE_LABEL_KEYS[f.name]) : f.name
              const tooltip = FEATURE_TOOLTIP_KEYS[f.name] ? t(FEATURE_TOOLTIP_KEYS[f.name]) : ''
              const { text, color } = formatFeatureBadge(f.name, f.value, isWhitelisted, brand, t)
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
                {t('rc.suspiciousTld')}
                <TooltipIcon text={t('rc.suspiciousTld.tip')} />
              </span>
              <Badge color={suspTld && !isWhitelisted ? 'var(--danger)' : 'var(--success)'} bg={suspTld && !isWhitelisted ? 'var(--danger-bg)' : 'var(--success-bg)'}>
                {suspTld ? t('common.yes') : t('common.no')}
              </Badge>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
        <div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px', margin: '0 0 0.5rem' }}>
            {t('rc.section.advanced')}
          </p>
          {brand?.has_brand_impersonation ? (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: 'var(--danger-bg)', border: '1px solid var(--danger)44', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: 0, color: 'var(--danger)', fontSize: '0.8rem', fontWeight: 600 }}>
                {'\u26A0'} {t('rc.brandImpersonation')}
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
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{t('rc.risk')}</span>
                <div style={{ flex: 1 }}>
                  <ProgressBar value={brand.risk_score} color={brand.risk_score > 0.7 ? 'var(--danger)' : 'var(--warning)'} height="14px" showLabel={false} />
                </div>
                <span style={{ color: 'var(--danger)', fontSize: '0.8rem', fontWeight: 700, minWidth: '36px', textAlign: 'right' }}>
                  {(brand.risk_score * 100).toFixed(0)}%
                </span>
              </div>
              {brand.techniques?.length > 0 && (
                <p style={{ margin: '0.35rem 0 0', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                  {t('rc.technique', { value: brand.techniques.join(', ') })}
                </p>
              )}
            </div>
          ) : (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: 'var(--bg-page)', border: '1px solid var(--border)', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: 0, color: 'var(--success)', fontSize: '0.8rem' }}>
                {'\u2713'} {t('rc.noBrandImpersonation')}
              </p>
            </div>
          )}
          {result.engine_results?.engines && Object.keys(result.engine_results.engines).length > 0 && (
            <div style={{
              padding: '0.75rem', borderRadius: '8px',
              background: 'var(--bg-page)', border: '1px solid var(--border)', marginBottom: '0.75rem',
            }}>
              <p style={{ margin: '0 0 0.5rem', color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {t('rc.engine.results', { count: result.engine_count || Object.keys(result.engine_results.engines).length })}
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
            {t('rc.section.details')}
          </p>
          <div style={{
            padding: '0.75rem', borderRadius: '8px',
            background: 'var(--bg-page)', border: '1px solid var(--border)',
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
              <tbody>
                {(() => {
                  const rows = [
                  { label: t('rc.row.aggregateScore'), value: `${pct}%`, color: barColor, tooltip: t('rc.row.tip.aggregateScore') },
                  { label: t('rc.row.aiProbability'), value: `${((result.phishing_probability ?? 0) * 100).toFixed(1)}%`, color: result.phishing_probability >= 0.6 ? 'var(--danger)' : result.phishing_probability >= 0.3 ? 'var(--warning)' : 'var(--success)', tooltip: t('rc.row.tip.aiProbability') },
                  { label: t('rc.row.threatIntel'), value: (() => {
                    const threat = result.threat_match
                    if (!threat) return t('rc.row.value.noMatch')
                    return `${threat.value} (${threat.source || threat.layer || 'feed'})`
                  })(), color: result.threat_match ? 'var(--danger)' : 'var(--text-muted)', tooltip: t('rc.row.tip.threatIntel') },
                  { label: t('rc.row.scanDuration'), value: formatLatency(result.latency_ms) || 'N/A', color: 'var(--text-primary)', tooltip: t('rc.row.tip.scanDuration') },
                  { label: t('rc.row.confidenceRange'), value: (() => {
                    const b = result.probability_band
                    if (!b || b.low == null) return 'N/A'
                    return `${(b.low * 100).toFixed(1)}% \u2013 ${(b.high * 100).toFixed(1)}%`
                  })(), color: 'var(--text-primary)', tooltip: t('rc.row.tip.confidenceRange') },
                  { label: t('rc.row.reputable'), value: isWhitelisted ? t('common.yes') : t('common.no'), color: isWhitelisted ? 'var(--success)' : 'var(--text-muted)', tooltip: t('rc.row.tip.reputable') },
                  { label: t('rc.row.shortener'), value: isShort ? t('common.yes') : t('common.no'), color: isShort ? 'var(--warning)' : 'var(--success)' },
                  { label: t('rc.row.redirect'), value: (() => {
                    const cr = result.ssl_redirect?.cross_domain_redirect
                    if (cr !== 1) return t('common.no')
                    const fu = (result.ssl_redirect?.final_url || '').toLowerCase()
                    const known = WHITELIST_DOMAINS.some(d => fu.includes(d.toLowerCase()))
                    return known ? t('rc.row.value.toReputable') : t('rc.row.value.unknownDest')
                  })(), color: (() => {
                    const cr = result.ssl_redirect?.cross_domain_redirect
                    if (cr !== 1) return 'var(--success)'
                    const fu = (result.ssl_redirect?.final_url || '').toLowerCase()
                    const known = WHITELIST_DOMAINS.some(d => fu.includes(d.toLowerCase()))
                    return known ? 'var(--warning)' : 'var(--danger)'
                  })() },
                  { label: t('rc.row.finalDestination'), value: expandedUrl || t('rc.row.value.sameAsInput'), color: 'var(--success)' },
                  { label: t('rc.row.analysisQuality'), value: result.analysis_quality === 'full' ? t('rc.row.value.full') : t('rc.row.value.limited'), color: result.analysis_quality === 'full' ? 'var(--success)' : 'var(--warning)' },
                  { label: t('rc.row.htmlContent'), value: result.html_provided ? t('rc.row.value.provided') : t('rc.row.value.notProvided'), color: result.html_provided ? 'var(--success)' : 'var(--text-muted)' },
                  { label: t('rc.row.featuresExtracted'), value: t('rc.row.value.signals', { count: features.length }), color: 'var(--text-primary)' },
                  { label: t('rc.row.model'), value: t('rc.row.value.multiEngine', { count: result.engine_count || 5 }), color: 'var(--text-primary)' },
                  { label: t('rc.row.analyzedAt'), value: result.timestamp ? new Date(result.timestamp).toLocaleString() : scanTime, color: 'var(--text-muted)' },
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
  const { t } = useLanguage()
  const trustedCAOverride = result?.url ? /google\.com|youtube\.com|gmail\.com|github\.com|facebook\.com|microsoft\.com|apple\.com|amazon\.com/i.test(result.url) : false
  const finalUrl = ssl?.final_url || ''
  const extra = { whitelisted, trustedCAOverride, finalUrl }
  const subInfo = result?.subdomain_info

  if (!dns && !ssl) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
        {t('rc.noNetwork')}
      </div>
    )
  }

  const renderRow = (key, value) => {
    const label = DETAIL_LABEL_KEYS[key] ? t(DETAIL_LABEL_KEYS[key]) : key
    const formatted = formatDetailValue(key, value, extra, t)
    const color = getDetailColor(key, value, extra)
    const badge = getDetailBadge(key, value, extra, t)
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
          {t('rc.section.dns')}
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {subInfo && (
            <div style={{
              padding: '0.5rem 0.6rem', borderRadius: '6px', marginBottom: '0.25rem',
              background: 'var(--warning-bg)', border: '1px solid var(--warning)44',
            }}>
              <p style={{ margin: '0 0 0.25rem', color: 'var(--warning)', fontSize: '0.7rem', fontWeight: 700 }}>
                {'\u26A0'} {t('rc.subdomain.title')}
              </p>
              <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.72rem', lineHeight: '1.5' }}>
                {t('rc.subdomain.body', { reg: subInfo.registered_domain, sub: subInfo.subdomain })}
              </p>
            </div>
          )}
          {dns && Object.entries(dns).map(([key, value]) => renderRow(key, value))}
        </div>
      </div>
      <div>
        <p style={{ color: 'var(--text-bright)', fontSize: '0.85rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
          {t('rc.section.ssl')}
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {ssl && Object.entries(ssl).map(([key, value]) => renderRow(key, value))}
        </div>
      </div>
    </div>
  )
}

function BehaviorTab({ domSignals, features, htmlProvided }) {
  const { t } = useLanguage()
  if (!htmlProvided) {
    return (
      <div style={{ textAlign: 'center', padding: '2.5rem 1.5rem', borderRadius: '8px', background: 'var(--bg-page)', border: '1px solid var(--border)' }}>
        <p style={{ margin: '0 0 0.5rem', color: 'var(--warning)', fontSize: '1rem', fontWeight: 700 }}>
          {'\u26A0'} {t('rc.noHtml.title')}
        </p>
        <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.85rem', lineHeight: '1.5' }}>
          {t('rc.noHtml.body')}
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
          {t('rc.section.dom')}
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {['script_count', 'iframe_count', 'form_count', 'input_count', 'password_input', 'button_count', 'total_links', 'hidden_elements', 'meta_refresh'].map(key => {
            if (!(key in domSignals)) return null
            const value = domSignals[key]
            const label = SIGNAL_LABEL_KEYS[key] ? t(SIGNAL_LABEL_KEYS[key]) : key
            const isRisk = formatSignalRisk(key, value)
            const formatted = formatFeatureValue(key, value, t)
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
          {t('rc.section.js')}
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {['external_scripts', 'eval_count', 'document_write', 'suspicious_js', 'empty_links', 'external_link_ratio'].map(key => {
            if (!(key in domSignals)) return null
            const value = domSignals[key]
            const label = SIGNAL_LABEL_KEYS[key] ? t(SIGNAL_LABEL_KEYS[key]) : key
            const isRisk = formatSignalRisk(key, value)
            const formatted = formatFeatureValue(key, value, t)
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
  const { t } = useLanguage()
  const dns = result.dns_whois
  return (
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 0 0 1px var(--accent)44' }}>
      <div style={{ height: '5px', background: 'linear-gradient(90deg, var(--accent), var(--accent)88)' }} />
      <div style={{ background: 'var(--bg-card)', padding: '1.5rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            {t('rc.domain.title')}
          </p>
          <p style={{ margin: 0, color: 'var(--text-bright)', fontSize: '0.9rem', fontFamily: 'monospace' }}>
            {result.domain}
          </p>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 1rem' }}>
          {t('rc.domain.body')}
        </p>
        <DetailsTab dns={dns} ssl={result.ssl_redirect} />
      </div>
    </div>
  )
}

function IpResult({ result }) {
  const { t } = useLanguage()
  const dns = result.dns_whois
  const ssl = result.ssl_redirect
  return (
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 0 0 1px var(--accent)44' }}>
      <div style={{ height: '5px', background: 'linear-gradient(90deg, var(--accent), var(--accent)88)' }} />
      <div style={{ background: 'var(--bg-card)', padding: '1.5rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', margin: '0 0 0.25rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            {t('rc.ip.title')}
          </p>
          <p style={{ margin: 0, color: 'var(--text-bright)', fontSize: '0.9rem', fontFamily: 'monospace' }}>
            {result.ip}
          </p>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0 0 1rem' }}>
          {t('rc.ip.body')}
        </p>
        <DetailsTab dns={dns} ssl={ssl} />
      </div>
    </div>
  )
}

function ResultCard({ result }) {
  const { t } = useLanguage()
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
  const badgeLabel = confidence >= 0.6 ? t('rc.verdict.phishing') : confidence >= 0.3 ? t('rc.verdict.suspicious') : t('rc.verdict.safe')
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
              {t('rc.analyzedUrl')}
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
              {'\u2713'} {t('rc.whitelisted')}
            </p>
          </div>
        )}

        <div style={{
          display: 'flex', gap: '0.25rem', background: 'var(--bg-tab)',
          borderRadius: '8px', padding: '2px', marginBottom: '1rem',
        }} role="tablist" aria-label={t('rc.tabs.aria')}>
          <TabButton active={tab === 'overview'} onClick={() => setTab('overview')}>{t('rc.tab.overview')}</TabButton>
          <TabButton active={tab === 'details'} onClick={() => setTab('details')}>{t('rc.tab.details')}</TabButton>
          <TabButton active={tab === 'behavior'} onClick={() => setTab('behavior')}>{t('rc.tab.behavior')}</TabButton>
          {result.explanation && <TabButton active={tab === 'copilot'} onClick={() => setTab('copilot')}>{t('rc.tab.copilot')}</TabButton>}
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
  const { t, lang } = useLanguage()
  const [activeQuestion, setActiveQuestion] = useState(null)
  const [llmAnswers, setLlmAnswers] = useState({})
  const [loading, setLoading] = useState({})
  const [llmStatus, setLlmStatus] = useState(null)
  const exp = explanation || {}
  const verdict = confidence >= 0.6 ? 'phishing' : confidence >= 0.3 ? 'suspicious' : 'safe'
  const verdictLabel = t('rc.verdict.' + verdict)

  useEffect(() => {
    const apiUrl = getApiUrl()
    fetch(apiUrl + '/health/llm', { headers: getApiHeaders() })
      .then(r => r.json())
      .then(d => setLlmStatus(d.available ? 'ai' : 'template'))
      .catch(() => setLlmStatus('template'))
  }, [])

  // Template answers are rebuilt per render so they always follow the
  // currently selected language. Explanation fields from the API are already
  // localized by the backend (lang param on /predict).
  const templateAnswers = [
    (() => {
      const base = exp.verdict_summary || t('copilot.ans.summary', { score: (confidence * 100).toFixed(0), verdict: verdictLabel })
      const risk = exp.risk_factors?.length ? t('copilot.ans.summaryRisk', { risk: exp.risk_factors.join(', ') }) : ''
      return base + risk
    })(),
    exp.key_findings?.length ? exp.key_findings.map((f, i) => `${i + 1}. ${f}`).join('. ') : t('copilot.ans.noFindings'),
    exp.recommendations?.length ? exp.recommendations.map((r, i) => `${i + 1}. ${r}`).join('. ') : t('copilot.ans.noRecs'),
    (() => {
      const rep = result.reputation || {}
      if (rep.scans > 0) {
        const more = rep.scans > 1 ? t('copilot.ans.repBaseline') : t('copilot.ans.repMore')
        return t('copilot.ans.reputation', { scans: rep.scans, avg: rep.avg_score?.toFixed(0) || 'N/A', rate: ((rep.phishing_rate || 0) * 100).toFixed(0), more })
      }
      return t('copilot.ans.noReputation')
    })(),
    (() => {
      const parts = []
      const brand = result.brand_analysis || {}
      if (brand.has_brand_impersonation) {
        parts.push(t('copilot.ans.brand', { brands: brand.brands_detected?.join(', ') || t('copilot.ans.knownBrand') }))
      }
      const sub = result.subdomain_info
      if (sub) {
        parts.push(t('copilot.ans.subdomain', { sub: sub.subdomain, reg: sub.registered_domain }))
      }
      if (result.suspicious_tld) {
        parts.push(t('copilot.ans.tld'))
      }
      if (result.is_shortener) {
        parts.push(t('copilot.ans.shortener'))
      }
      return parts.length ? parts.join('. ') + '.' : t('copilot.ans.noAttack')
    })(),
  ]

  const faqs = [
    { q: verdict === 'safe' ? t('copilot.q.whySafe') : t('copilot.q.whyFlagged') },
    { q: t('copilot.q.keyFindings') },
    { q: t('copilot.q.nextSteps') },
    { q: t('copilot.q.trust') },
    { q: t('copilot.q.attack') },
  ]

  const fetchLlmAnswer = async (i) => {
    if (llmAnswers[i] || loading[i]) return
    setLoading(prev => ({ ...prev, [i]: true }))
    try {
      const apiUrl = getApiUrl()
      const res = await fetch(`${apiUrl}/explain`, {
        method: 'POST',
        headers: getApiHeaders(),
        body: JSON.stringify({ question: faqs[i].q, result, lang }),
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
          {t('copilot.intro')}
        </p>
        {llmStatus && (
          <span style={{
            fontSize: '0.6rem', fontWeight: 600, padding: '0.15rem 0.45rem', borderRadius: '4px',
            background: llmStatus === 'ai' ? 'var(--success-bg)' : 'var(--bg-tab)',
            color: llmStatus === 'ai' ? 'var(--success)' : 'var(--text-soft)',
            border: llmStatus === 'ai' ? '1px solid var(--success-border)' : 'none',
            whiteSpace: 'nowrap',
          }}>
            {llmStatus === 'ai' ? t('copilot.badge.ai') : t('copilot.badge.template')}
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
  const { t } = useLanguage()
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
    { actual: 'safe', label: t('feedback.option.safe'), color: 'var(--success)' },
    { actual: 'suspicious', label: t('feedback.option.suspicious'), color: 'var(--warning)' },
    { actual: 'phishing', label: t('feedback.option.phishing'), color: 'var(--danger)' },
  ]

  return (
    <div style={{ marginTop: '1rem', padding: '0.6rem 0.75rem', borderRadius: '8px', background: 'var(--bg-page)', border: '1px solid var(--border)' }}>
      <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {t('feedback.question')}
      </p>
      <p style={{ margin: '0 0 0.35rem', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
        {t('feedback.hint', { predicted })}
      </p>
      <div style={{ display: 'flex', gap: '0.4rem' }} role="radiogroup" aria-label={t('feedback.aria')}>
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
          {submitted === 'correct' ? t('feedback.thanks.correct') : t('feedback.thanks.misclassified')}
        </p>
      )}
    </div>
  )
}

export default ResultCard