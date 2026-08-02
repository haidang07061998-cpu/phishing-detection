import { useState } from 'react'
import { useLanguage } from '../LanguageContext'

const TAB_EXAMPLES = {
  url: [
    { value: 'https://google.com', label: 'google.com' },
    { value: 'https://paypa1.secure-login.com/verify', label: 'paypa1.secure-login.com/verify' },
    { value: 'https://facebook.com/login', label: 'facebook.com/login' },
    { value: 'http://free-prize-winner.xyz/claim', label: 'free-prize-winner.xyz/claim' },
  ],
  domain: [
    { value: 'google.com', label: 'google.com' },
    { value: 'github.com', label: 'github.com' },
    { value: 'paypa1-secure.com', label: 'paypa1-secure.com' },
  ],
  'ip address': [
    { value: '8.8.8.8', label: '8.8.8.8 (Google DNS)' },
    { value: '1.1.1.1', label: '1.1.1.1 (Cloudflare)' },
    { value: '185.220.101.42', label: '185.220.101.42 (Tor exit)' },
  ],
}

const PLACEHOLDER_KEYS = {
  url: 'input.placeholder.url',
  domain: 'input.placeholder.domain',
  'ip address': 'input.placeholder.ip',
}

const BUTTON_KEYS = {
  url: 'input.button.scan',
  domain: 'input.button.lookup',
  'ip address': 'input.button.lookup',
}

// Must stay in sync with api/config.py MAX_HTML_BYTES (2 MiB).
const MAX_HTML_BYTES = 2 * 1024 * 1024

function formatBytes(n) {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB'
  if (n >= 1024) return (n / 1024).toFixed(0) + ' KB'
  return n + ' B'
}

function UrlInput({ onPredict, loading, activeTab }) {
  const { t } = useLanguage()
  const [value, setValue] = useState('')
  const [htmlFile, setHtmlFile] = useState(null)
  const [fileName, setFileName] = useState('')
  const [showHtmlUpload, setShowHtmlUpload] = useState(false)
  const [fileError, setFileError] = useState('')
  const examples = TAB_EXAMPLES[activeTab] || TAB_EXAMPLES.url
  const placeholder = t(PLACEHOLDER_KEYS[activeTab] || 'input.placeholder.fallback')
  const buttonLabel = t(BUTTON_KEYS[activeTab] || 'input.button.scan')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!value.trim()) return
    onPredict(value.trim(), htmlFile)
  }

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (!file) { setHtmlFile(null); setFileName(''); setFileError(''); return }
    if (file.size > MAX_HTML_BYTES) {
      setFileError(t('input.fileError', { size: formatBytes(file.size), max: formatBytes(MAX_HTML_BYTES) }))
      setHtmlFile(null)
      setFileName('')
      e.target.value = ''
      return
    }
    setFileError('')
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = () => setHtmlFile(reader.result)
    reader.readAsText(file)
  }

  const pickExample = (ex) => {
    setValue(ex.value)
  }

  const clearFile = () => {
    setHtmlFile(null)
    setFileName('')
    setFileError('')
  }

  return (
    <form onSubmit={handleSubmit} style={{ width: '100%' }}>
      <div style={{
        display: 'flex', gap: '0', background: 'var(--bg-card)',
        borderRadius: '12px', border: '1px solid var(--border)',
        overflow: 'hidden', transition: 'border-color 0.15s',
      }}>
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={placeholder}
          aria-label={placeholder}
          style={{
            flex: 1, padding: '0.85rem 1rem', border: 'none',
            background: 'transparent', color: 'var(--text-bright)',
            fontSize: '0.95rem', outline: 'none',
          }}
        />
        <button
          type="submit"
          disabled={loading || !value.trim()}
          style={{
            padding: '0.85rem 1.5rem', border: 'none',
            background: loading ? 'var(--border)' : 'var(--accent)',
            color: loading ? 'var(--text-muted)' : '#fff',
            fontSize: '0.9rem', fontWeight: 700,
            cursor: loading || !value.trim() ? 'not-allowed' : 'pointer',
            transition: 'background 0.15s',
            display: 'flex', alignItems: 'center', gap: '0.4rem',
          }}
        >
          {loading ? (
            <>
              <div style={{
                width: '14px', height: '14px', border: '2px solid var(--text-muted)',
                borderTop: '2px solid var(--text-secondary)', borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }} />
              {activeTab === 'url' ? t('input.button.scanning') : t('input.button.searching')}
            </>
          ) : (
            <>
              {buttonLabel}
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M4 8h8M8 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </>
          )}
        </button>
      </div>

      <div style={{
        display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginTop: '1rem',
      }}>
        {examples.map((ex, i) => (
          <button key={i} type="button" onClick={() => pickExample(ex)} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            color: 'var(--text-secondary)', borderRadius: '999px',
            padding: '0.3rem 0.75rem', fontSize: '0.8rem',
            cursor: 'pointer', fontFamily: 'monospace',
            transition: 'all 0.15s',
          }}>
            {ex.label}
          </button>
        ))}
        {activeTab === 'url' && (
          <button
            type="button"
            onClick={() => setShowHtmlUpload(!showHtmlUpload)}
            style={{
              background: 'none', border: 'none',
              color: showHtmlUpload ? 'var(--accent)' : 'var(--text-muted)',
              fontSize: '0.8rem', cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: '0.3rem',
              padding: '0.3rem 0.5rem',
            }}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M7 1v12M1 7h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            {t('input.htmlUpload')}
          </button>
        )}
      </div>

      {showHtmlUpload && activeTab === 'url' && (
        <>
        <div style={{
          marginTop: '0.75rem', padding: '0.75rem 1rem', borderRadius: '10px',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: '0.75rem',
        }}>
          <input type="file" accept=".html,.htm" onChange={handleFileChange} id="html-upload" style={{ display: 'none' }} aria-label={t('input.uploadAria')} />
          <label htmlFor="html-upload" style={{
            padding: '0.4rem 0.85rem', borderRadius: '6px',
            background: 'var(--bg-tab)', color: 'var(--text-primary)', fontSize: '0.8rem',
            cursor: 'pointer', flexShrink: 0, border: '1px solid var(--border)',
          }}>
            {t('input.chooseFile')}
          </label>
          <span style={{
            color: fileError ? 'var(--danger)' : fileName ? 'var(--text-primary)' : 'var(--text-muted)', fontSize: '0.85rem',
            flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {fileError || fileName || t('input.noFile')}
          </span>
          {fileName && (
            <button type="button" onClick={clearFile} aria-label={t('input.removeFile')} style={{
              background: 'none', border: 'none', color: 'var(--danger)', cursor: 'pointer',
              fontSize: '1rem', padding: '0 0.25rem',
            }}>
              {'\u2717'}
            </button>
          )}
        </div>
        {fileError && (
          <p role="alert" style={{ margin: '0.35rem 0 0', color: 'var(--danger)', fontSize: '0.75rem' }}>
            {'\u26A0'} {fileError}
          </p>
        )}
        </>
      )}
    </form>
  )
}

export default UrlInput