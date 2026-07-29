import { useState } from 'react'

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

const PLACEHOLDERS = {
  url: 'Enter a URL to scan — paste any suspicious link',
  domain: 'Enter a domain name — e.g. example.com',
  'ip address': 'Enter an IP address — e.g. 8.8.8.8',
}

const BUTTON_LABELS = {
  url: 'SCAN',
  domain: 'LOOKUP',
  'ip address': 'LOOKUP',
}

function UrlInput({ onPredict, loading, activeTab }) {
  const [value, setValue] = useState('')
  const [htmlFile, setHtmlFile] = useState(null)
  const [fileName, setFileName] = useState('')
  const [showHtmlUpload, setShowHtmlUpload] = useState(false)
  const examples = TAB_EXAMPLES[activeTab] || TAB_EXAMPLES.url

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!value.trim()) return
    onPredict(value.trim(), htmlFile)
  }

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (!file) { setHtmlFile(null); setFileName(''); return }
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
          placeholder={PLACEHOLDERS[activeTab] || 'Enter a URL'}
          style={{
            flex: 1, padding: '0.85rem 1rem', border: 'none',
            background: 'transparent', color: '#fff',
            fontSize: '0.95rem', outline: 'none',
          }}
        />
        <button
          type="submit"
          disabled={loading || !value.trim()}
          style={{
            padding: '0.85rem 1.5rem', border: 'none',
            background: loading ? '#1e2a45' : '#3b82f6',
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
                width: '14px', height: '14px', border: '2px solid #64748b',
                borderTop: '2px solid #94a3b8', borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }} />
              {BUTTON_LABELS[activeTab] === 'SCAN' ? 'SCANNING' : 'SEARCHING'}
            </>
          ) : (
            <>
              {BUTTON_LABELS[activeTab] || 'SCAN'}
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
              color: showHtmlUpload ? '#3b82f6' : 'var(--text-muted)',
              fontSize: '0.8rem', cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: '0.3rem',
              padding: '0.3rem 0.5rem',
            }}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M7 1v12M1 7h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            + HTML file
          </button>
        )}
      </div>

      {showHtmlUpload && activeTab === 'url' && (
        <div style={{
          marginTop: '0.75rem', padding: '0.75rem 1rem', borderRadius: '10px',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: '0.75rem',
        }}>
          <input type="file" accept=".html,.htm" onChange={handleFileChange} id="html-upload" style={{ display: 'none' }} />
          <label htmlFor="html-upload" style={{
            padding: '0.4rem 0.85rem', borderRadius: '6px',
            background: 'var(--bg-tab)', color: 'var(--text-primary)', fontSize: '0.8rem',
            cursor: 'pointer', flexShrink: 0, border: '1px solid #2a3a52',
          }}>
            Choose File
          </label>
          <span style={{
            color: fileName ? 'var(--text-primary)' : 'var(--text-muted)', fontSize: '0.85rem',
            flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {fileName || 'No file selected — upload an HTML page for deeper analysis'}
          </span>
          {fileName && (
            <button type="button" onClick={clearFile} style={{
              background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer',
              fontSize: '1rem', padding: '0 0.25rem',
            }}>
              {'\u2717'}
            </button>
          )}
        </div>
      )}
    </form>
  )
}

export default UrlInput