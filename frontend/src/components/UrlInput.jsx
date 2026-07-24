import { useState } from 'react'

const EXAMPLE_URLS = [
  'https://google.com',
  'https://paypa1.secure-login.com/verify',
  'https://facebook.com/login',
  'http://free-prize-winner.xyz/claim',
]

function UrlInput({ onPredict, loading }) {
  const [url, setUrl] = useState('')
  const [htmlFile, setHtmlFile] = useState(null)
  const [fileName, setFileName] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!url.trim()) return
    onPredict(url.trim(), htmlFile)
  }

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (!file) { setHtmlFile(null); setFileName(''); return }
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = () => setHtmlFile(reader.result)
    reader.readAsText(file)
  }

  const pickExample = (exampleUrl) => {
    setUrl(exampleUrl)
  }

  const clearFile = () => {
    setHtmlFile(null)
    setFileName('')
  }

  return (
    <form onSubmit={handleSubmit} style={{
      background: '#1e293b',
      borderRadius: '12px',
      padding: '1.5rem',
      maxWidth: '600px',
      width: '100%',
      border: '1px solid #334155',
    }}>
      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 600, color: '#94a3b8', fontSize: '0.9rem' }}>
        URL TO ANALYZE
      </label>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://example.com — paste any URL to scan"
        style={{
          width: '100%',
          padding: '0.75rem',
          borderRadius: '8px',
          border: '1px solid #475569',
          background: '#0f172a',
          color: '#e2e8f0',
          fontSize: '1rem',
          outline: 'none',
          boxSizing: 'border-box',
        }}
      />

      <div style={{ marginTop: '0.75rem' }}>
        <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0 0 0.35rem' }}>Quick examples</p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
          {EXAMPLE_URLS.map((ex, i) => (
            <button key={i} type="button" onClick={() => pickExample(ex)} style={{
              background: '#0f172a', border: '1px solid #334155', color: '#94a3b8',
              borderRadius: '6px', padding: '0.3rem 0.6rem', fontSize: '0.75rem',
              cursor: 'pointer', whiteSpace: 'nowrap', fontFamily: 'monospace',
            }}>
              {ex}
            </button>
          ))}
        </div>
      </div>

      <label style={{
        display: 'block',
        marginTop: '1rem',
        marginBottom: '0.5rem',
        fontWeight: 600,
        color: '#94a3b8',
        fontSize: '0.9rem',
      }}>
        HTML CONTENT (optional)
      </label>
      <div style={{
        display: 'flex', alignItems: 'center', gap: '0.5rem',
        padding: '0.5rem 0.75rem', borderRadius: '8px',
        border: '1px solid #475569', background: '#0f172a',
      }}>
        <input
          type="file"
          accept=".html,.htm"
          onChange={handleFileChange}
          id="html-upload"
          style={{ display: 'none' }}
        />
        <label htmlFor="html-upload" style={{
          padding: '0.4rem 0.75rem', borderRadius: '6px',
          background: '#334155', color: '#e2e8f0', fontSize: '0.8rem',
          cursor: 'pointer', flexShrink: 0,
        }}>
          Choose File
        </label>
        <span style={{ color: fileName ? '#e2e8f0' : '#64748b', fontSize: '0.85rem', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {fileName || 'No file selected'}
        </span>
        {fileName && (
          <button type="button" onClick={clearFile} style={{
            background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer',
            fontSize: '1rem', padding: '0 0.25rem',
          }}>
            ✕
          </button>
        )}
      </div>

      <button
        type="submit"
        disabled={loading || !url.trim()}
        style={{
          width: '100%',
          marginTop: '1rem',
          padding: '0.75rem',
          borderRadius: '8px',
          border: 'none',
          background: loading ? '#475569' : 'linear-gradient(90deg, #38bdf8, #818cf8)',
          color: loading ? '#94a3b8' : '#0f172a',
          fontSize: '1rem',
          fontWeight: 600,
          cursor: loading || !url.trim() ? 'not-allowed' : 'pointer',
          transition: 'opacity 0.2s',
        }}
      >
        {loading ? 'ANALYZING...' : 'ANALYZE URL'}
      </button>
    </form>
  )
}

export default UrlInput
