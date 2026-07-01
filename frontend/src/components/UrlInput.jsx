import { useState } from 'react'

function UrlInput({ onPredict, loading }) {
  const [url, setUrl] = useState('')
  const [htmlFile, setHtmlFile] = useState(null)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!url.trim()) return
    onPredict(url.trim(), htmlFile)
  }

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (!file) return setHtmlFile(null)
    const reader = new FileReader()
    reader.onload = () => setHtmlFile(reader.result)
    reader.readAsText(file)
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
        placeholder="https://example.com"
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
      <input
        type="file"
        accept=".html,.htm"
        onChange={handleFileChange}
        style={{
          width: '100%',
          color: '#94a3b8',
          fontSize: '0.9rem',
        }}
      />

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
