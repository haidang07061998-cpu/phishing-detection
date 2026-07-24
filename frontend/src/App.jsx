import { useState } from 'react'
import UrlInput from './components/UrlInput'
import ResultCard from './components/ResultCard'

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])

  const handlePredict = async (url, htmlContent) => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch('http://localhost:5000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, html: htmlContent || undefined }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `Server error (${res.status})`)
      setResult(data)
      setHistory(prev => [{ url, time: new Date().toLocaleTimeString(), phishing: data.phishing_probability >= 0.5 }, ...prev].slice(0, 10))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const clearHistory = () => setHistory([])

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      color: '#e2e8f0',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      padding: '2rem 1rem',
    }}>
      <header style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 700, margin: 0, background: 'linear-gradient(90deg, #38bdf8, #818cf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          Phishing Detection
        </h1>
        <p style={{ color: '#94a3b8', marginTop: '0.5rem', fontSize: '1.1rem' }}>
          AI-powered URL & HTML content analysis
        </p>
      </header>

      <UrlInput onPredict={handlePredict} loading={loading} />

      {loading && (
        <div style={{
          marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem',
          background: '#1e293b', borderRadius: '12px', padding: '1.5rem',
          maxWidth: '600px', width: '100%', border: '1px solid #334155',
        }}>
          <div style={{
            width: '24px', height: '24px', border: '3px solid #334155',
            borderTop: '3px solid #38bdf8', borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
          }} />
          <span style={{ color: '#94a3b8' }}>Analyzing URL...</span>
        </div>
      )}

      {error && (
        <div style={{
          background: '#7f1d1d',
          border: '1px solid #dc2626',
          borderRadius: '8px',
          padding: '1rem',
          maxWidth: '600px',
          width: '100%',
          marginTop: '1rem',
        }}>
          <p style={{ margin: 0, fontWeight: 600, color: '#fca5a5' }}>Error</p>
          <p style={{ margin: '0.25rem 0 0', color: '#fca5a5', fontSize: '0.9rem' }}>{error}</p>
        </div>
      )}

      {result && <ResultCard result={result} />}

      {history.length > 0 && (
        <div style={{
          marginTop: '1.5rem', maxWidth: '600px', width: '100%',
          background: '#1e293b', borderRadius: '12px', padding: '1.5rem',
          border: '1px solid #334155',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', color: '#f1f5f9' }}>Previous Checks</h3>
            <button onClick={clearHistory} style={{
              background: 'none', border: '1px solid #475569', color: '#94a3b8',
              borderRadius: '6px', padding: '0.25rem 0.5rem', fontSize: '0.75rem',
              cursor: 'pointer',
            }}>Clear</button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            {history.map((h, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '0.4rem 0.6rem', borderRadius: '6px', background: '#0f172a',
                fontSize: '0.8rem',
              }}>
                <span style={{
                  color: h.phishing ? '#fca5a5' : '#86efac', fontWeight: 600, marginRight: '0.5rem',
                  flexShrink: 0,
                }}>
                  {h.phishing ? '⚠' : '✓'}
                </span>
                <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {h.url}
                </span>
                <span style={{ color: '#64748b', flexShrink: 0, marginLeft: '0.5rem' }}>{h.time}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}

export default App
