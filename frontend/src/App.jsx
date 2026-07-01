import { useState } from 'react'
import UrlInput from './components/UrlInput'
import ResultCard from './components/ResultCard'

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

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
      if (!res.ok) throw new Error(data.error || 'Prediction failed')
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

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
          {error}
        </div>
      )}

      {result && <ResultCard result={result} />}
    </div>
  )
}

export default App
