import { useState } from 'react'
import UrlInput from './components/UrlInput'
import ResultCard from './components/ResultCard'

const API_URL = import.meta.env.VITE_API_URL || '/api'

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])
  const [activeTab, setActiveTab] = useState('url')

  const TAB_CONFIG = {
    url: {
      endpoint: '/predict',
      bodyKey: 'url',
      bodyFn: (input, html) => ({ url: input, html: html || undefined }),
      label: 'URL',
    },
    domain: {
      endpoint: '/domain',
      bodyKey: 'domain',
      bodyFn: (input) => ({ domain: input }),
      label: 'Domain',
    },
    'ip address': {
      endpoint: '/ip',
      bodyKey: 'ip',
      bodyFn: (input) => ({ ip: input }),
      label: 'IP',
    },
  }

  const handlePredict = async (inputValue, htmlContent) => {
    setLoading(true)
    setError(null)
    setResult(null)
    const cfg = TAB_CONFIG[activeTab]
    try {
      const res = await fetch(`${API_URL}${cfg.endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg.bodyFn(inputValue, htmlContent)),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `Server error (${res.status})`)
      setResult(data)
      setHistory(prev => [
        { url: inputValue, time: new Date().toLocaleTimeString(), phishing: data.phishing_probability >= 0.5, prob: data.phishing_probability ? data.phishing_probability * 100 : null },
        ...prev,
      ].slice(0, 10))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0b0f19',
      color: '#c4d1ec',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'stretch',
    }}>
      {/* Header */}
      <header style={{
        width: '100%',
        borderBottom: '1px solid #1e2a45',
        background: '#0d1117',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}>
        <div style={{
          maxWidth: '1200px',
          margin: '0 auto',
          padding: '0 1.5rem',
          height: '56px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
                <rect width="28" height="28" rx="6" fill="#3b82f6" />
                <path d="M14 6v16M6 14h16" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" />
              </svg>
              <span style={{ color: '#fff', fontSize: '1.1rem', fontWeight: 700, letterSpacing: '-0.3px' }}>
                PhishDetect
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.25rem', background: '#1a2332', borderRadius: '8px', padding: '2px' }}>
              {['url', 'domain', 'ip address'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  style={{
                    padding: '0.35rem 0.85rem',
                    borderRadius: '6px',
                    border: 'none',
                    background: activeTab === tab ? '#3b82f6' : 'transparent',
                    color: activeTab === tab ? '#fff' : '#8892b0',
                    fontSize: '0.8rem',
                    fontWeight: activeTab === tab ? 600 : 400,
                    cursor: 'pointer',
                    textTransform: 'capitalize',
                    transition: 'all 0.15s',
                  }}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          <span style={{
            padding: '0.25rem 0.65rem',
            borderRadius: '6px',
            background: '#1a2332',
            color: '#8892b0',
            fontSize: '0.75rem',
            border: '1px solid #2a3a52',
          }}>
            AI Model v2.0
          </span>
        </div>
      </header>

      {/* Hero */}
      <main style={{
        width: '100%',
          maxWidth: '1200px',
          margin: '0 auto',
        padding: '3rem 1.5rem 2rem',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
      }}>
        <h1 style={{
          fontSize: '2rem',
          fontWeight: 600,
          color: '#fff',
          margin: '0 0 0.35rem',
          textAlign: 'center',
        }}>
          {activeTab === 'url' ? 'Analyze suspicious URLs' :
           activeTab === 'domain' ? 'Domain Intelligence Lookup' :
           'IP Address Reputation'}
        </h1>
        <p style={{
          color: '#8892b0',
          fontSize: '0.95rem',
          margin: '0 0 2rem',
          textAlign: 'center',
        }}>
          {activeTab === 'url' ? 'Powered by Gated Fusion AI &middot; TabTransformer + ModernBERT + DOM Analysis' :
           activeTab === 'domain' ? 'DNS records &middot; WHOIS data &middot; SSL certificate info' :
           'Reverse DNS &middot; WHOIS lookup &middot; Network intelligence'}
        </p>

        <UrlInput onPredict={handlePredict} loading={loading} activeTab={activeTab} />

        {loading && (
          <div style={{
            marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem',
            background: '#131b2a', borderRadius: '12px', padding: '1.25rem 1.5rem',
            width: '100%', border: '1px solid #1e2a45',
          }}>
            <div style={{
              width: '20px', height: '20px', border: '2px solid #2a3a52',
              borderTop: '2px solid #3b82f6', borderRadius: '50%',
              animation: 'spin 0.8s linear infinite',
            }} />
            <span style={{ color: '#8892b0', fontSize: '0.9rem' }}>
              {activeTab === 'url' ? 'Analyzing URL &mdash; running AI inference...' :
               activeTab === 'domain' ? 'Looking up domain DNS/WHOIS records...' :
               'Looking up IP address information...'}
            </span>
          </div>
        )}

        {error && (
          <div style={{
            background: '#2a1515', border: '1px solid #ef4444', borderRadius: '10px',
            padding: '1rem 1.25rem', width: '100%', marginTop: '1rem',
          }}>
            <p style={{ margin: 0, fontWeight: 600, color: '#fca5a5', fontSize: '0.9rem' }}>Error</p>
            <p style={{ margin: '0.25rem 0 0', color: '#fca5a5', fontSize: '0.85rem' }}>{error}</p>
          </div>
        )}

        {result && <ResultCard result={result} />}

        {/* History */}
        {history.length > 0 && (
          <div style={{
            marginTop: '1.5rem', width: '100%',
            background: '#131b2a', borderRadius: '12px', padding: '1.25rem',
            border: '1px solid #1e2a45',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h3 style={{ margin: 0, fontSize: '0.95rem', color: '#fff', fontWeight: 600 }}>Previous Checks</h3>
              <button onClick={() => setHistory([])} style={{
                background: 'none', border: '1px solid #2a3a52', color: '#8892b0',
                borderRadius: '6px', padding: '0.25rem 0.5rem', fontSize: '0.75rem',
                cursor: 'pointer',
              }}>Clear</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              {history.map((h, i) => (
                <div key={i} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.4rem 0.6rem', borderRadius: '6px', background: '#0b0f19',
                  fontSize: '0.8rem',
                }}>
                  <span style={{ color: h.phishing ? '#ef4444' : '#10b981', fontWeight: 600, marginRight: '0.5rem', flexShrink: 0 }}>
                    {h.phishing ? '\u26A0' : '\u2713'}
                  </span>
                  <span style={{ color: '#c4d1ec', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                    {h.url}
                  </span>
                  <span style={{
                    color: h.phishing ? '#ef4444' : '#10b981', fontWeight: 600,
                    flexShrink: 0, margin: '0 0.5rem', fontSize: '0.75rem', minWidth: '42px', textAlign: 'right',
                  }}>
                    {h.prob != null ? `${h.prob.toFixed(0)}%` : ''}
                  </span>
                  <span style={{ color: '#64748b', flexShrink: 0, fontSize: '0.75rem' }}>{h.time}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Stats Footer */}
      {!result && <footer style={{
        width: '100%',
        borderTop: '1px solid #1e2a45',
        background: '#0d1117',
        padding: '1.5rem',
        marginTop: 'auto',
      }}>
        <div style={{
        maxWidth: '1200px',
          margin: '0 auto',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
        }}>
          <div style={{
            background: '#131b2a', borderRadius: '10px', padding: '1rem 1.25rem',
            border: '1px solid #1e2a45',
          }}>
            <p style={{ margin: 0, color: '#8892b0', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>AI Model</p>
            <p style={{ margin: '0.35rem 0 0', color: '#fff', fontSize: '0.85rem', fontWeight: 600 }}>
              Gated Fusion
            </p>
            <p style={{ margin: '0.15rem 0 0', color: '#64748b', fontSize: '0.75rem' }}>
              TabTransformer + ModernBERT
            </p>
          </div>
          <div style={{
            background: '#131b2a', borderRadius: '10px', padding: '1rem 1.25rem',
            border: '1px solid #1e2a45',
          }}>
            <p style={{ margin: 0, color: '#8892b0', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Accuracy</p>
            <p style={{ margin: '0.35rem 0 0', color: '#10b981', fontSize: '1.3rem', fontWeight: 700 }}>
              97.7%
            </p>
            <p style={{ margin: '0.15rem 0 0', color: '#64748b', fontSize: '0.75rem' }}>
              F1 Score on Mendeley 2021
            </p>
          </div>
          <div style={{
            background: '#131b2a', borderRadius: '10px', padding: '1rem 1.25rem',
            border: '1px solid #1e2a45',
          }}>
            <p style={{ margin: 0, color: '#8892b0', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>AUC Score</p>
            <p style={{ margin: '0.35rem 0 0', color: '#3b82f6', fontSize: '1.3rem', fontWeight: 700 }}>
              0.993
            </p>
            <p style={{ margin: '0.15rem 0 0', color: '#64748b', fontSize: '0.75rem' }}>
              5-Fold Cross Validation
            </p>
          </div>
        </div>
      </footer>}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        input:focus { box-shadow: 0 0 0 2px rgba(59,130,246,0.3); }
      `}</style>
    </div>
  )
}

export default App
