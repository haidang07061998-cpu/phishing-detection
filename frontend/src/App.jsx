import { useState } from 'react'
import UrlInput from './components/UrlInput'
import ResultCard from './components/ResultCard'
import { useTheme } from './ThemeContext'

const API_URL = import.meta.env.VITE_API_URL || '/api'

function SkeletonLine({ width, height }) {
  return <div className="skeleton-pulse" style={{ width: width || '60%', height: height || '0.75rem', borderRadius: '6px', background: 'var(--bg-tab)' }} />
}

function SkeletonBlock({ height, width }) {
  return <div className="skeleton-pulse" style={{ width: width || '100%', height: height || '8rem', borderRadius: '8px', background: 'var(--bg-card)', border: '1px solid var(--border)' }} />
}

function SkeletonResult({ activeTab }) {
  return (
    <div style={{ width: '100%', marginTop: '1.5rem', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)' }}>
      <div className="skeleton-pulse" style={{ height: '5px', background: 'var(--border)' }} />
      <div style={{ background: 'var(--bg-card)', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <SkeletonLine width="100px" height="0.65rem" />
            <SkeletonLine width="80%" height="0.85rem" />
          </div>
          <SkeletonLine width="80px" height="1.5rem" />
        </div>
        <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1rem' }}>
          {['Overview', 'Details', 'Behavior', 'AI Copilot'].map((_, i) => (
            <div key={i} className="skeleton-pulse" style={{ height: '1.6rem', width: i === 3 ? '60px' : '70px', borderRadius: '6px', background: 'var(--bg-tab)' }} />
          ))}
        </div>
        <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'flex-start' }}>
          <SkeletonLine width="120px" height="120px" />
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <SkeletonLine width="40%" />
            <SkeletonLine width="90%" height="0.65rem" />
            <SkeletonLine width="75%" height="0.65rem" />
            <SkeletonLine width="60%" height="0.65rem" />
          </div>
        </div>
      </div>
      <style>{`
        @keyframes skeleton-shimmer {
          0% { opacity: 0.5; }
          50% { opacity: 0.8; }
          100% { opacity: 0.5; }
        }
        .skeleton-pulse {
          animation: skeleton-shimmer 1.5s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])
  const [activeTab, setActiveTab] = useState('url')
  const { isDark, toggle: toggleTheme } = useTheme()

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
      background: 'var(--bg-page)',
      color: 'var(--text-primary)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'stretch',
    }}>
      {/* Header */}
      <header style={{
        width: '100%',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-header)',
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
            <div style={{ display: 'flex', gap: '0.25rem', background: 'var(--bg-tab)', borderRadius: '8px', padding: '2px' }}>
              {['url', 'domain', 'ip address'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  style={{
                    padding: '0.35rem 0.85rem',
                    borderRadius: '6px',
                    border: 'none',
                    background: activeTab === tab ? '#3b82f6' : 'transparent',
                    color: activeTab === tab ? '#fff' : 'var(--text-secondary)',
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button onClick={toggleTheme} style={{
              background: 'var(--bg-tab)', border: '1px solid var(--border)', borderRadius: '6px',
              padding: '0.25rem 0.5rem', cursor: 'pointer', fontSize: '0.85rem', lineHeight: 1,
              color: 'var(--text-secondary)',
            }} title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}>
              {isDark ? '\u2600' : '\uD83C\uDF19'}
            </button>
            <span style={{
              padding: '0.25rem 0.65rem', borderRadius: '6px',
              background: 'var(--bg-tab)', color: 'var(--text-secondary)',
              fontSize: '0.75rem', border: '1px solid var(--border)',
            }}>
              AI Model v2.0
            </span>
          </div>
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
          color: 'var(--text-secondary)',
          fontSize: '0.95rem',
          margin: '0 0 2rem',
          textAlign: 'center',
        }}>
          {activeTab === 'url' ? 'Powered by Gated Fusion AI \u00B7 TabTransformer + ModernBERT + DOM Analysis' :
           activeTab === 'domain' ? 'DNS records \u00B7 WHOIS data \u00B7 SSL certificate info' :
           'Reverse DNS \u00B7 WHOIS lookup \u00B7 Network intelligence'}
        </p>

        <UrlInput onPredict={handlePredict} loading={loading} activeTab={activeTab} />

        {loading && (
          <SkeletonResult activeTab={activeTab} />
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
            background: 'var(--bg-card)', borderRadius: '12px', padding: '1.25rem',
            border: '1px solid var(--border)',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h3 style={{ margin: 0, fontSize: '0.95rem', color: '#fff', fontWeight: 600 }}>Previous Checks</h3>
              <button onClick={() => setHistory([])} style={{
                background: 'none', border: '1px solid #2a3a52', color: 'var(--text-secondary)',
                borderRadius: '6px', padding: '0.25rem 0.5rem', fontSize: '0.75rem',
                cursor: 'pointer',
              }}>Clear</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              {history.map((h, i) => (
                <div key={i} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '0.4rem 0.6rem', borderRadius: '6px', background: 'var(--bg-page)',
                  fontSize: '0.8rem',
                }}>
                  <span style={{ color: h.phishing ? '#ef4444' : '#10b981', fontWeight: 600, marginRight: '0.5rem', flexShrink: 0 }}>
                    {h.phishing ? '\u26A0' : '\u2713'}
                  </span>
                  <span style={{ color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                    {h.url}
                  </span>
                  <span style={{
                    color: h.phishing ? '#ef4444' : '#10b981', fontWeight: 600,
                    flexShrink: 0, margin: '0 0.5rem', fontSize: '0.75rem', minWidth: '42px', textAlign: 'right',
                  }}>
                    {h.prob != null ? `${h.prob.toFixed(0)}%` : ''}
                  </span>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0, fontSize: '0.75rem' }}>{h.time}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Stats Footer */}
      {!result && <footer style={{
        width: '100%',
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-header)',
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
            background: 'var(--bg-card)', borderRadius: '10px', padding: '1rem 1.25rem',
            border: '1px solid var(--border)',
          }}>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>AI Model</p>
            <p style={{ margin: '0.35rem 0 0', color: '#fff', fontSize: '0.85rem', fontWeight: 600 }}>
              Gated Fusion
            </p>
            <p style={{ margin: '0.15rem 0 0', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
              TabTransformer + ModernBERT
            </p>
          </div>
          <div style={{
            background: 'var(--bg-card)', borderRadius: '10px', padding: '1rem 1.25rem',
            border: '1px solid var(--border)',
          }}>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Accuracy</p>
            <p style={{ margin: '0.35rem 0 0', color: '#10b981', fontSize: '1.3rem', fontWeight: 700 }}>
              97.7%
            </p>
            <p style={{ margin: '0.15rem 0 0', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
              F1 Score on Mendeley 2021
            </p>
          </div>
          <div style={{
            background: 'var(--bg-card)', borderRadius: '10px', padding: '1rem 1.25rem',
            border: '1px solid var(--border)',
          }}>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>AUC Score</p>
            <p style={{ margin: '0.35rem 0 0', color: '#3b82f6', fontSize: '1.3rem', fontWeight: 700 }}>
              0.993
            </p>
            <p style={{ margin: '0.15rem 0 0', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
              5-Fold Cross Validation
            </p>
          </div>
        </div>
      </footer>}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes skeleton-shimmer {
          0% { opacity: 0.5; }
          50% { opacity: 0.8; }
          100% { opacity: 0.5; }
        }
        .skeleton-pulse { animation: skeleton-shimmer 1.5s ease-in-out infinite; }
        input:focus { box-shadow: 0 0 0 2px rgba(59,130,246,0.3); }
        @media (max-width: 768px) {
          .app-header-inner { flex-wrap: wrap; gap: 0.5rem !important; }
          .app-tabs { order: 3; width: 100%; overflow-x: auto; }
        }
        @media (max-width: 640px) {
          .app-main { padding: 1.5rem 0.75rem 1rem !important; }
          .app-header-inner { padding: 0 0.75rem !important; }
        }
      `}</style>
    </div>
  )
}

export default App
