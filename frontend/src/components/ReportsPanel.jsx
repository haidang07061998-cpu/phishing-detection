import { useState, useEffect, useCallback } from 'react'
import { getApiUrl, getApiHeaders, friendlyError } from '../api'

const VERDICT_COLORS = {
  safe: 'var(--success)',
  suspicious: 'var(--warning)',
  phishing: 'var(--danger)',
}

function formatLatency(ms) {
  if (ms == null || Number.isNaN(Number(ms))) return '–'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

function VerdictBadge({ verdict }) {
  const color = VERDICT_COLORS[verdict] || 'var(--text-muted)'
  return (
    <span style={{
      padding: '0.1rem 0.5rem', borderRadius: '999px', fontSize: '0.68rem', fontWeight: 700,
      background: color + '1a', color, border: `1px solid ${color}55`,
      textTransform: 'uppercase',
    }}>{verdict}</span>
  )
}

function ReportsPanel() {
  const [records, setRecords] = useState([])
  const [summary, setSummary] = useState(null)
  const [threats, setThreats] = useState(null)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [newThreat, setNewThreat] = useState('')
  const [adminKey, setAdminKey] = useState('')
  const [keyEntered, setKeyEntered] = useState(false)

  const load = useCallback(async (key) => {
    setError('')
    try {
      const apiUrl = getApiUrl()
      const h = getApiHeaders({}, key)
      const [hist, thr] = await Promise.all([
        fetch(`${apiUrl}/history?limit=50`, { headers: h }).then(r => r.json()),
        fetch(`${apiUrl}/threat`, { headers: h }).then(r => r.json()),
      ])
      if (hist && Array.isArray(hist.records)) {
        setRecords(hist.records)
        setSummary(hist.summary || null)
      } else if (hist && hist.error) {
        setError(friendlyError({ status: 403, message: hist.error }))
      }
      if (thr && Array.isArray(thr.entries)) setThreats(thr)
    } catch (e) {
      setError(friendlyError(e))
    }
  }, [])

  // Reports require a runtime-entered reports/admin key — never the bundled key.
  useEffect(() => {
    if (keyEntered && adminKey.trim()) load(adminKey.trim())
  }, [keyEntered, adminKey, load])

  const handleKeySubmit = (e) => {
    e.preventDefault()
    if (!adminKey.trim()) {
      setError('Enter a reports-scoped API key to view reports.')
      return
    }
    setKeyEntered(true)
  }

  const exportData = async (fmt) => {
    setError('')
    try {
      const apiUrl = getApiUrl()
      const res = await fetch(`${apiUrl}/history/export?format=${fmt}`, { headers: getApiHeaders({}, adminKey.trim()) })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.error || 'Export failed')
        return
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan_history.${fmt}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(friendlyError(err))
    }
  }

  const addThreat = async (e) => {
    e.preventDefault()
    const value = newThreat.trim()
    if (!value) return
    if (!adminKey.trim()) {
      setError('Admin API key required to modify the blocklist. Enter it below (it is held in memory only, never stored).')
      return
    }
    try {
      const apiUrl = getApiUrl()
      const res = await fetch(`${apiUrl}/threat`, {
        method: 'POST', headers: getApiHeaders({}, adminKey.trim()), body: JSON.stringify({ value, source: 'manual' }),
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.error || 'Could not add threat entry')
        return
      }
      setNewThreat('')
      load(adminKey.trim())
    } catch (err) {
      setError(friendlyError(err))
    }
  }

  const removeThreat = async (value) => {
    if (!adminKey.trim()) {
      setError('Admin API key required to modify the blocklist. Enter it below (it is held in memory only, never stored).')
      return
    }
    try {
      const apiUrl = getApiUrl()
      await fetch(`${apiUrl}/threat`, {
        method: 'DELETE', headers: getApiHeaders({}, adminKey.trim()), body: JSON.stringify({ value }),
      })
      load(adminKey.trim())
    } catch (err) {
      setError(friendlyError(err))
    }
  }

  const filtered = records.filter(r =>
    !filter || (r.target || '').toLowerCase().includes(filter.toLowerCase()) ||
      (r.url || '').toLowerCase().includes(filter.toLowerCase()))

  const localThreats = (threats?.entries || []).filter(t => t.layer === 'local')

  return (
    <div style={{ width: '100%', marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Reports access key gate — reports never use the bundled VITE_API_KEY */}
      <form onSubmit={handleKeySubmit} style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '1rem 1.25rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '220px' }}>
            <label htmlFor="reports-key" style={{ display: 'block', color: 'var(--text-muted)', fontSize: '0.72rem', fontWeight: 600, marginBottom: '0.3rem' }}>
              Reports API Key (reports or admin scope)
            </label>
            <input
              id="reports-key"
              type="password" value={adminKey} onChange={(e) => { setAdminKey(e.target.value); setKeyEntered(false) }}
              placeholder="Enter a reports/admin-scoped key — held in memory only" aria-label="Reports API key"
              autoComplete="off"
              style={{ width: '100%', padding: '0.4rem 0.6rem', fontSize: '0.78rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-input)', color: 'var(--text-primary)', outline: 'none' }}
            />
          </div>
          <button type="submit" disabled={!adminKey.trim()} style={{
            padding: '0.4rem 1rem', fontSize: '0.78rem', borderRadius: '6px', border: 'none',
            background: keyEntered ? 'var(--success)' : 'var(--accent)', color: '#fff', cursor: 'pointer', fontWeight: 600, alignSelf: 'flex-end',
          }}>
            {keyEntered ? '\u2713 Connected' : 'Load Reports'}
          </button>
        </div>
        <p style={{ margin: '0.5rem 0 0', color: 'var(--text-muted)', fontSize: '0.7rem', lineHeight: '1.4' }}>
          Scan history and the threat database are sensitive. Reports never use the build-time
          <code> VITE_API_KEY</code> — enter a <code>reports</code>- or <code>admin</code>-scoped registry key here.
          It is used for these calls only and never persisted.
        </p>
      </form>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '0.9rem 1rem' }}>
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Total Scans</p>
          <p style={{ margin: '0.3rem 0 0', color: 'var(--text-bright)', fontSize: '1.3rem', fontWeight: 700 }}>{summary?.total ?? '–'}</p>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '0.9rem 1rem' }}>
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Phishing</p>
          <p style={{ margin: '0.3rem 0 0', color: 'var(--danger)', fontSize: '1.3rem', fontWeight: 700 }}>{summary?.counts?.phishing ?? '–'}</p>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '0.9rem 1rem' }}>
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Suspicious</p>
          <p style={{ margin: '0.3rem 0 0', color: 'var(--warning)', fontSize: '1.3rem', fontWeight: 700 }}>{summary?.counts?.suspicious ?? '–'}</p>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '0.9rem 1rem' }}>
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Threat DB Hits</p>
          <p style={{ margin: '0.3rem 0 0', color: 'var(--accent)', fontSize: '1.3rem', fontWeight: 700 }}>{summary?.threat_db_hits ?? '–'}</p>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '0.9rem 1rem' }}>
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Blocklist Entries</p>
          <p style={{ margin: '0.3rem 0 0', color: 'var(--text-bright)', fontSize: '1.3rem', fontWeight: 700 }}>{threats?.count ?? '–'}</p>
        </div>
      </div>

      {error && (
        <div role="alert" style={{ background: 'var(--danger-bg)', border: '1px solid var(--danger)', borderRadius: '10px', padding: '0.75rem 1rem' }}>
          <p style={{ margin: 0, color: 'var(--danger)', fontSize: '0.8rem', fontWeight: 600 }}>Reports unavailable</p>
          <p style={{ margin: '0.2rem 0 0', color: 'var(--danger)', fontSize: '0.75rem' }}>{error} Enable auth (API key) and a key with the 'reports' scope to view this tab.</p>
        </div>
      )}

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <h3 style={{ margin: 0, fontSize: '0.95rem', color: 'var(--text-bright)', fontWeight: 600 }}>Scan History</h3>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <input
              type="text" value={filter} onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by target/URL" aria-label="Filter scan history"
              style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-input)', color: 'var(--text-primary)', outline: 'none' }}
            />
            <button onClick={() => exportData('json')} style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-tab)', color: 'var(--text-primary)', cursor: 'pointer' }}>JSON</button>
            <button onClick={() => exportData('csv')} style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-tab)', color: 'var(--text-primary)', cursor: 'pointer' }}>CSV</button>
          </div>
        </div>
        {filtered.length === 0 ? (
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', padding: '1rem' }}>
            No scans recorded yet — run a URL scan to populate history.
          </p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
              <thead>
                <tr style={{ color: 'var(--text-muted)', textAlign: 'left' }}>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Time</th>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Target</th>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Verdict</th>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Score</th>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Latency</th>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Quality</th>
                  <th style={{ padding: '0.35rem 0.5rem', borderBottom: '1px solid var(--border)', fontWeight: 600 }}>Threat DB</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '0.35rem 0.5rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {r.timestamp ? new Date(r.timestamp).toLocaleString() : '–'}
                    </td>
                    <td style={{ padding: '0.35rem 0.5rem', color: 'var(--text-primary)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.target || r.url || '–'}
                    </td>
                    <td style={{ padding: '0.35rem 0.5rem' }}><VerdictBadge verdict={r.verdict} /></td>
                    <td style={{ padding: '0.35rem 0.5rem', color: VERDICT_COLORS[r.verdict] || 'var(--text-primary)', fontWeight: 600 }}>{r.aggregate_score != null ? `${r.aggregate_score}/100` : '–'}</td>
                    <td style={{ padding: '0.35rem 0.5rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{formatLatency(r.latency_ms)}</td>
                    <td style={{ padding: '0.35rem 0.5rem', color: 'var(--text-muted)' }}>{r.analysis_quality || '–'}</td>
                    <td style={{ padding: '0.35rem 0.5rem', color: r.threat_db_hit ? 'var(--danger)' : 'var(--text-muted)' }}>
                      {r.threat_db_hit ? 'HIT' : '–'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '1.25rem' }}>
        <h3 style={{ margin: '0 0 0.75rem', fontSize: '0.95rem', color: 'var(--text-bright)', fontWeight: 600 }}>
          Known-Threat Database
        </h3>
        <p style={{ margin: '0 0 0.75rem', color: 'var(--text-muted)', fontSize: '0.72rem', lineHeight: '1.5' }}>
          Adding/removing blocklist entries requires an <code>admin</code>-scoped key — the same key entered above.
          With a <code>reports</code>-only key the list is read-only.
        </p>
        <form onSubmit={addThreat} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input
            type="text" value={newThreat} onChange={(e) => setNewThreat(e.target.value)}
            placeholder="Add URL or domain to blocklist, e.g. secure-paypa1.com" aria-label="Add threat entry"
            style={{ flex: 1, padding: '0.4rem 0.6rem', fontSize: '0.78rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-input)', color: 'var(--text-primary)', outline: 'none' }}
          />
          <button type="submit" disabled={!newThreat.trim()} style={{ padding: '0.4rem 0.9rem', fontSize: '0.78rem', borderRadius: '6px', border: 'none', background: 'var(--danger)', color: '#fff', cursor: 'pointer', fontWeight: 600 }}>Add</button>
        </form>
        {localThreats.length === 0 ? (
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.78rem' }}>
            Blocklist is empty. Add domains/URLs known to be malicious; they become a strong signal in every scan.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {localThreats.map((t, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.35rem 0.6rem', borderRadius: '6px', background: 'var(--bg-page)', fontSize: '0.75rem' }}>
                <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.value}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>{t.source || 'manual'}</span>
                  <button onClick={() => removeThreat(t.value)} aria-label={`Remove ${t.value}`} style={{ background: 'none', border: 'none', color: 'var(--danger)', cursor: 'pointer', fontSize: '0.9rem', padding: '0 0.2rem' }}>✕</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default ReportsPanel