function ResultCard({ result }) {
  if (!result) return null

  const confidence = result.phishing_probability
  const isPhishing = confidence >= 0.5
  const pct = (confidence * 100).toFixed(1)

  let barColor, badgeBg, badgeColor
  if (confidence < 0.3) {
    barColor = '#22c55e'
    badgeBg = '#14532d'
    badgeColor = '#86efac'
  } else if (confidence < 0.6) {
    barColor = '#eab308'
    badgeBg = '#713f12'
    badgeColor = '#fde047'
  } else {
    barColor = '#ef4444'
    badgeBg = '#7f1d1d'
    badgeColor = '#fca5a5'
  }

  const barWidth = `${pct}%`
  const features = result.features || result.top_features || []

  return (
    <div style={{
      background: '#1e293b',
      borderRadius: '12px',
      padding: '1.5rem',
      maxWidth: '600px',
      width: '100%',
      marginTop: '1.5rem',
      border: `1px solid ${barColor}`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem', color: '#f1f5f9' }}>
          Analysis Result
        </h2>
        <span style={{
          padding: '0.25rem 0.75rem',
          borderRadius: '999px',
          fontSize: '0.85rem',
          fontWeight: 600,
          background: badgeBg,
          color: badgeColor,
        }}>
          {isPhishing ? '⚠ PHISHING' : '✓ SAFE'}
        </span>
      </div>

      <div style={{ marginBottom: '0.75rem' }}>
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.25rem' }}>URL</p>
        <p style={{
          margin: 0,
          color: '#e2e8f0',
          wordBreak: 'break-all',
          fontSize: '0.9rem',
          fontFamily: 'monospace',
        }}>
          {result.url}
        </p>
      </div>

      <div style={{ marginBottom: '0.75rem' }}>
        <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.25rem' }}>
          Phishing Probability
        </p>
        <div style={{
          width: '100%',
          height: '24px',
          background: '#334155',
          borderRadius: '12px',
          overflow: 'hidden',
          position: 'relative',
        }}>
          <div style={{
            width: barWidth,
            height: '100%',
            background: barColor,
            borderRadius: '12px',
            transition: 'width 0.5s ease',
          }} />
          <span style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            fontSize: '0.8rem',
            fontWeight: 600,
            color: '#f8fafc',
            textShadow: '0 1px 2px rgba(0,0,0,0.5)',
          }}>
            {pct}%
          </span>
        </div>
        <p style={{ color: '#64748b', fontSize: '0.75rem', margin: '0.25rem 0 0', textAlign: 'right' }}>
          0-30% safe · 30-60% suspicious · 60-100% phishing
        </p>
      </div>

      {features.length > 0 && (
        <div style={{ marginBottom: '0.75rem' }}>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.5rem' }}>
            Top URL Features
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {features.slice(0, 6).map((f, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between',
                padding: '0.3rem 0.5rem', borderRadius: '6px',
                background: '#0f172a', fontSize: '0.8rem',
              }}>
                <span style={{ color: '#94a3b8' }}>{f.name || f.key || `Feature ${i + 1}`}</span>
                <span style={{ color: f.value > 0.5 ? '#fca5a5' : '#86efac', fontWeight: 600 }}>
                  {typeof f.value === 'number' ? f.value.toFixed(3) : f.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {result.brand && (
        <div style={{
          marginBottom: '0.75rem', padding: '0.5rem 0.75rem',
          borderRadius: '8px', background: '#0f172a',
          border: '1px solid #334155',
        }}>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: '0 0 0.25rem' }}>Brand Detected</p>
          <p style={{ margin: 0, color: '#f1f5f9', fontWeight: 600 }}>
            {result.brand.name || result.brand}
          </p>
        </div>
      )}

      <p style={{ color: '#64748b', fontSize: '0.8rem', margin: 0 }}>
        HTML content: {result.html_provided ? '✓ Provided' : '✗ Not provided'}
      </p>
    </div>
  )
}

export default ResultCard
