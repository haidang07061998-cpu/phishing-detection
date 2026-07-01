function ResultCard({ result }) {
  if (!result) return null

  const isPhishing = result.phishing_probability >= 0.5
  const barWidth = `${Math.round(result.phishing_probability * 100)}%`
  const barColor = isPhishing ? '#ef4444' : '#22c55e'

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
          background: isPhishing ? '#7f1d1d' : '#14532d',
          color: isPhishing ? '#fca5a5' : '#86efac',
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
            {(result.phishing_probability * 100).toFixed(1)}%
          </span>
        </div>
      </div>

      <p style={{ color: '#64748b', fontSize: '0.8rem', margin: 0 }}>
        HTML content: {result.html_provided ? '✓ Provided' : '✗ Not provided'}
      </p>
    </div>
  )
}

export default ResultCard
