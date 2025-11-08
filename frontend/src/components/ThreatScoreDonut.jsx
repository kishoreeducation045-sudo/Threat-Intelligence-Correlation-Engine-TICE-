import './ThreatScoreDonut.css'

const clampScore = (score) => {
  if (Number.isNaN(Number(score))) return 0
  return Math.min(100, Math.max(0, Math.round(score)))
}

const ThreatScoreDonut = ({ score = 0 }) => {
  const normalized = clampScore(score)
  const angle = (normalized / 100) * 360
  const threatColor = '#f28b8b'
  const safeColor = '#9be7c4'
  const background = `conic-gradient(${threatColor} ${angle}deg, ${safeColor} ${angle}deg 360deg)`

  return (
    <div className="donut" style={{ background }}>
      <div className="donut-inner">
        <span className="donut-value">{normalized}%</span>
        <span className="donut-label">Threat</span>
      </div>
    </div>
  )
}

export default ThreatScoreDonut
