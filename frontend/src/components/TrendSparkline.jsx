import './TrendSparkline.css'

const TrendSparkline = ({ data }) => {
  if (!data || data.length === 0) {
    return <div className="sparkline-empty">No trend data</div>
  }

  const width = 260
  const height = 80
  const padding = 10
  const counts = data.map((point) => point.count || 0)
  const max = Math.max(...counts, 1)
  const step = data.length > 1 ? (width - padding * 2) / (data.length - 1) : 0

  const path = data
    .map((point, index) => {
      const x = padding + index * step
      const scaled = (point.count || 0) / max
      const y = height - padding - scaled * (height - padding * 2)
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`
    })
    .join(' ')

  const gradientId = 'sparkline-gradient'

  return (
    <svg
      className="sparkline"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Trend sparkline"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="rgba(14, 165, 233, 0.35)" />
          <stop offset="100%" stopColor="rgba(14, 165, 233, 0)" />
        </linearGradient>
      </defs>

      <path
        className="sparkline-fill"
        d={`${path} L ${padding + (data.length - 1) * step} ${height - padding} L ${padding} ${height - padding} Z`}
        fill={`url(#${gradientId})`}
      />
      <path className="sparkline-line" d={path} />
      {data.map((point, index) => {
        const x = padding + index * step
        const scaled = (point.count || 0) / max
        const y = height - padding - scaled * (height - padding * 2)
        return <circle key={point.bucket ?? index} cx={x} cy={y} r={3} className="sparkline-dot" />
      })}
    </svg>
  )
}

export default TrendSparkline
