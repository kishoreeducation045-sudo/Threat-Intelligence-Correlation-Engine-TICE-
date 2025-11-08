import { memo } from 'react'
import './ThreatCard.css'

const riskPalette = {
  LOW: '#16a34a',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#dc2626',
}

const formatNumber = (value) =>
  typeof value === 'number' && !Number.isNaN(value) ? value.toLocaleString() : '—'

const formatTime = (value) => {
  if (!value) return '—'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

const ThreatCard = ({ report }) => {
  const severityColor = riskPalette[report.risk_level] ?? '#6b7280'
  const isRepeat = (report.occurrence_count ?? 0) > 1
  const isMostReported = (report.occurrence_count ?? 0) >= 3

  return (
    <article className="threat-card" data-risk={report.risk_level}>
      <header className="threat-card__header" style={{ borderColor: severityColor }}>
        <div>
          <h4>{report.ip_address}</h4>
          <span className="risk-level" style={{ color: severityColor }}>
            {report.risk_level}
          </span>
        </div>
        <div className="score" style={{ color: severityColor }}>
          {report.threat_score}
          <span>/100</span>
        </div>
      </header>

      <section className="threat-card__meta">
        <div>
          <span className="label">Abuse Confidence</span>
          <span className="value">{formatNumber(report.abuse_confidence)}%</span>
        </div>
        <div>
          <span className="label">Total Reports</span>
          <span className="value">{formatNumber(report.total_reports)}</span>
        </div>
        <div>
          <span className="label">Country</span>
          <span className="value">{report.country ?? 'Unknown'}</span>
        </div>
        <div>
          <span className="label">ASN</span>
          <span className="value">{report.asn ?? 'Unknown'}</span>
        </div>
      </section>

      <section className="threat-card__badges">
        {report.is_new && <span className="badge badge-new">New</span>}
        {isRepeat && !isMostReported && (
          <span className="badge badge-repeat">Repeat x{report.occurrence_count}</span>
        )}
        {isMostReported && <span className="badge badge-hot">Most Reported</span>}
        <span className="timestamp">{formatTime(report.analyzed_at)}</span>
      </section>

      <section className="threat-card__categories">
        {(report.categories || []).length === 0 ? (
          <span className="empty">No categories</span>
        ) : (
          (report.categories || []).map((category) => (
            <span key={category} className="category">
              {category}
            </span>
          ))
        )}
      </section>

      <section className="threat-card__rules">
        {(report.triggered_rules || []).length === 0 ? (
          <span className="empty">No rules triggered</span>
        ) : (
          (report.triggered_rules || []).map((rule) => (
            <span key={rule} className="rule-chip">
              {rule}
            </span>
          ))
        )}
      </section>

      {report.narrative && (
        <section className="threat-card__narrative">
          <p>{report.narrative}</p>
        </section>
      )}
    </article>
  )
}

export default memo(ThreatCard)
