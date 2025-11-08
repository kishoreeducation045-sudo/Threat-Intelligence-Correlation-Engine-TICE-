import { useEffect, useMemo, useState } from 'react'
import { fetchRecentReports, fetchReportStats } from '../services/api'
import ThreatCard from './ThreatCard'
import TrendSparkline from './TrendSparkline'
import './ThreatDashboard.css'

const REFRESH_INTERVAL_MS = 15000
const RECENT_LIMIT = 36

const formatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
})

const relativeTime = (value) => {
  if (!value) return '—'
  const now = Date.now()
  const timestamp = new Date(value).getTime()
  const diff = Math.max(0, now - timestamp)
  const minute = 60 * 1000
  const hour = 60 * minute
  const day = 24 * hour

  if (diff < minute) return 'moments ago'
  if (diff < hour) {
    const minutes = Math.round(diff / minute)
    return `${minutes} min ago`
  }
  if (diff < day) {
    const hours = Math.round(diff / hour)
    return `${hours} hr ago`
  }
  const days = Math.round(diff / day)
  return `${days} day${days > 1 ? 's' : ''} ago`
}

const riskPalette = {
  LOW: '#10b981',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#dc2626',
}

function ThreatDashboard() {
  const [reports, setReports] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [isRefreshing, setIsRefreshing] = useState(false)

  const loadData = async (showSpinner = true) => {
    try {
      if (showSpinner) {
        setLoading(true)
      } else {
        setIsRefreshing(true)
      }
      const [recent, dashboardStats] = await Promise.all([
        fetchRecentReports(RECENT_LIMIT),
        fetchReportStats(24),
      ])
      setReports(recent.reports || [])
      setStats(dashboardStats)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setIsRefreshing(false)
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(() => loadData(false), REFRESH_INTERVAL_MS)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const categoryChips = useMemo(() => {
    if (!stats?.category_counts) return []
    return Object.entries(stats.category_counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
  }, [stats])

  const riskCounts = useMemo(() => {
    if (!stats?.risk_counts) return []
    return Object.entries(stats.risk_counts)
  }, [stats])

  const metrics = useMemo(() => stats?.metrics || {}, [stats])

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div>
          <h2>Live Threat Feed</h2>
          <p>Real-time intelligence wall for top risky IPs</p>
        </div>
        <div className="dashboard-actions">
          <button className="refresh-button" onClick={() => loadData(false)} disabled={isRefreshing}>
            {isRefreshing ? 'Refreshing…' : 'Refresh now'}
          </button>
          <span className="last-updated" title={metrics.last_analysis_at ? formatter.format(new Date(metrics.last_analysis_at)) : ''}>
            Last update: {metrics.last_analysis_at ? relativeTime(metrics.last_analysis_at) : 'No data yet'}
          </span>
        </div>
      </div>

      {error && <div className="dashboard-error">⚠️ {error}</div>}

      <section className="dashboard-summary">
        <div className="summary-card">
          <h3>Total Reports</h3>
          <p className="summary-value">{metrics.total_reports ?? 0}</p>
          <span className="summary-caption">Stored analyses</span>
        </div>
        <div className="summary-card">
          <h3>Unique IPs</h3>
          <p className="summary-value">{metrics.unique_ips ?? 0}</p>
          <span className="summary-caption">Distinct addresses observed</span>
        </div>
        <div className="summary-card">
          <h3>Risk Mix</h3>
          <div className="risk-counts">
            {riskCounts.length === 0 && <span className="empty">No data</span>}
            {riskCounts.map(([risk, count]) => (
              <span key={risk} className="risk-chip" style={{ backgroundColor: `${riskPalette[risk] ?? '#6b7280'}22`, color: riskPalette[risk] ?? '#374151' }}>
                {risk}: {count}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="dashboard-widgets">
        <div className="widget widget-top-risks">
          <header>
            <h3>Top Risks</h3>
            <span>Highest scoring IPs</span>
          </header>
          <ul>
            {stats?.top_risks?.length ? (
              stats.top_risks.map((item) => (
                <li key={`${item.ip_address}-${item.last_seen}`}>
                  <div className="risk-label">
                    <span className="ip">{item.ip_address}</span>
                    <span className="score" style={{ color: riskPalette[item.risk_level] ?? '#374151' }}>
                      {item.threat_score}
                    </span>
                  </div>
                  <div className="risk-meta">
                    <span>{item.risk_level}</span>
                    <span>{relativeTime(item.last_seen)}</span>
                    <span>{item.occurrence_count} detections</span>
                  </div>
                </li>
              ))
            ) : (
              <li className="empty">No high risk IPs yet</li>
            )}
          </ul>
        </div>

        <div className="widget widget-trend">
          <header>
            <h3>Activity Trend</h3>
            <span>Last 24 hours</span>
          </header>
          <TrendSparkline data={stats?.report_volume || []} />
        </div>

        <div className="widget widget-categories">
          <header>
            <h3>Common Categories</h3>
            <span>Top 8 categories observed</span>
          </header>
          <div className="category-chips">
            {categoryChips.length === 0 && <span className="empty">No category data</span>}
            {categoryChips.map(([category, count]) => (
              <span key={category} className="category-chip">
                {category} <span>{count}</span>
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="dashboard-feed">
        <header className="feed-header">
          <h3>Recent Analyses</h3>
          <span>{reports.length} results</span>
        </header>

        {loading ? (
          <div className="dashboard-loading">Loading latest intelligence…</div>
        ) : reports.length === 0 ? (
          <div className="dashboard-empty">Run an analysis to populate the live feed.</div>
        ) : (
          <div className="feed-grid">
            {reports.map((report) => (
              <ThreatCard key={report.id} report={report} />
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

export default ThreatDashboard
