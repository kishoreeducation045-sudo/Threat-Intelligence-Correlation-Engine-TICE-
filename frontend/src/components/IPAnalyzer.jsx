import { useState, useEffect } from 'react'
import { analyzeIP, healthCheck, downloadAnalysis } from '../services/api'
import ThreatScoreDonut from './ThreatScoreDonut'
import './IPAnalyzer.css'

const riskColors = {
  LOW: '#3cba92',
  MEDIUM: '#ffb347',
  HIGH: '#ff6b6b',
  CRITICAL: '#db2c2c',
}

const IPAnalyzer = () => {
  const [ipAddress, setIpAddress] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [healthStatus, setHealthStatus] = useState(null)
  const [downloading, setDownloading] = useState(false)

  useEffect(() => {
    healthCheck()
      .then((data) => setHealthStatus({ status: 'healthy', ...data }))
      .catch(() => setHealthStatus({ status: 'unhealthy' }))
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!ipAddress.trim()) {
      setError('Please enter an IP address')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await analyzeIP(ipAddress.trim())
      setResult(data)
    } catch (err) {
      setError(err.message || 'Failed to analyze IP address')
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (riskLevel) => riskColors[riskLevel?.toUpperCase()] ?? '#6b7280'

  const handleDownload = async () => {
    if (!result?.ip_address) {
      return
    }

    try {
      setDownloading(true)
      const { blob, filename } = await downloadAnalysis(result.ip_address)
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message || 'Failed to download IP analysis')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="ip-analyzer">
      <div className="analyzer-container">
        <form onSubmit={handleSubmit} className="analyzer-form">
          <div className="form-group">
            <label htmlFor="ip-input">IP Address</label>
            <div className="input-group">
              <input
                id="ip-input"
                type="text"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                placeholder="Enter IPv4 address (e.g., 1.2.3.4)"
                disabled={loading}
                className="ip-input"
              />
              <button type="submit" disabled={loading} className="analyze-button">
                {loading ? 'Analyzing…' : 'Analyze'}
              </button>
            </div>
          </div>
        </form>

        {healthStatus && (
          <div className={`health-status ${healthStatus.status}`}>
            <span className="health-indicator"></span>
            Backend: {healthStatus.status === 'healthy' ? 'Connected' : 'Disconnected'}
          </div>
        )}

        {error && (
          <div className="error-message">
            <span>⚠️</span> {error}
          </div>
        )}

        {result && (
          <div className="result-container">
            <div className="result-header">
              <h2>Analysis Snapshot</h2>
              <div className="result-actions">
                <div className="ip-display">IP • {result.ip_address}</div>
                <button
                  type="button"
                  className="download-button"
                  onClick={handleDownload}
                  disabled={downloading}
                >
                  {downloading ? 'Preparing…' : 'Download JSON'}
                </button>
              </div>
            </div>

            <div className="result-grid">
              <div className="result-card score-card">
                <div className="card-label">Threat Score</div>
                <ThreatScoreDonut score={result.threat_score} />
              </div>

              <div className="result-card risk-card">
                <div className="card-label">Risk Level</div>
                <div
                  className="risk-badge"
                  style={{
                    backgroundColor: `${getRiskColor(result.risk_level)}22`,
                    color: getRiskColor(result.risk_level),
                  }}
                >
                  {result.risk_level}
                </div>
              </div>

              <div className="result-card">
                <div className="card-label">Country</div>
                <div className="card-value">{result.country || 'Unknown'}</div>
              </div>

              <div className="result-card">
                <div className="card-label">ASN</div>
                <div className="card-value">{result.asn || 'Unknown'}</div>
              </div>

              <div className="result-card">
                <div className="card-label">Malicious Sources</div>
                <div className="card-value">{result.malicious_sources || 0}</div>
              </div>

              <div className="result-card">
                <div className="card-label">Abuse Confidence</div>
                <div className="card-value">{result.abuse_confidence?.toFixed(1) || 0}%</div>
              </div>
            </div>

            {result.threat_categories && result.threat_categories.length > 0 && (
              <div className="result-section">
                <h3>Threat Categories</h3>
                <div className="categories-list">
                  {result.threat_categories.map((category, idx) => (
                    <span key={idx} className="category-tag">
                      {category}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {result.triggered_rules && result.triggered_rules.length > 0 && (
              <div className="result-section">
                <h3>Triggered Rules</h3>
                <ul className="rules-list">
                  {result.triggered_rules.map((rule, idx) => (
                    <li key={idx}>{rule}</li>
                  ))}
                </ul>
              </div>
            )}

            {result.threat_narrative && (
              <div className="result-section narrative-section">
                <h3>Threat Narrative</h3>
                <p className="narrative-text">{result.threat_narrative}</p>
              </div>
            )}

            {result.raw_data && Object.keys(result.raw_data).length > 0 && (
              <div className="result-section">
                <details className="raw-data-details">
                  <summary>Raw Data (Click to expand)</summary>
                  <pre className="raw-data">{JSON.stringify(result.raw_data, null, 2)}</pre>
                </details>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default IPAnalyzer

