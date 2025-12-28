import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://threat-intelligence-correlation-engine-3gnf.onrender.com'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const healthCheck = async () => {
  try {
    const response = await api.get('/api/health')
    return response.data
  } catch (error) {
    throw new Error(`Health check failed: ${error.message}`)
  }
}

export const analyzeIP = async (ipAddress) => {
  try {
    const response = await api.post('/api/v1/analyze', {
      ip_address: ipAddress,
    })
    return response.data
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data.detail || 'Analysis failed')
    }
    throw new Error(`Network error: ${error.message}`)
  }
}

export const downloadAnalysis = async (ipAddress) => {
  try {
    const response = await api.post(
      '/api/v1/analyze/export',
      { ip_address: ipAddress },
      { responseType: 'blob' }
    )

    const disposition = response.headers['content-disposition'] || ''
    const filenameMatch = disposition.match(/filename="?([^";]+)"?/i)
    const filename = filenameMatch ? filenameMatch[1] : `${ipAddress}_analysis.json`

    return { blob: response.data, filename }
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data.detail || 'Download failed')
    }
    throw new Error(`Network error: ${error.message}`)
  }
}

export const fetchRecentReports = async (limit = 50) => {
  try {
    const response = await api.get('/api/v1/reports/recent', {
      params: { limit },
    })
    return response.data
  } catch (error) {
    throw new Error(`Failed to load recent reports: ${error.message}`)
  }
}

export const fetchReportStats = async (hours = 24) => {
  try {
    const response = await api.get('/api/v1/reports/stats', {
      params: { hours },
    })
    return response.data
  } catch (error) {
    throw new Error(`Failed to load report stats: ${error.message}`)
  }
}

export default api

