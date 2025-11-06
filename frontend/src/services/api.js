import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

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

export default api

