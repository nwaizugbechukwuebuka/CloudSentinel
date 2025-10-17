import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Scan API
export const scanAPI = {
  startScan: (scanData) => api.post('/scan/start', scanData),
  getScanResults: (scanId, params = {}) => api.get(`/scan/results/${scanId}`, { params }),
  getScanSummary: (scanId) => api.get(`/scan/summary/${scanId}`),
  getScanHistory: (params = {}) => api.get('/scan/history', { params }),
  getScanStats: () => api.get('/scan/stats'),
  getSupportedProviders: () => api.get('/scan/providers'),
}

// Alert API
export const alertAPI = {
  getAlerts: (params = {}) => api.get('/alerts', { params }),
  getAlert: (alertId) => api.get(`/alerts/${alertId}`),
  updateAlert: (alertId, data) => api.put(`/alerts/${alertId}`, data),
  acknowledgeAlert: (alertId) => api.post(`/alerts/${alertId}/acknowledge`),
  resolveAlert: (alertId) => api.post(`/alerts/${alertId}/resolve`),
  getAlertStats: () => api.get('/alerts/stats/summary'),
}

// Report API
export const reportAPI = {
  generateReport: (reportData) => api.post('/reports/generate', reportData),
  exportReport: (reportType, params = {}) => api.get(`/reports/export/${reportType}`, { 
    params,
    responseType: 'blob'
  }),
  getDashboardSummary: () => api.get('/reports/dashboard/summary'),
}

// Auth API
export const authAPI = {
  login: (credentials) => api.post('/auth/token', credentials),
  register: (userData) => api.post('/auth/register', userData),
  getMe: () => api.get('/auth/me'),
  validateToken: () => api.get('/auth/validate'),
  changePassword: (passwordData) => api.put('/auth/me/password', passwordData),
  logout: () => api.post('/auth/logout'),
}

export default api
