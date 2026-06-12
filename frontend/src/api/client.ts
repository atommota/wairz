import axios from 'axios'

import { getAccessToken, login } from '@/auth/userManager'

const apiClient = axios.create({
  baseURL: '/api/v1',
})

// Attach the OIDC access token when auth is enabled (no-op otherwise — local
// dev has no UserManager, so getAccessToken() returns null).
apiClient.interceptors.request.use(async (config) => {
  const token = await getAccessToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Session expired / rejected by the API → bounce back through login.
    if (error.response?.status === 401) {
      void login()
    }
    const message =
      error.response?.data?.detail ?? error.message ?? 'An error occurred'
    console.error('[API Error]', message)
    return Promise.reject(error)
  },
)

export default apiClient
