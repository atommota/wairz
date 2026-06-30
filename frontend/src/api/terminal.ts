import { getAccessToken } from '@/auth/userManager'

// Browsers can't set Authorization headers on a WebSocket handshake, so when
// auth is enabled the access token is passed as a query param the backend
// validates before accepting the connection. No-op when auth is disabled
// (getAccessToken() returns null).
export async function buildTerminalWebSocketURL(
  projectId: string,
  firmwareId?: string,
): Promise<string> {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const params = new URLSearchParams()
  if (firmwareId) params.set('firmware_id', firmwareId)
  const token = await getAccessToken()
  if (token) params.set('access_token', token)
  const query = params.toString()
  return `${proto}//${host}/api/v1/projects/${projectId}/terminal/ws${query ? `?${query}` : ''}`
}
