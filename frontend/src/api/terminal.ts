import { getAccessToken } from '@/auth/userManager'

// Browsers can't set Authorization headers on a WebSocket handshake, so when
// auth is enabled the access token is passed as a query param the backend
// validates before accepting the connection. No-op when auth is disabled
// (getAccessToken() returns null).
export async function buildTerminalWebSocketURL(projectId: string): Promise<string> {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  let url = `${proto}//${host}/api/v1/projects/${projectId}/terminal/ws`
  const token = await getAccessToken()
  if (token) {
    url += `?access_token=${encodeURIComponent(token)}`
  }
  return url
}
