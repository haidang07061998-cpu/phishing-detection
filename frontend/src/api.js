const API_URL = import.meta.env.VITE_API_URL || '/api'
// VITE_API_KEY is baked into the JS bundle, so it MUST be a low-privilege
// registry key (scopes: scan + feedback + reports). NEVER put a
// PHISHGUARD_API_KEYS env key or an 'admin'-scoped key here — anyone can read it.
const API_KEY = import.meta.env.VITE_API_KEY || ''

export function getApiUrl() {
  return API_URL
}

// Pass a runtime admin key (held in memory only, never bundled) for privileged
// calls; falls back to VITE_API_KEY when no override is given.
export function getApiHeaders(extra = {}, apiKey = '') {
  const headers = { 'Content-Type': 'application/json', ...extra }
  const key = apiKey || API_KEY
  if (key) headers['X-API-Key'] = key
  return headers
}

export async function apiFetch(path, options = {}, apiKey = '') {
  const opts = {
    ...options,
    headers: getApiHeaders(options.headers || {}, apiKey),
  }
  const res = await fetch(`${API_URL}${path}`, opts)
  let data = null
  try { data = await res.json() } catch (e) { /* non-JSON response */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || `Server error (${res.status})`)
    err.status = res.status
    throw err
  }
  return data
}

export function friendlyError(err) {
  const status = err && err.status
  if (status === 413) return 'The file or request is too large (max 2 MB).'
  if (status === 401) return 'Authentication failed. Check your API key.'
  if (status === 429) return 'Too many requests. Please wait a moment and try again.'
  if (status === 500) return 'The server encountered an error. Please try again later.'
  if (status && status >= 400) {
    const msg = (err && err.message) || 'The request was rejected.'
    return msg.replace(/^Server error \(\d+\)/, 'The request could not be completed')
  }
  if (err && err.message && /failed to fetch|networkerror|load failed/i.test(err.message)) {
    return 'Could not reach the server. Is the backend running?'
  }
  return (err && err.message) || 'Something went wrong.'
}
