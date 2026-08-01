const API_URL = import.meta.env.VITE_API_URL || '/api'
const API_KEY = import.meta.env.VITE_API_KEY || ''

export function getApiUrl() {
  return API_URL
}

export function getApiHeaders(extra = {}) {
  const headers = { 'Content-Type': 'application/json', ...extra }
  if (API_KEY) headers['X-API-Key'] = API_KEY
  return headers
}

export async function apiFetch(path, options = {}) {
  const opts = {
    ...options,
    headers: getApiHeaders(options.headers || {}),
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
