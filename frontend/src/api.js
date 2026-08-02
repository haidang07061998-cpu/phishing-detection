const API_URL = import.meta.env.VITE_API_URL || '/api'
// VITE_API_KEY is baked into the JS bundle, so it MUST be a low-privilege
// registry key (scopes: scan + feedback only). NEVER put a PHISHGUARD_API_KEYS
// env key, an 'admin'-scoped key, or a 'reports'-scoped key here — anyone can
// read it. Reports require a runtime-entered reports/admin key (see ReportsPanel).
const API_KEY = import.meta.env.VITE_API_KEY || ''

// Default timeout for scan requests. DNS/SSL extraction can take several
// seconds; 90s is generous yet still fails fast on a hung server.
const DEFAULT_TIMEOUT_MS = 90000

export function getApiUrl() {
  return API_URL
}

// Pass a runtime admin/reports key (held in memory only, never bundled) for
// privileged calls; falls back to VITE_API_KEY when no override is given.
export function getApiHeaders(extra = {}, apiKey = '') {
  const headers = { 'Content-Type': 'application/json', ...extra }
  const key = apiKey || API_KEY
  if (key) headers['X-API-Key'] = key
  return headers
}

export async function apiFetch(path, options = {}, apiKey = '', timeoutMs = DEFAULT_TIMEOUT_MS) {
  // Support both an external AbortController (for cancel) and an internal
  // timeout. Whichever fires first aborts the underlying fetch.
  const externalSignal = options.signal || null
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const onExternalAbort = () => controller.abort()
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort()
    else externalSignal.addEventListener('abort', onExternalAbort, { once: true })
  }

  const opts = {
    ...options,
    headers: getApiHeaders(options.headers || {}, apiKey),
    signal: controller.signal,
  }
  let res
  try {
    res = await fetch(`${API_URL}${path}`, opts)
  } catch (e) {
    if (e && e.name === 'AbortError') {
      // Distinguish internal timeout from external user cancel.
      const err = new Error('The request timed out.')
      err.status = 408
      err.cancelled = !!(externalSignal && externalSignal.aborted)
      if (err.cancelled) {
        const cancelErr = new Error('Scan cancelled.')
        cancelErr.name = 'AbortError'
        throw cancelErr
      }
      throw err
    }
    throw e
  } finally {
    clearTimeout(timer)
    if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort)
  }
  let data = null
  try { data = await res.json() } catch (e) { /* non-JSON response */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || `Server error (${res.status})`)
    err.status = res.status
    throw err
  }
  return data
}

export function friendlyError(err, t) {
  const L = (key, fallback) => (typeof t === 'function' ? t(key) : fallback)
  if (err && err.name === 'AbortError') {
    return L('error.abort', 'Scan cancelled. Click SCAN again to retry.')
  }
  const status = err && err.status
  if (status === 408) return L('error.timeout', 'The request timed out. The backend may be busy — try again.')
  if (status === 413) return L('error.tooLarge', 'The file or request is too large (max 2 MB).')
  if (status === 401) return L('error.unauthorized', 'Authentication failed. Check your API key.')
  if (status === 403) {
    const msg = (err && err.message) || ''
    return msg || L('error.forbidden', 'You do not have permission for this action. Enter a key with the required scope.')
  }
  if (status === 429) return L('error.rateLimited', 'Too many requests. Please wait a moment and try again.')
  if (status === 500) return L('error.server', 'The server encountered an error. Please try again later.')
  if (status && status >= 400) {
    const msg = (err && err.message) || L('error.rejected', 'The request was rejected.')
    return msg.replace(/^Server error \(\d+\)/, L('error.rejected', 'The request could not be completed'))
  }
  if (err && err.message && /failed to fetch|networkerror|load failed/i.test(err.message)) {
    return L('error.network', 'Could not reach the server. Is the backend running?')
  }
  return (err && err.message) || L('error.generic', 'Something went wrong.')
}
