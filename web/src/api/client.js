// The custom header makes every state-changing request a non-simple cross-origin request, which the server never
// authorises; the server also requires it. Same-origin only: there is no CORS and no configurable base URL.
const HEADERS = { 'X-SafeRun-Request': '1' }

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function failure(r) {
  try {
    const j = await r.json()
    return new ApiError(r.status, String(j?.error?.code ?? 'error'), String(j?.error?.message ?? r.statusText))
  } catch {
    return new ApiError(r.status, 'error', r.statusText || 'request failed')
  }
}

export async function getHealth(signal) {
  try {
    const r = await fetch('/api/health', { signal })
    return r.ok ? await r.json() : null
  } catch { return null }
}

export async function startScan(file, osv, signal) {
  const r = await fetch(`/api/scans?osv=${osv}`, { method: 'POST', body: file, signal, headers: { ...HEADERS, 'Content-Type': 'application/zip' } })
  if (!r.ok) throw await failure(r)
  return await r.json()
}

export async function getScan(id, signal) {
  const r = await fetch(`/api/scans/${encodeURIComponent(id)}`, { signal })
  if (!r.ok) throw await failure(r)
  return await r.json()
}

export async function deleteScan(id) {
  await fetch(`/api/scans/${encodeURIComponent(id)}`, { method: 'DELETE', headers: HEADERS }).catch(() => undefined)
}
