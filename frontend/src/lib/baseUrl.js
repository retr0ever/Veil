let _cached = null

export async function getBaseUrl() {
  if (_cached !== null) return _cached
  try {
    const res = await fetch('/api/config')
    if (res.ok) {
      const data = await res.json()
      if (data.base_url) {
        _cached = data.base_url
        return _cached
      }
    }
  } catch {}
  _cached = window.location.origin
  return _cached
}

export function getBaseUrlSync() {
  return _cached || window.location.origin
}

export function proxyUrl(siteId) {
  return `${getBaseUrlSync()}/p/${siteId}`
}
