const STORAGE_KEY = 'veil-project-names'

export function getProjectNames() {
  if (typeof window === 'undefined') return {}
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

export function getProjectName(siteId) {
  return getProjectNames()[siteId] || ''
}

export function setProjectName(siteId, name) {
  if (typeof window === 'undefined' || !siteId || !name) return
  const names = getProjectNames()
  names[siteId] = name
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(names))
}
