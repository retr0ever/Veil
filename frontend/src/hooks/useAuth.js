import { useState, useEffect } from 'react'

export function useAuth() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/auth/me')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setUser(data || null))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  const logout = () => {
    window.location.href = '/auth/logout'
  }

  return { user, loading, logout }
}
