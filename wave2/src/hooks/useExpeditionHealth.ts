import { useCallback, useEffect, useState } from 'react'
import { useSettings } from '../config/settings'

export type HealthState = 'checking' | 'online' | 'offline'

/**
 * Probes the HTTP port (default :18080) to avoid self-signed HTTPS cert failures
 * in the browser. Classic UI still opens on the configured HTTPS base URL.
 */
export function useExpeditionHealth() {
  const { httpProbeUrl, expeditionUrl, settings } = useSettings()
  const [state, setState] = useState<HealthState>('checking')
  const [detail, setDetail] = useState('Checking Expedition…')

  const refresh = useCallback(async () => {
    setState('checking')
    setDetail('Checking Expedition…')
    try {
      const ctrl = new AbortController()
      const timer = window.setTimeout(() => ctrl.abort(), 4000)
      const res = await fetch(httpProbeUrl, {
        method: 'GET',
        mode: 'no-cors',
        signal: ctrl.signal,
        cache: 'no-store',
      })
      window.clearTimeout(timer)
      // Opaque success means TCP/HTTP reached the stack
      if (res.type === 'opaque' || res.ok || res.status === 0) {
        setState('online')
        setDetail(`Reachable via ${httpProbeUrl} · UI ${expeditionUrl('/')}`)
      } else {
        setState('offline')
        setDetail(`Unexpected response from ${httpProbeUrl}`)
      }
    } catch {
      setState('offline')
      setDetail(
        `Cannot reach ${httpProbeUrl} (HTTPS UI: ${settings.expeditionBaseUrl})`,
      )
    }
  }, [httpProbeUrl, expeditionUrl, settings.expeditionBaseUrl])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      await refresh()
      if (cancelled) return
    })()
    return () => {
      cancelled = true
    }
  }, [refresh])

  return { state, detail, refresh }
}
