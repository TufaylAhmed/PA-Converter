import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

const STORAGE_KEY = 'pa-converter-wave2-settings'

export type AppSettings = {
  expeditionBaseUrl: string
  httpsPort: string
  httpPort: string
}

export const DEFAULT_SETTINGS: AppSettings = {
  expeditionBaseUrl: 'https://localhost:18443',
  httpsPort: '18443',
  httpPort: '18080',
}

/** Classic Expedition ExtJS entry points */
export const EXPEDITION_PATHS = {
  home: '/',
  login: '/',
  projects: '/',
  devices: '/',
  ml: '/',
} as const

export function normalizeBaseUrl(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, '')
  if (!trimmed) return DEFAULT_SETTINGS.expeditionBaseUrl
  try {
    const u = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`)
    return `${u.protocol}//${u.host}`
  } catch {
    return DEFAULT_SETTINGS.expeditionBaseUrl
  }
}

function persist(settings: AppSettings) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
}

function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...DEFAULT_SETTINGS }
    const parsed = JSON.parse(raw) as Partial<AppSettings>
    const expeditionBaseUrl = normalizeBaseUrl(
      parsed.expeditionBaseUrl || DEFAULT_SETTINGS.expeditionBaseUrl,
    )
    let httpsPort = parsed.httpsPort || DEFAULT_SETTINGS.httpsPort
    try {
      const u = new URL(expeditionBaseUrl)
      if (u.port) httpsPort = u.port
    } catch {
      /* keep */
    }
    return {
      expeditionBaseUrl,
      httpsPort,
      httpPort: parsed.httpPort || DEFAULT_SETTINGS.httpPort,
    }
  } catch {
    return { ...DEFAULT_SETTINGS }
  }
}

export function mergeSettings(
  prev: AppSettings,
  next: Partial<AppSettings>,
): AppSettings {
  const merged: AppSettings = {
    ...prev,
    ...next,
    expeditionBaseUrl: normalizeBaseUrl(
      next.expeditionBaseUrl ?? prev.expeditionBaseUrl,
    ),
    httpsPort: (next.httpsPort ?? prev.httpsPort).trim() || prev.httpsPort,
    httpPort: (next.httpPort ?? prev.httpPort).trim() || prev.httpPort,
  }
  try {
    const u = new URL(merged.expeditionBaseUrl)
    if (next.expeditionBaseUrl != null && u.port) {
      merged.httpsPort = u.port
    } else if (next.httpsPort) {
      u.protocol = 'https:'
      u.port = merged.httpsPort
      merged.expeditionBaseUrl = `${u.protocol}//${u.host}`
    }
  } catch {
    /* keep */
  }
  return merged
}

export function httpProbeUrl(settings: AppSettings): string {
  try {
    const u = new URL(settings.expeditionBaseUrl)
    return `http://${u.hostname}:${settings.httpPort}/`
  } catch {
    return `http://localhost:${settings.httpPort}/`
  }
}

type SettingsContextValue = {
  settings: AppSettings
  save: (next: Partial<AppSettings>) => AppSettings
  expeditionUrl: (path?: string) => string
  openExpedition: (path?: string) => void
  httpProbeUrl: string
  defaults: AppSettings
}

const SettingsContext = createContext<SettingsContextValue | null>(null)

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => loadSettings())
  const settingsRef = useRef(settings)
  settingsRef.current = settings

  const save = useCallback((next: Partial<AppSettings>) => {
    const result = mergeSettings(settingsRef.current, next)
    settingsRef.current = result
    persist(result)
    setSettings(result)
    return result
  }, [])

  const expeditionUrl = useCallback(
    (path = '/') => {
      const base = settings.expeditionBaseUrl.replace(/\/+$/, '')
      const p = path.startsWith('/') ? path : `/${path}`
      return p === '/' ? `${base}/` : `${base}${p}`
    },
    [settings.expeditionBaseUrl],
  )

  const openExpedition = useCallback(
    (path = '/') => {
      window.open(expeditionUrl(path), '_blank', 'noopener,noreferrer')
    },
    [expeditionUrl],
  )

  const probe = useMemo(() => httpProbeUrl(settings), [settings])

  const value = useMemo(
    () => ({
      settings,
      save,
      expeditionUrl,
      openExpedition,
      httpProbeUrl: probe,
      defaults: DEFAULT_SETTINGS,
    }),
    [settings, save, expeditionUrl, openExpedition, probe],
  )

  return (
    <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
  )
}

export function useSettings() {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider')
  return ctx
}
