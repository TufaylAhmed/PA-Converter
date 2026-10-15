import { createContext, useContext, type ReactNode } from 'react'
import type { NavId } from '../nav'

type NavContextValue = {
  active: NavId
  navigate: (id: NavId) => void
}

const NavContext = createContext<NavContextValue | null>(null)

export function NavProvider({
  active,
  navigate,
  children,
}: NavContextValue & { children: ReactNode }) {
  return (
    <NavContext.Provider value={{ active, navigate }}>{children}</NavContext.Provider>
  )
}

export function useNav() {
  const ctx = useContext(NavContext)
  if (!ctx) throw new Error('useNav must be used within NavProvider')
  return ctx
}
