import { useState, type ReactElement } from 'react'
import { Sidebar } from './components/Sidebar'
import { PAGE_META, type NavId } from './nav'
import { NavProvider } from './nav/NavContext'
import { useExpeditionHealth } from './hooks/useExpeditionHealth'
import { useSettings } from './config/settings'
import {
  DashboardPage,
  ImportPage,
  ProjectsPage,
  DevicesPage,
  MLPage,
  SettingsPage,
} from './views/pages'
import './styles/global.css'

const PAGES: Record<NavId, () => ReactElement> = {
  dashboard: DashboardPage,
  import: ImportPage,
  projects: ProjectsPage,
  devices: DevicesPage,
  ml: MLPage,
  settings: SettingsPage,
}

function HealthPill() {
  const { state, detail } = useExpeditionHealth()
  const { settings } = useSettings()
  return (
    <div
      className={`health-pill health-${state}`}
      data-testid="health-status"
      title={detail}
    >
      <span className="health-label">
        <span className="health-dot" aria-hidden />
        {state === 'checking'
          ? 'Checking…'
          : state === 'online'
            ? 'Expedition online'
            : 'Expedition offline'}
      </span>
      <span className="health-url">{settings.expeditionBaseUrl}</span>
    </div>
  )
}

export default function App() {
  const [active, setActive] = useState<NavId>('dashboard')
  const meta = PAGE_META[active]
  const Page = PAGES[active]

  return (
    <NavProvider active={active} navigate={setActive}>
      <div className="app-shell" data-testid="app-shell">
        <div className="ambient" aria-hidden />
        <Sidebar active={active} onSelect={setActive} />
        <main className="main">
          <header className="topbar">
            <div>
              <h1 data-testid="page-title">{meta.title}</h1>
              <p data-testid="page-subtitle">{meta.subtitle}</p>
            </div>
            <HealthPill />
          </header>
          <section className="glass content" key={active} data-testid={`page-${active}`}>
            <Page />
          </section>
        </main>
      </div>
    </NavProvider>
  )
}
