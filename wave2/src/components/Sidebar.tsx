import { NAV_ITEMS, type NavId } from '../nav'
import { NAV_ICONS, IconMoon, IconSun } from './Icons'
import { BrandMark } from './BrandMark'
import { useTheme } from '../theme/ThemeProvider'
import { EXPEDITION_PATHS, useSettings } from '../config/settings'

type Props = {
  active: NavId
  onSelect: (id: NavId) => void
}

export function Sidebar({ active, onSelect }: Props) {
  const { theme, toggle } = useTheme()
  const { openExpedition, settings } = useSettings()
  let lastSection = ''

  return (
    <aside className="glass sidebar" aria-label="Primary" data-testid="sidebar">
      <div className="brand">
        <BrandMark size={36} className="brand-mark-svg" />
        <div className="brand-text">
          <div className="brand-name" data-testid="brand-name">
            PA-Converter
          </div>
          <div className="brand-sub">Wave 2 · Expedition</div>
        </div>
      </div>

      <nav className="nav">
        {NAV_ITEMS.map((item) => {
          const Icon = NAV_ICONS[item.id]
          const showSection = Boolean(item.section && item.section !== lastSection)
          if (item.section) lastSection = item.section
          return (
            <div key={item.id}>
              {showSection ? <div className="nav-section">{item.section}</div> : null}
              <button
                type="button"
                className={`nav-item${active === item.id ? ' active' : ''}`}
                onClick={() => onSelect(item.id)}
                aria-current={active === item.id ? 'page' : undefined}
                data-testid={`nav-${item.id}`}
              >
                <Icon className="nav-icon" />
                {item.label}
              </button>
            </div>
          )
        })}
      </nav>

      <div className="sidebar-footer">
        <button
          type="button"
          className="classic-link"
          data-testid="sidebar-open-classic"
          onClick={() => openExpedition(EXPEDITION_PATHS.home)}
          title={settings.expeditionBaseUrl}
        >
          Open classic UI ↗
        </button>
        <button
          type="button"
          className="theme-toggle"
          onClick={toggle}
          aria-label="Toggle color theme"
          data-testid="theme-toggle"
        >
          <span>{theme === 'light' ? 'Light' : 'Dark'} mode</span>
          {theme === 'light' ? (
            <IconMoon className="nav-icon" />
          ) : (
            <IconSun className="nav-icon" />
          )}
        </button>
      </div>
    </aside>
  )
}
