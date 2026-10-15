import { useEffect, useState, type FormEvent } from 'react'
import {
  EXPEDITION_PATHS,
  normalizeBaseUrl,
  useSettings,
} from '../config/settings'
import { useNav } from '../nav/NavContext'
import { useExpeditionHealth } from '../hooks/useExpeditionHealth'

export function DashboardPage() {
  const { navigate } = useNav()
  const { openExpedition, expeditionUrl, settings } = useSettings()
  const { state, detail } = useExpeditionHealth()

  return (
    <>
      <div className="grid-3" style={{ marginBottom: 16 }}>
        <div className="stat" data-testid="stat-projects">
          <div className="label">Active projects</div>
          <div className="value">3</div>
          <div className="hint">1 migration in progress</div>
        </div>
        <div className="stat" data-testid="stat-imports">
          <div className="label">Imports this week</div>
          <div className="value">12</div>
          <div className="hint">Palo Alto · Fortinet · Cisco</div>
        </div>
        <div className="stat" data-testid="stat-ml">
          <div className="label">ML / stack</div>
          <div className="value" style={{ fontSize: 22 }}>
            {state === 'checking' ? '…' : state === 'online' ? 'OK' : 'Down'}
          </div>
          <div className="hint">{detail}</div>
        </div>
      </div>

      <h2 className="panel-title">Continue where you left off</h2>
      <p className="panel-copy">
        Open a project, import a vendor config, or launch the classic Expedition
        UI at{' '}
        <a
          className="inline-link"
          href={expeditionUrl(EXPEDITION_PATHS.home)}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="dashboard-expedition-link"
        >
          {settings.expeditionBaseUrl}
        </a>
        .
      </p>
      <div className="actions">
        <button
          type="button"
          className="btn btn-primary"
          data-testid="cta-new-import"
          onClick={() => navigate('import')}
        >
          New import
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          data-testid="cta-open-expedition"
          onClick={() => openExpedition(EXPEDITION_PATHS.home)}
        >
          Open Expedition UI
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          data-testid="cta-open-projects"
          onClick={() => navigate('projects')}
        >
          View projects
        </button>
      </div>
    </>
  )
}

export function ImportPage() {
  const { openExpedition, expeditionUrl } = useSettings()
  const [vendor, setVendor] = useState('paloalto')
  const [project, setProject] = useState('test')
  const [note, setNote] = useState('')

  return (
    <>
      <h2 className="panel-title">Import configuration</h2>
      <p className="panel-copy">
        Upload a vendor config into an Expedition project. Parsing runs in the
        Dockerized backend. For the full ExtJS importer, use{' '}
        <a
          className="inline-link"
          href={expeditionUrl('/')}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="import-expedition-link"
        >
          classic Expedition
        </a>
        .
      </p>
      <div className="field">
        <label htmlFor="vendor">Vendor</label>
        <select
          id="vendor"
          data-testid="import-vendor"
          value={vendor}
          onChange={(e) => setVendor(e.target.value)}
        >
          <option value="paloalto">Palo Alto Networks</option>
          <option value="fortinet">Fortinet</option>
          <option value="cisco">Cisco ASA / FTD</option>
          <option value="checkpoint">Check Point</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="project">Project</label>
        <select
          id="project"
          data-testid="import-project"
          value={project}
          onChange={(e) => setProject(e.target.value)}
        >
          <option value="test">Test</option>
          <option value="prod-cutover">Prod cutover</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="file">Config file</label>
        <input id="file" type="file" data-testid="import-file" />
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn btn-primary"
          data-testid="cta-start-import"
          onClick={() => {
            setNote(
              `Wave 2 will POST ${vendor} → project “${project}” in a later slice. Opening classic UI for now.`,
            )
            openExpedition(EXPEDITION_PATHS.home)
          }}
        >
          Start import
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          data-testid="cta-import-classic"
          onClick={() => openExpedition(EXPEDITION_PATHS.home)}
        >
          Open classic importer
        </button>
      </div>
      {note ? (
        <p className="form-note" data-testid="import-note" role="status">
          {note}
        </p>
      ) : null}
    </>
  )
}

export function ProjectsPage() {
  const { openExpedition, expeditionUrl } = useSettings()
  const rows = [
    { name: 'Test', status: 'Ready', updated: 'Today' },
    { name: 'Prod cutover', status: 'Importing', updated: '2h ago' },
    { name: 'Lab Fortinet', status: 'Ready', updated: 'Yesterday' },
  ]
  return (
    <>
      <h2 className="panel-title">Projects</h2>
      <p className="panel-copy">
        Each project maps to an Expedition workspace. Manage them in{' '}
        <a
          className="inline-link"
          href={expeditionUrl(EXPEDITION_PATHS.projects)}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="projects-expedition-link"
        >
          Expedition
        </a>
        .
      </p>
      <div className="list">
        {rows.map((r) => (
          <div className="list-row" key={r.name} data-testid={`project-row-${r.name}`}>
            <div>
              <strong>{r.name}</strong>
              <div style={{ color: 'var(--text-tertiary)', fontSize: 12, marginTop: 2 }}>
                Updated {r.updated}
              </div>
            </div>
            <div className="row-actions">
              <span className="badge">{r.status}</span>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => openExpedition(EXPEDITION_PATHS.projects)}
              >
                Open
              </button>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

export function DevicesPage() {
  const { openExpedition, expeditionUrl } = useSettings()
  return (
    <>
      <h2 className="panel-title">Devices</h2>
      <p className="panel-copy">
        Connect firewalls and Panorama for config retrieval and push workflows.
        Device inventory lives in the classic UI at{' '}
        <a
          className="inline-link"
          href={expeditionUrl(EXPEDITION_PATHS.devices)}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="devices-expedition-link"
        >
          {expeditionUrl(EXPEDITION_PATHS.devices)}
        </a>
        .
      </p>
      <div className="list">
        <div className="list-row">
          <strong>No devices yet</strong>
          <button
            type="button"
            className="btn btn-ghost"
            data-testid="cta-add-device"
            onClick={() => openExpedition(EXPEDITION_PATHS.devices)}
          >
            Add device
          </button>
        </div>
      </div>
    </>
  )
}

export function MLPage() {
  const { openExpedition, expeditionUrl, httpProbeUrl } = useSettings()
  const { state, detail, refresh } = useExpeditionHealth()

  return (
    <>
      <h2 className="panel-title">Machine learning</h2>
      <p className="panel-copy">
        Spark jobs for log enrichment, rule learning, and discovery. Requires the
        Expedition web container with Spark runtime. Health probe:{' '}
        <code className="mono">{httpProbeUrl}</code>
      </p>
      <div className="grid-2">
        <div className="stat" data-testid="ml-agent-stat">
          <div className="label">Stack probe</div>
          <div className="value" style={{ fontSize: 22 }}>
            {state === 'checking' ? 'Checking…' : state === 'online' ? 'Online' : 'Offline'}
          </div>
          <div className="hint">{detail}</div>
        </div>
        <div className="stat">
          <div className="label">Parquet / data path</div>
          <div className="value" style={{ fontSize: 22 }}>
            /data
          </div>
          <div className="hint">Inside the web container</div>
        </div>
      </div>
      <div className="actions" style={{ marginTop: 16 }}>
        <button
          type="button"
          className="btn btn-primary"
          data-testid="cta-refresh-ml"
          onClick={() => void refresh()}
        >
          Refresh health
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          data-testid="cta-open-ml-ui"
          onClick={() => openExpedition(EXPEDITION_PATHS.ml)}
        >
          Open Expedition ML
        </button>
        <a
          className="btn btn-ghost"
          href={expeditionUrl(EXPEDITION_PATHS.ml)}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="ml-expedition-link"
        >
          Direct link
        </a>
      </div>
    </>
  )
}

export function SettingsPage() {
  const { settings, save, defaults, openExpedition } = useSettings()
  const [baseUrl, setBaseUrl] = useState(settings.expeditionBaseUrl)
  const [httpsPort, setHttpsPort] = useState(settings.httpsPort)
  const [httpPort, setHttpPort] = useState(settings.httpPort)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setBaseUrl(settings.expeditionBaseUrl)
    setHttpsPort(settings.httpsPort)
    setHttpPort(settings.httpPort)
  }, [settings.expeditionBaseUrl, settings.httpsPort, settings.httpPort])

  const previewUrl = `${normalizeBaseUrl(baseUrl)}/`

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    const next = save({
      expeditionBaseUrl: normalizeBaseUrl(baseUrl),
      httpsPort,
      httpPort,
    })
    setBaseUrl(next.expeditionBaseUrl)
    setHttpsPort(next.httpsPort)
    setHttpPort(next.httpPort)
    setSaved(true)
    window.setTimeout(() => setSaved(false), 2200)
  }

  function resetDefaults() {
    const next = save({ ...defaults })
    setBaseUrl(next.expeditionBaseUrl)
    setHttpsPort(next.httpsPort)
    setHttpPort(next.httpPort)
    setSaved(true)
    window.setTimeout(() => setSaved(false), 2200)
  }

  return (
    <>
      <h2 className="panel-title">Settings</h2>
      <p className="panel-copy">
        Theme follows the control in the left sidebar. These URLs control where
        Wave 2 opens classic Expedition (defaults match Docker Compose ports).
      </p>
      <form onSubmit={onSubmit} data-testid="settings-form">
        <div className="field">
          <label htmlFor="api">Expedition base URL (HTTPS)</label>
          <input
            id="api"
            data-testid="settings-base-url"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={defaults.expeditionBaseUrl}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="grid-2">
          <div className="field">
            <label htmlFor="https-port">HTTPS port</label>
            <input
              id="https-port"
              data-testid="settings-https-port"
              value={httpsPort}
              onChange={(e) => setHttpsPort(e.target.value)}
              inputMode="numeric"
            />
          </div>
          <div className="field">
            <label htmlFor="http-port">HTTP probe port</label>
            <input
              id="http-port"
              data-testid="settings-http-port"
              value={httpPort}
              onChange={(e) => setHttpPort(e.target.value)}
              inputMode="numeric"
            />
          </div>
        </div>
        <p className="panel-copy" style={{ marginTop: -4 }}>
          Preview:{' '}
          <a
            className="inline-link"
            href={previewUrl}
            target="_blank"
            rel="noopener noreferrer"
            data-testid="settings-preview-link"
          >
            {previewUrl}
          </a>
        </p>
        <div className="actions">
          <button type="submit" className="btn btn-primary" data-testid="cta-save-settings">
            Save
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            data-testid="cta-reset-settings"
            onClick={resetDefaults}
          >
            Reset defaults
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            data-testid="cta-test-open"
            onClick={() => openExpedition('/')}
          >
            Test open UI
          </button>
        </div>
        {saved ? (
          <p className="form-note success" data-testid="settings-saved" role="status">
            Settings saved to this browser.
          </p>
        ) : null}
      </form>
    </>
  )
}
