export type NavId =
  | 'dashboard'
  | 'import'
  | 'projects'
  | 'devices'
  | 'ml'
  | 'settings'

export type NavItem = {
  id: NavId
  label: string
  section?: string
}

export const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', section: 'Workspace' },
  { id: 'import', label: 'Import configs' },
  { id: 'projects', label: 'Projects' },
  { id: 'devices', label: 'Devices', section: 'Operations' },
  { id: 'ml', label: 'Machine learning' },
  { id: 'settings', label: 'Settings', section: 'System' },
]

export const PAGE_META: Record<
  NavId,
  { title: string; subtitle: string }
> = {
  dashboard: {
    title: 'Dashboard',
    subtitle: 'Convert, import, and optimize firewall policy in one place.',
  },
  import: {
    title: 'Import',
    subtitle: 'Bring vendor configs into Expedition projects.',
  },
  projects: {
    title: 'Projects',
    subtitle: 'Organize migrations and conversion workstreams.',
  },
  devices: {
    title: 'Devices',
    subtitle: 'Track managed firewalls and Panorama connections.',
  },
  ml: {
    title: 'Machine learning',
    subtitle: 'Spark-assisted discovery, enrichment, and analytics.',
  },
  settings: {
    title: 'Settings',
    subtitle: 'Appearance, runtime, and Expedition connectivity.',
  },
}
