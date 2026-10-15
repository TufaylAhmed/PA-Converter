/**
 * PA-Converter UI enhancer — left rails, flat icons, glass layout repair.
 */
(function () {
  var ICON_MAP = {
    dashboard: 'dashboard',
    projects: 'projects',
    devices: 'devices',
    device: 'devices',
    snippets: 'snippets',
    settings: 'settings',
    logs: 'logs',
    help: 'help',
    import: 'import',
    plugins: 'plugins',
    policies: 'policies',
    objects: 'objects',
    monitor: 'monitor',
    'machine learning': 'ml',
    'm. learning': 'ml',
    'best practices': 'policies',
    network: 'network',
    library: 'folder',
    tools: 'tools',
    export: 'export',
    panorama: 'devices',
    interfaces: 'interfaces',
    interface: 'interfaces',
    zones: 'zones',
    zone: 'zones',
    'virtual routers': 'router',
    'virtual router': 'router',
    routers: 'router',
    'virtual wires': 'vwire',
    'virtual wire': 'vwire',
    vlans: 'vlan',
    vlan: 'vlan',
    vpn: 'vpn',
    servers: 'server',
    server: 'server',
    jobs: 'jobs',
    users: 'users',
    user: 'users',
    'prefix suffix replace': 'prefix-suffix',
    'prefix suffix': 'prefix-suffix',
    rename: 'rename',
    'search replace': 'search-replace',
    'custom params': 'settings',
    'user mapping': 'objects',
    security: 'security',
    nat: 'nat',
    'application override': 'app-override',
    qos: 'qos',
    'policy based forwarding': 'pbf',
    decryption: 'decryption',
    'captive portal': 'captive',
    'dos protection': 'dos',
    'virtual systems': 'vsys',
    'virtual system': 'vsys',
    'response pages': 'response-pages',
    'response page': 'response-pages',
    'server profiles': 'server-profiles',
    'server profile': 'server-profiles',
    'snmp trap': 'snmp',
    snmp: 'snmp',
    syslog: 'syslog',
    email: 'email',
    netflow: 'netflow',
    radius: 'radius',
    ldap: 'ldap',
    kerberos: 'kerberos',
  }

  // Only non-clickable section headers — Network/Device/Tools/Export are real tabs
  var SECTION_LABELS = {
    'best practices': 1,
    monitor: 1,
    panorama: 1,
  }

  var BACK_HTML =
    '<button type="button" class="pa-nav-back" data-pa-back="1">' +
    '<span class="pa-nav-back-icon" aria-hidden="true"></span>' +
    '<span>All projects</span></button>'

  function normalizeLabel(text) {
    return (text || '')
      .replace(/\s+/g, ' ')
      .replace(/[^\w.\s-]/g, '')
      .trim()
      .toLowerCase()
  }

  function enhanceTabBar(barEl, opts) {
    opts = opts || {}
    if (!barEl) return
    // Only decorate visible left rails
    var rect = barEl.getBoundingClientRect()
    if (rect.width < 80 || rect.height < 80 || rect.y < -100) return

    barEl.classList.add('pa-side-nav')
    if (opts.project) barEl.classList.add('pa-project-nav')

    // Remove injected Workspace brand card (logo lives on login / content)
    var staleBrand = barEl.querySelectorAll('[data-pa-brand], .pa-nav-brand')
    for (var bi = 0; bi < staleBrand.length; bi++) {
      if (staleBrand[bi].parentNode) staleBrand[bi].parentNode.removeChild(staleBrand[bi])
    }

    if (opts.project && !barEl.querySelector('[data-pa-back]')) {
      var backWrap = document.createElement('div')
      backWrap.innerHTML = BACK_HTML
      var btn = backWrap.firstChild
      btn.addEventListener('click', function (e) {
        e.preventDefault()
        e.stopPropagation()
        try {
          var card = Ext.getCmp('mainpanelcard')
          if (card && card.getLayout) card.getLayout().setActiveItem('MainPanel')
          fixAllLayouts()
        } catch (err) {
          /* ignore */
        }
      })
      barEl.insertBefore(btn, barEl.firstChild)
    }

    applyIcons(barEl)
    hideJunkTabs(barEl)
  }

  function applyIcons(root) {
    var tabs = (root || document).querySelectorAll(
      '.x-tab-bar-left .x-tab, .pa-side-nav .x-tab, .x-tab-bar-top .x-tab, .x-tab-bar-default-horizontal .x-tab',
    )
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i]
      var label = normalizeLabel(tab.textContent).replace(/^[^\w.]+/, '')

      // Section labels only apply to left rails — never horizontal top tabs
      var inLeftRail = !!(
        tab.closest &&
        tab.closest('.x-tab-bar-left, .pa-side-nav')
      )
      if (inLeftRail && SECTION_LABELS[label]) {
        tab.setAttribute('data-pa-section', '1')
        tab.removeAttribute('data-pa-icon')
        continue
      }
      tab.removeAttribute('data-pa-section')

      var key = null
      var bestLen = -1
      for (var name in ICON_MAP) {
        if (label === name || label.indexOf(name) === 0) {
          if (name.length > bestLen) {
            bestLen = name.length
            key = ICON_MAP[name]
          }
        }
      }
      if (key) tab.setAttribute('data-pa-icon', key)

      var glyph = tab.querySelector('.x-tab-glyph, .x-tab-icon-el')
      if (!glyph && key) {
        var btn = tab.querySelector('.x-tab-button, .x-tab-wrap') || tab
        glyph = document.createElement('span')
        glyph.className = 'x-tab-glyph'
        glyph.setAttribute('aria-hidden', 'true')
        btn.insertBefore(glyph, btn.firstChild)
      }
      // Kill legacy FA / iconCls chrome so flat masks show cleanly
      if (key && glyph) {
        glyph.style.setProperty('font-size', '0', 'important')
        glyph.style.setProperty('color', 'transparent', 'important')
        glyph.style.setProperty('background-image', 'none', 'important')
        glyph.style.setProperty('text-indent', '-9999px', 'important')
      }
    }
  }

  function hideJunkTabs(root) {
    var tabs = (root || document).querySelectorAll('.x-tab')
    for (var i = 0; i < tabs.length; i++) {
      var label = normalizeLabel(tabs[i].textContent)
      // Hide Updates + Help (and empty chrome tabs)
      if (label === 'updates' || label === 'help' || label === '') {
        tabs[i].style.setProperty('display', 'none', 'important')
        tabs[i].setAttribute('aria-hidden', 'true')
      }
    }
  }

  function stripPanwChrome(root) {
    root = root || document
    var imgs = root.querySelectorAll(
      'img[src*="panlogo"], img[src*="logo1024"], img[src*="mypanbar"], img[src*="footprint"]',
    )
    for (var j = 0; j < imgs.length; j++) {
      imgs[j].style.display = 'none'
    }
  }

  // Legacy skeuomorphic GIFs/PNGs → flat expedition icons
  var FLAT_OBJECT_ICON = {
    'address.gif': 'address.svg',
    'address.png': 'address.svg',
    'address_group.gif': 'objects.svg',
    'address_groups.gif': 'objects.svg',
    'any_zone.png': 'zones.svg',
    'service.gif': 'service.svg',
    'service.png': 'service.svg',
    'service_group.gif': 'service.svg',
    'services_group.gif': 'service.svg',
    'tag.png': 'snippets.svg',
    'regions.png': 'network.svg',
    'zone.gif': 'zones.svg',
    'zone.png': 'zones.svg',
    'application.gif': 'app-override.svg',
    'application.png': 'app-override.svg',
    'application-override.png': 'app-override.svg',
    'profile_group.gif': 'policies.svg',
    'security.gif': 'security.svg',
    'security.png': 'security.svg',
    'nat.gif': 'nat.svg',
    'nat.png': 'nat.svg',
    'qos.png': 'qos.svg',
    'policy-based-forwarding.png': 'pbf.svg',
    'decryption.png': 'decryption.svg',
    'captive-portal.png': 'captive.svg',
    'dos-protection.png': 'dos.svg',
    'interfaces.png': 'interfaces.svg',
    'interface-mgmt.png': 'interfaces.svg',
    'sub-interface.png': 'interfaces.svg',
    'ipsec-tunnels.png': 'vpn.svg',
    'virtual-routers.gif': 'router.svg',
    'virtual-routers.png': 'router.svg',
    'virtual-wires.png': 'vwire.svg',
    'vlans.png': 'vlan.svg',
    'network.png': 'network.svg',
    'network-profiles.png': 'network.svg',
    'excel.png': 'excel.svg',
    'cloud.png': 'network.svg',
    'device.gif': 'devices.svg',
    'device.png': 'devices.svg',
    'devices.png': 'devices.svg',
    'lock.png': 'lock.svg',
    'checked.gif': 'tick.svg',
    'unchecked.gif': 'unchecked.svg',
    'ok_small.png': 'tick.svg',
    'ok_big.png': 'tick.svg',
    'error_small.png': 'cross.svg',
    'error_big.png': 'cross.svg',
    'allow.gif': 'tick.svg',
    'deny.gif': 'cross.svg',
    'enable.png': 'tick.svg',
    'disable.png': 'cross.svg',
    'delete.png': 'trash.svg',
    'action_delete.png': 'trash.svg',
    'refresh.png': 'refresh.svg',
    'restart.png': 'restart.svg',
    'filter.gif': 'filter.svg',
    'export.png': 'export.svg',
    'import.png': 'import.svg',
    'import.gif': 'import.svg',
    'monitor.png': 'monitor.svg',
    'logs.png': 'logs.svg',
    'puzzle.png': 'plugins.svg',
    'police.png': 'policies.svg',
    'policeman.png': 'policies.svg',
    'pan16.gif': 'security.svg',
    'pan16.png': 'security.svg',
    'response-pages.png': 'response-pages.svg',
    'server-profiles.png': 'server-profiles.svg',
    'email.png': 'email.svg',
    'kerberos.gif': 'kerberos.svg',
    'kerberos.png': 'kerberos.svg',
  }

  var ICON_CLS_FLAT = {
    'icon-security': 'security.svg',
    'icon-securityrule': 'security.svg',
    'icon-nat': 'nat.svg',
    'icon-rulenat': 'nat.svg',
    'icon-app_override': 'app-override.svg',
    'icon-appoverride': 'app-override.svg',
    'icon-qos': 'qos.svg',
    'icon-pbf': 'pbf.svg',
    'icon-decryption': 'decryption.svg',
    'icon-captive_portal': 'captive.svg',
    'icon-dos_protection': 'dos.svg',
    'icon-interfaces': 'interfaces.svg',
    'icon-interface-mgmt': 'interfaces.svg',
    'icon-vr': 'router.svg',
    'icon-vwire': 'vwire.svg',
    'icon-vlans': 'vlan.svg',
    'icon-ipsec-tunnels': 'vpn.svg',
    'icon-network': 'network.svg',
    'icon-zone': 'zones.svg',
    'icon-address': 'address.svg',
    'icon-address_groups': 'objects.svg',
    'icon-applications': 'app-override.svg',
    'icon-applications_groups': 'app-override.svg',
    'icon-services': 'service.svg',
    'icon-service': 'service.svg',
    'icon-services_groups': 'service.svg',
    'icon-device': 'devices.svg',
    'icon-devices': 'devices.svg',
    'icon-user': 'users.svg',
    'icon-users': 'users.svg',
    'icon-lock': 'lock.svg',
    'icon-export': 'export.svg',
    'icon-import': 'import.svg',
    'icon-excel2': 'excel.svg',
    'icon-delete': 'trash.svg',
    'icon-refresh': 'refresh.svg',
    'icon-restart': 'restart.svg',
    'icon-filter': 'filter.svg',
    'icon-monitor': 'monitor.svg',
    'icon-logs': 'logs.svg',
    'icon-plugins': 'plugins.svg',
    'icon-settings': 'settings.svg',
    'icon-config': 'settings.svg',
    'icon-checked': 'tick.svg',
    'icon-check': 'tick.svg',
    'icon-unchecked': 'unchecked.svg',
    'icon-ok': 'tick.svg',
    'icon-error': 'cross.svg',
    'icon-allow': 'tick.svg',
    'icon-deny': 'cross.svg',
    'action-delete': 'trash.svg',
    'action-add': 'import.svg',
    'action-edit': 'settings.svg',
    'icon-response_page': 'response-pages.svg',
    'icon-response-pages': 'response-pages.svg',
    'icon-email': 'email.svg',
    'icon-kerberos': 'kerberos.svg',
  }

  function resolveFlatIcon(file) {
    file = (file || '').toLowerCase()
    var flat = FLAT_OBJECT_ICON[file]
    if (flat) return flat
    if (/virtual[-_]?router/.test(file)) return 'router.svg'
    if (/virtual[-_]?wire/.test(file)) return 'vwire.svg'
    if (/^vlan/.test(file)) return 'vlan.svg'
    if (/^zone|any_zone/.test(file)) return 'zones.svg'
    if (/interface/.test(file)) return 'interfaces.svg'
    if (/vpn|ipsec|tunnel/.test(file)) return 'vpn.svg'
    if (/excel|csv/.test(file)) return 'excel.svg'
    if (/security/.test(file)) return 'security.svg'
    if (/^nat/.test(file)) return 'nat.svg'
    if (/qos/.test(file)) return 'qos.svg'
    if (/pbf|policy-based|forwarding/.test(file)) return 'pbf.svg'
    if (/decrypt/.test(file)) return 'decryption.svg'
    if (/captive/.test(file)) return 'captive.svg'
    if (/dos/.test(file)) return 'dos.svg'
    if (/override|application/.test(file)) return 'app-override.svg'
    if (/lock/.test(file)) return 'lock.svg'
    if (/unchecked/.test(file)) return 'unchecked.svg'
    if (/checked|ok_small|ok_big|enable|allow\.gif/.test(file)) return 'tick.svg'
    if (/error_small|error_big|deny\.gif|disable\.png/.test(file)) return 'cross.svg'
    if (/delete|trash/.test(file)) return 'trash.svg'
    if (/refresh|reload|restart/.test(file)) return 'refresh.svg'
    if (/filter/.test(file)) return 'filter.svg'
    if (/device/.test(file)) return 'devices.svg'
    if (/address/.test(file)) return 'address.svg'
    if (/service/.test(file)) return 'service.svg'
    if (/export/.test(file)) return 'export.svg'
    if (/import/.test(file)) return 'import.svg'
    if (/response[-_]?page/.test(file)) return 'response-pages.svg'
    if (/server[-_]?profile/.test(file)) return 'server-profiles.svg'
    if (/snmp/.test(file)) return 'snmp.svg'
    if (/syslog/.test(file)) return 'syslog.svg'
    if (/email/.test(file)) return 'email.svg'
    if (/netflow/.test(file)) return 'netflow.svg'
    if (/radius/.test(file)) return 'radius.svg'
    if (/ldap/.test(file)) return 'ldap.svg'
    if (/kerberos/.test(file)) return 'kerberos.svg'
    return null
  }

  function applyFlatObjectIcons(root) {
    root = root || document
    var imgs = root.querySelectorAll(
      'img[src*="/resources/images/rules/"], img[src*="/resources/images/icons/"], img[src*="resources/images/rules/"], img[src*="resources/images/icons/"], img[src*="/resources/images/grid/"], img[src*="resources/images/restart"], img[src*="resources/images/shutdown"]',
    )
    for (var i = 0; i < imgs.length; i++) {
      var img = imgs[i]
      var src = img.getAttribute('src') || ''
      var file = src.split('/').pop().split('?')[0].toLowerCase()
      var flat = resolveFlatIcon(file)
      if (!flat) continue
      var next = '/resources/images/expedition/icons/' + flat
      if (img.getAttribute('data-pa-flat') === flat) continue
      img.setAttribute('data-pa-flat', flat)
      img.src = next
      img.classList.add('pa-flat-obj-icon')
      img.style.width = '16px'
      img.style.height = '16px'
      img.style.verticalAlign = 'middle'
    }

    // Ext btnIconEl / icon-el use background-image — rewrite those too
    var iconEls = root.querySelectorAll(
      '[id$="-btnIconEl"], .x-btn-icon-el, .x-tab-icon-el, .x-menu-item-icon, .x-action-col-icon, .x-grid-cell-inner img, [class*="icon-"]',
    )
    for (var j = 0; j < iconEls.length; j++) {
      var el = iconEls[j]
      if (el.tagName === 'IMG') continue
      var cls = el.className || ''
      var mapped = null
      for (var c in ICON_CLS_FLAT) {
        if (cls.indexOf(c) !== -1) {
          mapped = ICON_CLS_FLAT[c]
          break
        }
      }
      if (!mapped) {
        var bg = ''
        try {
          bg = window.getComputedStyle(el).backgroundImage || ''
        } catch (e) {
          bg = el.style.backgroundImage || ''
        }
        var m = bg.match(/\/([^/"')]+\.(?:png|gif|jpg|jpeg|svg))/i)
        if (m) mapped = resolveFlatIcon(m[1])
      }
      if (!mapped) continue
      if (el.getAttribute('data-pa-flat-bg') === mapped) continue
      el.setAttribute('data-pa-flat-bg', mapped)
      el.classList.add('pa-flat-bg-icon')
      el.style.setProperty(
        'background-image',
        'url("/resources/images/expedition/icons/' + mapped + '")',
        'important',
      )
      el.style.setProperty('background-size', '16px 16px', 'important')
      el.style.setProperty('background-repeat', 'no-repeat', 'important')
      el.style.setProperty('background-position', 'center', 'important')
    }
  }

  function enhanceLibraryTiles() {
    // Projects stay as classic rows (tiles reverted)
    var panel = document.getElementById('ProjectsGridPanel')
    if (!panel) return
    panel.classList.remove('pa-projects-tiles')
    panel.classList.add('pa-projects-rows')
    var view = panel.querySelector('.x-grid-view')
    if (view) {
      view.classList.remove('pa-projects-tiles-view')
      view.classList.add('pa-projects-rows-view')
    }
    enhanceAddProjectTool(panel)
  }

  /** Ext header "plus" tool is nearly invisible in light mode — label it Add Project. */
  function enhanceAddProjectTool(panel) {
    panel = panel || document.getElementById('ProjectsGridPanel')
    if (!panel) return
    var tools = panel.querySelectorAll('.x-tool')
    for (var i = 0; i < tools.length; i++) {
      var tool = tools[i]
      var tip = (
        tool.getAttribute('data-qtip') ||
        tool.getAttribute('title') ||
        tool.getAttribute('aria-label') ||
        ''
      ).toLowerCase()
      var isPlus =
        !!tool.querySelector('.x-tool-plus, .x-tool-img.x-tool-plus') ||
        tip.indexOf('add new project') !== -1 ||
        tip === 'add project'
      if (!isPlus) continue
      if (!tool.classList.contains('pa-add-project-btn')) {
        tool.classList.add('pa-add-project-btn')
      }
      tool.setAttribute('aria-label', 'Add Project')
      tool.setAttribute('data-qtip', 'Add Project')
      tool.setAttribute('title', 'Add Project')
      if (!tool.querySelector('.pa-add-project-label')) {
        var label = document.createElement('span')
        label.className = 'pa-add-project-label'
        label.textContent = 'Add Project'
        tool.appendChild(label)
      }
    }
  }

  function polishDashboardWidgets() {
    var headers = document.querySelectorAll('.x-panel-header-title-default, .x-title-text-default')
    for (var i = 0; i < headers.length; i++) {
      var t = (headers[i].textContent || '').trim().toLowerCase()
      var panel = headers[i].closest('.x-panel')
      if (!panel) continue
      if (t.indexOf('ml health') !== -1) panel.classList.add('pa-ml-health')
      if (t.indexOf('jobs') !== -1) panel.classList.add('pa-jobs-panel')
      if (t === 'library') panel.classList.add('pa-library-panel')
    }
  }

  // Vendor import tabs → official company logos
  var VENDOR_TAB_LOGO = [
    { match: /^palo\s*alto/, src: '/resources/images/vendors/panp.png', cls: 'pa-vendor-pan' },
    { match: /^csv$/, src: '/resources/images/expedition/icons/excel.svg', cls: 'pa-vendor-csv' },
    { match: /^checkpoint/, src: '/resources/images/vendors/checkpointp.png', cls: 'pa-vendor-checkpoint' },
    { match: /^cisco/, src: '/resources/images/vendors/cisco2.gif', cls: 'pa-vendor-cisco' },
    { match: /^fortinet/, src: '/resources/images/vendors/fortinetp.png', cls: 'pa-vendor-fortinet' },
    { match: /^ibm|xgs/, src: '/resources/images/vendors/ibmp.png', cls: 'pa-vendor-ibm' },
    { match: /^juniper/, src: '/resources/images/vendors/juniperp.png', cls: 'pa-vendor-juniper' },
    { match: /^forcepoint/, src: '/resources/images/vendors/forcepointp.png', cls: 'pa-vendor-forcepoint' },
    { match: /^stonesoft/, src: '/resources/images/vendors/stonesoft.png', cls: 'pa-vendor-stonesoft' },
    { match: /^sidewinder/, src: '/resources/images/vendors/sidewinder.jpg', cls: 'pa-vendor-sidewinder' },
  ]

  var PROFILE_BTN_ICON = {
    'snmp trap': 'snmp.svg',
    snmp: 'snmp.svg',
    syslog: 'syslog.svg',
    email: 'email.svg',
    netflow: 'netflow.svg',
    radius: 'radius.svg',
    ldap: 'ldap.svg',
    kerberos: 'kerberos.svg',
  }

  function enhanceProfileToolbarButtons(root) {
    root = root || document
    var btns = root.querySelectorAll('.x-toolbar .x-btn, .x-btn')
    for (var i = 0; i < btns.length; i++) {
      var btn = btns[i]
      var label = normalizeLabel(btn.textContent)
      var flat = null
      for (var key in PROFILE_BTN_ICON) {
        if (label === key || label.indexOf(key) === 0) {
          flat = PROFILE_BTN_ICON[key]
          break
        }
      }
      if (!flat) continue
      // Only touch profile-style toggle pills (short labels)
      if (label.length > 24) continue
      var iconEl =
        btn.querySelector('.x-btn-icon-el') ||
        btn.querySelector('[id$="-btnIconEl"]')
      if (!iconEl) continue
      if (iconEl.getAttribute('data-pa-profile-icon') === flat) continue
      iconEl.setAttribute('data-pa-profile-icon', flat)
      iconEl.style.setProperty(
        'background-image',
        'url("/resources/images/expedition/icons/' + flat + '")',
        'important',
      )
      iconEl.style.setProperty('background-size', '16px 16px', 'important')
      iconEl.style.setProperty('background-repeat', 'no-repeat', 'important')
      iconEl.style.setProperty('background-position', 'center', 'important')
      iconEl.style.setProperty('background-color', 'transparent', 'important')
      btn.classList.add('pa-profile-pill')
    }
  }

  function enhanceVendorTabs(root) {
    root = root || document
    var tabs = root.querySelectorAll(
      '#ImportSupport .x-tab, #ImportSupport .x-tab-bar .x-tab, .x-tab-bar-top .x-tab',
    )
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i]
      var label = normalizeLabel(tab.textContent)
      if (!label) continue
      var hit = null
      for (var v = 0; v < VENDOR_TAB_LOGO.length; v++) {
        if (VENDOR_TAB_LOGO[v].match.test(label)) {
          hit = VENDOR_TAB_LOGO[v]
          break
        }
      }
      if (!hit) continue
      tab.classList.add('pa-vendor-tab', hit.cls)
      tab.setAttribute('data-pa-vendor', '1')
      tab.removeAttribute('data-pa-icon')
      var glyph = tab.querySelector('.x-tab-glyph, .x-tab-icon-el')
      if (!glyph) {
        var btn = tab.querySelector('.x-tab-button, .x-tab-wrap') || tab
        glyph = document.createElement('span')
        glyph.className = 'x-tab-icon-el pa-vendor-logo'
        glyph.setAttribute('aria-hidden', 'true')
        btn.insertBefore(glyph, btn.firstChild)
      } else {
        glyph.classList.add('pa-vendor-logo')
      }
      glyph.style.setProperty(
        'background-image',
        'url("' + hit.src + '")',
        'important',
      )
      glyph.style.setProperty('background-size', 'contain', 'important')
      glyph.style.setProperty('background-repeat', 'no-repeat', 'important')
      glyph.style.setProperty('background-position', 'center', 'important')
      glyph.style.setProperty('background-color', 'transparent', 'important')
      glyph.style.setProperty('-webkit-mask-image', 'none', 'important')
      glyph.style.setProperty('mask-image', 'none', 'important')
      glyph.style.setProperty('font-size', '0', 'important')
      glyph.style.setProperty('color', 'transparent', 'important')
      glyph.style.setProperty('width', '20px', 'important')
      glyph.style.setProperty('height', '20px', 'important')
      glyph.style.setProperty('min-width', '20px', 'important')
      glyph.style.setProperty('margin-right', '8px', 'important')
    }
  }

  function scrubImportAdvertising() {
    var card =
      document.getElementById('ImportCard') ||
      document.getElementById('ImportProgress') ||
      document.querySelector('[itemid="ImportProgress"]')
    if (!card) {
      // Still scrub ads if progress view is mounted elsewhere
      card = document.body
    } else {
      card.classList.add('pa-import-clean')
    }
    var nodes = card.querySelectorAll(
      '.x-form-display-field, .x-component, img, .x-img, .x-field',
    )
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i]
      var txt = (el.textContent || el.getAttribute('value') || '').toLowerCase()
      var src = (el.getAttribute('src') || el.src || '').toLowerCase()
      var style = (el.getAttribute('style') || '').toLowerCase()
      if (
        txt.indexOf('holistic security') !== -1 ||
        txt.indexOf('palo alto networks holistic') !== -1 ||
        src.indexOf('layer-cake') !== -1 ||
        src.indexOf('palo_alto_canvas') !== -1 ||
        src.indexOf('mt-policy') !== -1 ||
        (style.indexOf('font-size:2.5em') !== -1 && txt.indexOf('palo') !== -1)
      ) {
        el.style.setProperty('display', 'none', 'important')
        el.setAttribute('aria-hidden', 'true')
        var wrap = el.closest('.x-container, .x-field, .x-component, .x-box-item')
        if (wrap && wrap !== card && wrap.id !== 'ImportCard') {
          wrap.style.setProperty('display', 'none', 'important')
        }
      }
    }
    var prog = document.getElementById('parseprogress')
    if (prog) {
      prog.classList.add('pa-progress-modern')
      var fieldset = prog.closest('fieldset, .x-fieldset, .x-panel')
      if (fieldset) fieldset.classList.add('pa-import-progress-wrap')
    }
    var bgNodes = document.querySelectorAll('.bgimport, [class*="bgimport"]')
    for (var b = 0; b < bgNodes.length; b++) {
      bgNodes[b].style.setProperty('background', 'transparent', 'important')
      bgNodes[b].style.setProperty('background-image', 'none', 'important')
    }
  }

  function flattenDeviceUsageChrome() {
    var titles = {
      'Device Usage': 1,
      'Global Summary': 1,
    }

    // Prefer real Ext buttons for Device Usage (avoid double-styling wrappers)
    var btns = document.querySelectorAll('.x-btn.green-button, .green-button.x-btn')
    for (var b = 0; b < btns.length; b++) {
      var btn = btns[b]
      var bt = (btn.textContent || '').replace(/\s+/g, ' ').trim()
      if (bt.indexOf('Device Usage') === -1) continue
      btn.classList.add('pa-banner-btn', 'pa-flat-device-usage')
      btn.classList.remove('pa-glass-title-chip')
      // Strip Ext frame ghosts on this button only
      var frameBits = btn.querySelectorAll(
        '.x-btn-wrap, .x-btn-button, .x-btn-inner, .x-frame-tl, .x-frame-tc, .x-frame-tr, .x-frame-ml, .x-frame-mc, .x-frame-mr, .x-frame-bl, .x-frame-bc, .x-frame-br',
      )
      for (var f = 0; f < frameBits.length; f++) {
        frameBits[f].style.setProperty('background', 'transparent', 'important')
        frameBits[f].style.setProperty('background-image', 'none', 'important')
        frameBits[f].style.setProperty('border', '0', 'important')
        frameBits[f].style.setProperty('box-shadow', 'none', 'important')
        frameBits[f].style.setProperty('border-radius', '0', 'important')
      }
    }

    var labels = document.querySelectorAll(
      'label, .x-component, .x-label, .x-form-item-label, span',
    )
    for (var i = 0; i < labels.length; i++) {
      var el = labels[i]
      // Only the leaf text node — never a wrapper that already contains a chip/btn
      if (el.querySelector && el.querySelector('.pa-glass-title-chip, .pa-banner-btn, .x-btn')) {
        continue
      }
      if ((el.childElementCount || 0) > 1) continue
      var t = (el.textContent || '').replace(/\s+/g, ' ').trim()
      if (!titles[t]) continue
      // Device Usage is a button — skip label clones
      if (t === 'Device Usage' && el.closest && el.closest('.x-btn')) continue

      el.classList.add('pa-glass-title-chip', 'pa-flat-device-usage')
      // Ancestors: strip chrome only — do NOT restyle them as pills.
      // Never force height on wrappers that contain dashboard charts (was
      // collapsing App-ID / User-ID / radar to ~4px tall).
      var node = el.parentElement
      var taggedBar = false
      for (var d = 0; d < 6 && node; d++) {
        if (
          node.id === 'DashboardCard' ||
          node.id === 'DashboardCard-body' ||
          (node.querySelector &&
            node.querySelector('#appidchart, #appidchart1, #DashboardRadarChart'))
        ) {
          break
        }
        node.classList.add('pa-banner-ancestor')
        node.style.setProperty('background', 'transparent', 'important')
        node.style.setProperty('background-image', 'none', 'important')
        node.style.setProperty('border', '0', 'important')
        node.style.setProperty('border-radius', '0', 'important')
        node.style.setProperty('box-shadow', 'none', 'important')
        node.style.setProperty('backdrop-filter', 'none', 'important')
        node.style.setProperty('-webkit-backdrop-filter', 'none', 'important')
        var cs = window.getComputedStyle(node)
        var h = parseFloat(cs.height) || 0
        var mh = parseFloat(cs.maxHeight) || 0
        if (
          !taggedBar &&
          ((h > 0 && h <= 64) || (mh > 0 && mh <= 64) || node.style.height === '50px')
        ) {
          node.classList.add('pa-section-title-bar', 'pa-flat-device-usage-bar')
          node.style.setProperty('overflow', 'visible', 'important')
          node.style.setProperty('height', '48px', 'important')
          node.style.setProperty('max-height', '48px', 'important')
          node.style.setProperty('min-height', '48px', 'important')
          taggedBar = true
        }
        node = node.parentElement
      }
    }
    var imgs = document.querySelectorAll('img[src*="pan-blue"]')
    for (var j = 0; j < imgs.length; j++) {
      imgs[j].style.setProperty('display', 'none', 'important')
      var wrap = imgs[j].closest('.x-component, .x-container, .x-box-item')
      if (wrap) wrap.style.setProperty('display', 'none', 'important')
    }
  }

  function scrubActiveTabUnderline() {
    var tabs = document.querySelectorAll(
      '.pa-side-nav .x-tab-active, #projectOptions .x-tab-active, #mainpaneltabs .x-tab-active',
    )
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i]
      tab.style.setProperty('border', '0', 'important')
      tab.style.setProperty('border-bottom', '0', 'important')
      tab.style.setProperty('outline', '0', 'important')
      var parts = tab.querySelectorAll(
        '.x-tab-inner, .x-tab-button, .x-tab-wrap, .x-tab-mc, .x-tab-tc, .x-tab-bc',
      )
      for (var j = 0; j < parts.length; j++) {
        parts[j].style.setProperty('text-decoration', 'none', 'important')
        parts[j].style.setProperty('border', '0', 'important')
        parts[j].style.setProperty('border-bottom', '0', 'important')
        parts[j].style.setProperty('box-shadow', 'none', 'important')
        parts[j].style.setProperty('background-image', 'none', 'important')
      }
    }
  }

  function enhanceDashboardHero(root) {
    root = root || document
    // Collapse Workspace hero slot so release grid fills the row
    var heroes = root.querySelectorAll(
      'img[src*="pa-side-hero"], img.pa-dash-hero, .pa-dash-hero, .pa-dash-hero-slot',
    )
    for (var i = 0; i < heroes.length; i++) {
      var node = heroes[i]
      node.style.setProperty('display', 'none', 'important')
      node.setAttribute('aria-hidden', 'true')
      // Climb to the fixed-width myborder tile (was 230px empty glass card)
      var wrap = node.closest
        ? node.closest('.myborder, .x-panel, .x-container, .x-box-item')
        : null
      var guard = 0
      while (wrap && guard < 4) {
        wrap.classList.add('pa-dash-hero-slot')
        wrap.style.setProperty('display', 'none', 'important')
        wrap.style.setProperty('width', '0', 'important')
        wrap.style.setProperty('min-width', '0', 'important')
        wrap.style.setProperty('height', '0', 'important')
        wrap.style.setProperty('margin', '0', 'important')
        wrap.style.setProperty('padding', '0', 'important')
        wrap.style.setProperty('border', '0', 'important')
        wrap.style.setProperty('overflow', 'hidden', 'important')
        wrap.setAttribute('aria-hidden', 'true')
        // Prefer the myborder card; stop once found
        if (wrap.classList.contains('myborder')) break
        wrap = wrap.parentElement
          ? wrap.parentElement.closest('.myborder, .x-panel, .x-container')
          : null
        guard++
      }
    }
    // Expand release property grid into the freed space
    try {
      var grid = Ext.getCmp && Ext.getCmp('mtversiongrid')
      if (grid) {
        if (grid.setFlex) grid.setFlex(1)
        if (grid.setMargin) grid.setMargin('0 5 0 0')
        if (grid.setWidth) grid.setWidth(null)
        var el = grid.getEl && grid.getEl()
        if (el && el.dom) {
          el.dom.classList.add('pa-release-grid')
          el.dom.style.setProperty('margin-left', '0', 'important')
          el.dom.style.setProperty('flex', '1 1 auto', 'important')
        }
        if (grid.updateLayout) grid.updateLayout()
        var owner = grid.ownerCt
        if (owner && owner.updateLayout) owner.updateLayout()
      }
    } catch (err) {
      /* ignore */
    }
    var release = root.querySelectorAll(
      '#mtversiongrid, .pa-release-grid, [id*="mtversiongrid"]',
    )
    for (var r = 0; r < release.length; r++) {
      release[r].style.setProperty('margin-left', '0', 'important')
      release[r].classList.add('pa-release-grid')
    }
  }

  function fixTabPanelLayout(id) {
    try {
      var tabs = Ext.getCmp(id)
      if (!tabs || !tabs.getTabBar || !tabs.body) return false
      if (tabs.getTabPosition && tabs.getTabPosition() !== 'left') {
        if (tabs.setTabPosition) tabs.setTabPosition('left')
        if (tabs.setTabRotation) tabs.setTabRotation(0)
      }
      var bar = tabs.getTabBar()
      var barW = 228
      if (bar && bar.setWidth) bar.setWidth(barW)
      if (bar && bar.getWidth) {
        var measured = bar.getWidth()
        if (measured > 120 && measured < 360) barW = measured
      }
      if (bar && bar.getEl && bar.getEl()) {
        enhanceTabBar(bar.getEl().dom, { project: id === 'projectOptions' })
      }
      var total = tabs.getWidth ? tabs.getWidth() : 0
      var height = tabs.getHeight ? tabs.getHeight() : 0
      if (!total || !height) return true
      // Prefer live geometry so we never double-count Ext's margin-left
      try {
        var panelEl = tabs.getEl && tabs.getEl()
        var barEl = bar && bar.getEl && bar.getEl()
        if (panelEl && barEl) {
          var pr = panelEl.dom.getBoundingClientRect()
          var br = barEl.dom.getBoundingClientRect()
          var live = Math.round(br.right - pr.left)
          if (live > 120 && live < 360) barW = live
        }
      } catch (geoErr) {
        /* ignore */
      }
      // Overlap 2px into the rail so the dark gutter never shows
      var flushLeft = Math.max(barW - 2, 0)
      var bodyW = Math.max(total - flushLeft, 320)
      var bodyDom = tabs.body.dom
      // Ext often sets BOTH left and margin-left → 2× gap; force a single offset
      bodyDom.style.setProperty('margin-left', '0px', 'important')
      bodyDom.style.setProperty('margin-top', '0px', 'important')
      bodyDom.style.setProperty('padding', '0px', 'important')
      bodyDom.style.setProperty('left', flushLeft + 'px', 'important')
      bodyDom.style.setProperty('top', '0px', 'important')
      bodyDom.style.setProperty('width', bodyW + 'px', 'important')
      bodyDom.style.setProperty('height', height + 'px', 'important')
      bodyDom.style.setProperty('right', '0px', 'important')
      bodyDom.style.setProperty('display', 'block', 'important')
      bodyDom.style.setProperty('position', 'absolute', 'important')
      bodyDom.style.setProperty('box-sizing', 'border-box', 'important')
      bodyDom.style.setProperty('border-radius', '0', 'important')
      bodyDom.style.setProperty('overflow', 'hidden', 'important')
      var active = tabs.getActiveTab && tabs.getActiveTab()
      if (active) {
        if (active.setSize) active.setSize(bodyW, height)
        if (active.updateLayout) active.updateLayout(true)
        try {
          var actEl = active.getEl && active.getEl()
          if (actEl && actEl.dom) {
            actEl.dom.style.setProperty('border-radius', '0', 'important')
            actEl.dom.style.setProperty('margin', '0', 'important')
            actEl.dom.style.setProperty('width', bodyW + 'px', 'important')
            actEl.dom.style.setProperty('height', height + 'px', 'important')
          }
        } catch (actErr) {
          /* ignore */
        }
        // Nested Workspace "Dashboard" card often collapses to ~2px wide
        try {
          fillNestedDashboard(active, bodyW, height)
        } catch (nestErr) {
          /* ignore */
        }
      }
      return true
    } catch (e) {
      return false
    }
  }

  function fillNestedDashboard(active, bodyW, height) {
    if (!active) return
    var dashWrap = Ext.getCmp('Dashboard') || (active.down && active.down('#Dashboard'))
    var dashCard = Ext.getCmp('DashboardCard')
    var targets = [dashWrap, dashCard]
    for (var i = 0; i < targets.length; i++) {
      var cmp = targets[i]
      if (!cmp) continue
      var sz = cmp.getSize && cmp.getSize()
      var broken = !sz || sz.width < 40 || sz.width > 4000
      if (broken || (cmp.id === 'DashboardCard' && sz && sz.width < bodyW * 0.5)) {
        if (cmp.setSize) cmp.setSize(bodyW, height)
        if (cmp.updateLayout) cmp.updateLayout(true)
        var el = cmp.getEl && cmp.getEl()
        if (el && el.dom) {
          el.dom.style.setProperty('width', bodyW + 'px', 'important')
          el.dom.style.setProperty('height', height + 'px', 'important')
          el.dom.style.setProperty('max-width', '100%', 'important')
          el.dom.style.setProperty('left', '0px', 'important')
          el.dom.style.setProperty('top', '0px', 'important')
        }
      }
    }
    // After dashboard fills, repair chart flex row
    repairDashboardChartLayout()
  }

  var LOGIN_THEME_KEY = 'pa-converter-login-theme'
  var loginCardSizing = { w: 0, h: 0, left: 0, top: 0 }
  var loginStyleBusy = false

  function getLoginTheme() {
    try {
      var stored = localStorage.getItem(LOGIN_THEME_KEY)
      if (stored === 'light' || stored === 'dark') return stored
    } catch (e) {
      /* ignore */
    }
    return 'light'
  }

  // Only clear paint overrides — never strip layout (position/size) or the split collapses.
  function clearLoginThemeInlineStyles(win) {
    win = win || document.getElementById('login')
    if (!win) return
    var nodes = win.querySelectorAll(
      '.pa-login-form-pane, .pa-login-form-inner, .pa-login-hero, #LoginForm, #LoginForm-body',
    )
    var props = [
      'background',
      'background-color',
      'background-image',
      'backdrop-filter',
      '-webkit-backdrop-filter',
    ]
    for (var i = 0; i < nodes.length; i++) {
      for (var p = 0; p < props.length; p++) {
        try {
          nodes[i].style.removeProperty(props[p])
        } catch (e) {
          /* ignore */
        }
      }
    }
  }

  function applyLoginTheme(theme, opts) {
    opts = opts || {}
    theme = theme === 'light' ? 'light' : 'dark'
    var root = document.documentElement
    root.classList.remove('pa-login-theme-dark', 'pa-login-theme-light', 'pa-theme-dark', 'pa-theme-light')
    root.classList.add('pa-login-theme-' + theme)
    root.classList.add('pa-theme-' + theme)
    root.setAttribute('data-pa-theme', theme)
    try {
      localStorage.setItem(LOGIN_THEME_KEY, theme)
    } catch (e) {
      /* ignore */
    }
    var btn = document.getElementById('pa-login-theme-toggle')
    if (btn) {
      var label = btn.querySelector('[data-pa-theme-label]')
      var next = theme === 'light' ? 'Dark' : 'Light'
      if (label && label.textContent !== next) label.textContent = next
      var tip = theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'
      btn.setAttribute('aria-label', tip)
      btn.setAttribute('data-theme', theme)
      btn.setAttribute('title', tip)
    }
    if (opts.clearLoginInline !== false) clearLoginThemeInlineStyles()
    if (opts.forceLoginRelayout) loginCardSizing = { w: 0, h: 0, left: 0, top: 0 }
    if (theme === 'dark') scrubLightSurfacesInDarkMode()
    else {
      clearDarkModeScrub()
      restyleDashboardChartsForTheme('light')
    }
  }

  function toggleLoginTheme() {
    applyLoginTheme(getLoginTheme() === 'light' ? 'dark' : 'light', {
      clearLoginInline: true,
      forceLoginRelayout: true,
    })
    try {
      styleLoginCard()
    } catch (e) {
      /* ignore */
    }
    return getLoginTheme()
  }

  function ensureLoginThemeToggle() {
    window.paConverterToggleLoginTheme = toggleLoginTheme
    var onLogin = !!document.getElementById('login')
    var existing = document.getElementById('pa-login-theme-toggle')
    if (existing) {
      if (existing.parentNode !== document.body) document.body.appendChild(existing)
      existing.style.display = ''
      existing.setAttribute('data-pa-placement', onLogin ? 'login' : 'workspace')
      applyLoginTheme(getLoginTheme())
      return
    }
    var btn = document.createElement('button')
    btn.type = 'button'
    btn.id = 'pa-login-theme-toggle'
    btn.className = 'pa-login-theme-toggle'
    btn.setAttribute('aria-label', 'Toggle color theme')
    btn.setAttribute('data-pa-placement', onLogin ? 'login' : 'workspace')
    btn.innerHTML =
      '<span class="pa-login-theme-icon" aria-hidden="true"></span>' +
      '<span class="pa-login-theme-label" data-pa-theme-label>Theme</span>'
    function onToggle(e) {
      if (e) {
        e.preventDefault()
        e.stopPropagation()
        if (e.stopImmediatePropagation) e.stopImmediatePropagation()
      }
      toggleLoginTheme()
    }
    btn.addEventListener('click', onToggle, true)
    document.body.appendChild(btn)
    applyLoginTheme(getLoginTheme())
  }

  function styleLoginCard() {
    if (loginStyleBusy) return false
    var win = document.getElementById('login')
    if (!win) {
      document.documentElement.classList.remove('pa-login-active')
      // Keep theme control in workspace — docked bottom-left of the rail
      ensureLoginThemeToggle()
      return false
    }
    loginStyleBusy = true
    try {
      win.classList.add('pa-login-window')
      document.documentElement.classList.add('pa-login-active')
      // Sync theme classes without wiping layout every tick
      applyLoginTheme(getLoginTheme(), { clearLoginInline: false, forceLoginRelayout: false })

      var body =
        document.getElementById('login-body') ||
        win.querySelector('.x-window-body')
      if (!body) return false
      body.classList.add('pa-login-card-ready')
      ensureLoginThemeToggle()

      // Same split card for light + dark (~960 × 600) — dark only changes form paint
      var darkLogin = document.documentElement.classList.contains('pa-login-theme-dark')
      var maxW = Math.min(960, Math.max(320, window.innerWidth - 40))
      if (maxW % 2) maxW -= 1
      var maxH = Math.min(600, Math.max(520, window.innerHeight - 96))
      var left = Math.round((window.innerWidth - maxW) / 2)
      var top = Math.round((window.innerHeight - maxH) / 2)
      var sizeChanged =
        loginCardSizing.w !== maxW ||
        loginCardSizing.h !== maxH ||
        loginCardSizing.left !== left ||
        loginCardSizing.top !== top

      try {
        var cmp = typeof Ext !== 'undefined' && Ext.getCmp && Ext.getCmp('login')
        if (cmp) {
          // Kill Ext's floating shadow — it intercepts clicks on fields/buttons
          try {
            cmp.shadow = false
            if (cmp.el && cmp.el.setStyle) cmp.el.setStyle('box-shadow', 'none')
            if (cmp.getShadow && cmp.getShadow()) {
              var sh = cmp.getShadow()
              if (sh.hide) sh.hide()
              if (sh.el && sh.el.setStyle) sh.el.setStyle('pointer-events', 'none')
            }
          } catch (shadowErr) {
            /* ignore */
          }
          if (sizeChanged) {
            // Demaximize once, then size/center as a real floating card so Ext layout stays correct
            if (cmp.maximized) {
              if (cmp.restore) cmp.restore()
              else if (cmp.setMaximized) cmp.setMaximized(false)
            }
            cmp.maximizable = false
            if (cmp.setSize) cmp.setSize(maxW, maxH)
            if (cmp.setPosition) cmp.setPosition(left, top)
            else if (cmp.center) cmp.center()
            if (cmp.updateLayout) cmp.updateLayout()
            loginCardSizing = { w: maxW, h: maxH, left: left, top: top }
          }
          // Same hero + form side-by-side split for light and dark
          try {
            var heroEl = win.querySelector('.pa-login-hero')
            var formEl = win.querySelector('.pa-login-form-pane')
            var bodyEl =
              document.getElementById('login-body') ||
              win.querySelector('.x-window-body')
            if (heroEl && formEl && bodyEl) {
              var bh = bodyEl.clientHeight || maxH
              var bw = bodyEl.clientWidth || maxW
              var half = Math.floor(bw / 2)
              ;[heroEl, formEl].forEach(function (el) {
                el.style.setProperty('position', 'absolute', 'important')
                el.style.setProperty('top', '0px', 'important')
                el.style.setProperty('margin', '0', 'important')
                el.style.setProperty('height', bh + 'px', 'important')
                el.style.setProperty('border', '0', 'important')
                el.style.setProperty('outline', '0', 'important')
              })
              heroEl.style.setProperty('display', 'block', 'important')
              heroEl.style.removeProperty('width')
              heroEl.style.removeProperty('min-width')
              heroEl.style.removeProperty('max-width')
              heroEl.style.setProperty('left', '0px', 'important')
              formEl.style.setProperty('left', half + 'px', 'important')
              heroEl.style.setProperty('width', half + 'px', 'important')
              formEl.style.setProperty('width', bw - half + 'px', 'important')
              formEl.style.setProperty('display', 'block', 'important')
              heroEl.style.setProperty(
                'border-radius',
                '32px 0 0 32px',
                'important',
              )
              formEl.style.setProperty(
                'border-radius',
                '0 32px 32px 0',
                'important',
              )
              heroEl.style.setProperty('overflow', 'hidden', 'important')
              formEl.style.setProperty('overflow', 'hidden', 'important')
              heroEl.style.setProperty(
                'box-shadow',
                darkLogin
                  ? 'inset -1px 0 0 rgba(255,255,255,0.1)'
                  : 'inset -1px 0 0 rgba(255,255,255,0.28)',
                'important',
              )
              ;[heroEl, formEl].forEach(function (col) {
                var targets = col.querySelectorAll('.x-box-inner, .x-box-target')
                for (var t = 0; t < targets.length; t++) {
                  targets[t].style.setProperty('width', '100%', 'important')
                  targets[t].style.setProperty('max-width', '100%', 'important')
                  targets[t].style.setProperty('left', '0px', 'important')
                }
              })
              var formInner = formEl.querySelector('.pa-login-form-inner')
              if (formInner) {
                formInner.style.setProperty('position', 'static', 'important')
                formInner.style.setProperty('left', 'auto', 'important')
                formInner.style.setProperty('top', 'auto', 'important')
                formInner.style.setProperty('transform', 'none', 'important')
                formInner.style.setProperty('height', 'auto', 'important')
                formInner.style.setProperty('overflow', 'visible', 'important')
                formInner.style.setProperty(
                  'width',
                  Math.min(392, Math.max(240, bw - half - 88)) + 'px',
                  'important',
                )
                formInner.style.setProperty('margin-left', 'auto', 'important')
                formInner.style.setProperty('margin-right', 'auto', 'important')
                var stacked = formInner.querySelectorAll(
                  '.x-box-item, #LoginForm, .pa-login-form-title, .pa-login-form-sub, .pa-login-terms',
                )
                for (var si = 0; si < stacked.length; si++) {
                  stacked[si].style.setProperty('position', 'static', 'important')
                  stacked[si].style.setProperty('left', 'auto', 'important')
                  stacked[si].style.setProperty('top', 'auto', 'important')
                  stacked[si].style.setProperty('float', 'none', 'important')
                  stacked[si].style.setProperty('width', '100%', 'important')
                }
                var loginFormEl = formInner.querySelector('#LoginForm')
                if (loginFormEl) {
                  loginFormEl.style.setProperty('height', 'auto', 'important')
                  loginFormEl.style.setProperty('overflow', 'visible', 'important')
                  var formItems = loginFormEl.querySelectorAll('.x-box-item, .x-form-item')
                  for (var fi = 0; fi < formItems.length; fi++) {
                    formItems[fi].style.setProperty('position', 'static', 'important')
                    formItems[fi].style.setProperty('left', 'auto', 'important')
                    formItems[fi].style.setProperty('top', 'auto', 'important')
                    formItems[fi].style.setProperty('width', '100%', 'important')
                  }
                }
              }
            }
          } catch (splitErr) {
            /* ignore */
          }
        }
      } catch (e) {
        /* ignore */
      }

      // Remove Ext rectangle shadow entirely (causes double-corner ghost)
      var shadows = document.querySelectorAll('.x-css-shadow, .x-shim')
      for (var s = 0; s < shadows.length; s++) {
        shadows[s].style.setProperty('display', 'none', 'important')
        shadows[s].style.setProperty('visibility', 'hidden', 'important')
        shadows[s].style.setProperty('opacity', '0', 'important')
        shadows[s].style.setProperty('pointer-events', 'none', 'important')
      }

      var bodyWrap = document.getElementById('login-bodyWrap')
      if (bodyWrap) {
        bodyWrap.style.setProperty('border-radius', '32px', 'important')
        bodyWrap.style.setProperty('overflow', 'hidden', 'important')
        bodyWrap.style.setProperty('outline', '0', 'important')
        bodyWrap.style.setProperty('border', '0', 'important')
      }
      body.style.setProperty('border-radius', '32px', 'important')
      body.style.setProperty('overflow', 'hidden', 'important')
      body.style.setProperty('border', '0', 'important')
      body.style.setProperty('outline', '0', 'important')
      win.style.setProperty('background', 'transparent', 'important')
      win.style.setProperty('border', '0', 'important')
      win.style.setProperty('outline', '0', 'important')
      win.style.setProperty('border-radius', '32px', 'important')
      win.style.setProperty('overflow', 'hidden', 'important')
      // Keep soft card elevation on the window (not Ext's 5px shadow)

      // Keep logo crisp + correct aspect inside the glass plate
      try {
        var brand = win.querySelector('.pa-login-brand')
        if (brand) {
          var bw = Math.min(260, Math.max(200, Math.floor((win.querySelector('.pa-login-hero')?.getBoundingClientRect().width || 400) * 0.58)))
          var bh = Math.round(bw * (199 / 1120))
          brand.style.width = bw + 'px'
          brand.style.height = bh + 'px'
          brand.style.maxWidth = '100%'
          var brandCmp = typeof Ext !== 'undefined' && Ext.getCmp && Ext.getCmp(brand.id)
          if (brandCmp && brandCmp.setSize) brandCmp.setSize(bw, bh)
        }
        var glass = win.querySelector('.pa-login-brand-glass')
        if (glass) {
          glass.style.setProperty('position', 'static', 'important')
          glass.style.setProperty('left', 'auto', 'important')
          glass.style.setProperty('top', 'auto', 'important')
          glass.style.setProperty('display', 'flex', 'important')
          glass.style.setProperty('margin-left', 'auto', 'important')
          glass.style.setProperty('margin-right', 'auto', 'important')
          // Hide Ext chrome inside the glass plate; keep only our crisp logo img
          var glassKids = glass.children
          for (var gi = 0; gi < glassKids.length; gi++) {
            if (!glassKids[gi].classList.contains('pa-login-brand-img')) {
              glassKids[gi].style.setProperty('display', 'none', 'important')
              glassKids[gi].style.setProperty('position', 'absolute', 'important')
              glassKids[gi].style.setProperty('opacity', '0', 'important')
            }
          }
          var logoImg = glass.querySelector('img.pa-login-brand-img')
          if (!logoImg) {
            logoImg = document.createElement('img')
            logoImg.className = 'pa-login-brand-img'
            logoImg.alt = 'PA-Converter'
            glass.appendChild(logoImg)
          }
          var logoSrc = '/resources/images/expedition/logo-bg.png?v=glass6'
          if (logoImg.getAttribute('src') !== logoSrc) logoImg.src = logoSrc
          logoImg.style.setProperty('display', 'block', 'important')
          logoImg.style.setProperty('margin', '0 auto', 'important')
        }
        var heroSub = win.querySelector('.pa-login-hero-sub')
        if (heroSub) {
          heroSub.style.setProperty('display', 'none', 'important')
          heroSub.style.setProperty('visibility', 'hidden', 'important')
          heroSub.style.setProperty('height', '0', 'important')
          heroSub.style.setProperty('margin', '0', 'important')
        }
        // Left column = banner image only (no logo plate)
        var leftGlass = win.querySelector('.pa-login-hero .pa-login-brand-glass')
        if (leftGlass) {
          leftGlass.style.setProperty('display', 'none', 'important')
          leftGlass.setAttribute('aria-hidden', 'true')
        }
        // Hide Terms and Conditions
        var terms = win.querySelectorAll('.pa-login-terms, .x-btn.pa-login-terms')
        for (var ti = 0; ti < terms.length; ti++) {
          terms[ti].style.setProperty('display', 'none', 'important')
          terms[ti].setAttribute('aria-hidden', 'true')
        }
        // Form copy + logo above Sign in
        var formInner = win.querySelector('.pa-login-form-inner')
        if (formInner) {
          var titleEl = formInner.querySelector('.pa-login-form-title')
          var subEl = formInner.querySelector('.pa-login-form-sub')
          var formLogo = formInner.querySelector('.pa-login-form-logo')
          if (!formLogo) {
            formLogo = document.createElement('img')
            formLogo.className = 'pa-login-form-logo'
            formLogo.alt = 'PA-Converter'
            formLogo.src = '/resources/images/expedition/logo-bg.png?v=form3'
          }
          // Always pin logo as first visual above Sign in (never below submit)
          formInner.insertBefore(formLogo, formInner.firstChild)
          if (titleEl && titleEl.parentNode === formInner) {
            formInner.insertBefore(formLogo, titleEl)
          }
          formLogo.style.setProperty('order', '-20', 'important')
          formLogo.style.setProperty('display', 'block', 'important')
          formLogo.style.setProperty('margin', '0 0 20px 0', 'important')
          formLogo.style.setProperty('position', 'static', 'important')
          formLogo.style.setProperty('left', 'auto', 'important')
          formLogo.style.setProperty('top', 'auto', 'important')
          if (titleEl) {
            titleEl.style.setProperty('order', '-10', 'important')
            titleEl.style.setProperty('margin', '0 0 8px 0', 'important')
            titleEl.style.setProperty('text-align', 'left', 'important')
            titleEl.style.setProperty('width', '100%', 'important')
          }
          if (subEl) {
            subEl.style.setProperty('order', '-5', 'important')
            subEl.style.setProperty('margin', '0 0 28px 0', 'important')
            subEl.style.setProperty('text-align', 'left', 'important')
            subEl.style.setProperty('width', '100%', 'important')
            subEl.style.setProperty('height', 'auto', 'important')
            subEl.style.setProperty('line-height', '1.4', 'important')
          }
          var loginForm = formInner.querySelector('#LoginForm')
          if (loginForm) loginForm.style.setProperty('order', '0', 'important')
        }
      } catch (brandErr) {
        /* ignore */
      }

      // Dark login: black form pane only — keep hero banner image intact
      if (darkLogin) {
        var blackNodes = win.querySelectorAll(
          '.pa-login-form-pane, .pa-login-form-inner, #LoginForm, #LoginForm-body',
        )
        for (var bi = 0; bi < blackNodes.length; bi++) {
          blackNodes[bi].style.setProperty('background', '#000000', 'important')
          blackNodes[bi].style.setProperty('background-color', '#000000', 'important')
          blackNodes[bi].style.setProperty('background-image', 'none', 'important')
          blackNodes[bi].style.setProperty('backdrop-filter', 'none', 'important')
        }
      }

      var fields = win.querySelectorAll('.pa-login-field')
      for (var i = 0; i < fields.length; i++) {
        fields[i].style.marginBottom = '12px'
      }

      var submit = document.getElementById('submit_login')
      if (submit) {
        submit.classList.add('pa-login-submit')
        var inner = submit.querySelector('.x-btn-inner')
        if (inner && /log\s*in/i.test(inner.textContent || '')) {
          inner.textContent = 'Sign in'
        }
        try {
          var btnCmp = Ext.getCmp('submit_login')
          var formCmp = Ext.getCmp('LoginForm')
          var form = document.getElementById('LoginForm')
          var fw = form ? Math.floor(form.getBoundingClientRect().width - 20) : 0
          if (btnCmp && btnCmp.setWidth && fw > 120) {
            var cur = btnCmp.getWidth ? btnCmp.getWidth() : 0
            if (Math.abs(cur - fw) > 2) btnCmp.setWidth(fw)
          }
          // Keep formBind in sync so Sign in is clickable after typing
          if (formCmp && formCmp.isValid && btnCmp && btnCmp.setDisabled) {
            btnCmp.setDisabled(!formCmp.isValid())
          }
        } catch (err) {
          /* ignore */
        }
      }

      return true
    } finally {
      loginStyleBusy = false
    }
  }

  function clearDarkModeScrub() {
    var scrubbed = document.querySelectorAll('[data-pa-dark-scrub="1"]')
    for (var i = 0; i < scrubbed.length; i++) {
      var el = scrubbed[i]
      el.style.removeProperty('background')
      el.style.removeProperty('background-color')
      el.style.removeProperty('background-image')
      el.style.removeProperty('color')
      el.removeAttribute('data-pa-dark-scrub')
    }
  }

  function scrubLightSurfacesInDarkMode() {
    if (!document.documentElement.classList.contains('pa-theme-dark')) return
    var darkBg = 'rgba(22, 28, 40, 0.96)'
    var darkText = '#f5f5f7'
    var roots = [
      document.getElementById('mainpaneltabs-body'),
      document.getElementById('projectOptions-body'),
      document.getElementById('DashboardCard'),
      document.getElementById('MainPanel-body'),
      document.body,
    ]
    function isChartSurface(el) {
      if (!el || !el.classList) return false
      if (
        el.classList.contains('x-surface') ||
        el.classList.contains('x-surface-canvas') ||
        el.classList.contains('x-draw-container') ||
        el.classList.contains('x-legend') ||
        el.classList.contains('x-legend-container')
      ) {
        return true
      }
      var id = el.id || ''
      return (
        id === 'appidchart' ||
        id === 'appidchart1' ||
        id === 'DashboardRadarChart' ||
        id.indexOf('appidchart') === 0 ||
        id.indexOf('DashboardRadar') === 0
      )
    }
    function paintDark(el) {
      if (!el || !el.style || isChartSurface(el)) return
      // Never paint over Ext chart/canvas ancestors' drawing hosts
      if (el.closest && el.closest('.x-draw-container, .x-surface, canvas.x-surface-canvas')) return
      el.style.setProperty('background', darkBg, 'important')
      el.style.setProperty('background-color', darkBg, 'important')
      el.style.setProperty('background-image', 'none', 'important')
      el.style.setProperty('color', darkText, 'important')
      el.setAttribute('data-pa-dark-scrub', '1')
    }
    function styleLooksWhite(st) {
      st = (st || '').toLowerCase().replace(/\s+/g, '')
      if (!st) return false
      if (
        st.indexOf('background-color:white') !== -1 ||
        st.indexOf('background-color:#fff') !== -1 ||
        st.indexOf('background-color:#ffffff') !== -1 ||
        st.indexOf('background:white') !== -1 ||
        st.indexOf('background:#fff') !== -1 ||
        st.indexOf('background:#ffffff') !== -1 ||
        st.indexOf('background:rgb(255,255,255)') !== -1 ||
        st.indexOf('background-color:rgb(255,255,255)') !== -1
      ) {
        return true
      }
      // Near-white hex backgrounds (#fafafa, #f5f5f7, etc.) — not pure black/dark
      var m = st.match(/background(?:-color)?:#([0-9a-f]{3,8})/)
      if (!m) return false
      var hex = m[1]
      if (hex.length === 3) hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2]
      if (hex.length < 6) return false
      var r = parseInt(hex.slice(0, 2), 16)
      var g = parseInt(hex.slice(2, 4), 16)
      var b = parseInt(hex.slice(4, 6), 16)
      return r > 220 && g > 220 && b > 220
    }
    for (var r = 0; r < roots.length; r++) {
      var root = roots[r]
      if (!root) continue
      var nodes = root.querySelectorAll(
        '.x-panel, .x-container, .x-panel-body, .x-fieldset, fieldset, .myborder, .x-grid-view, .x-grid-body, .x-grid-empty, .x-grid-header-ct, .x-column-header, .bgimport, [style*="background"]',
      )
      for (var i = 0; i < nodes.length; i++) {
        var el = nodes[i]
        if (styleLooksWhite(el.getAttribute('style'))) paintDark(el)
      }
      // Empty-state rows / fieldsets / chart panels — force dark even without inline white
      var force = root.querySelectorAll(
        '.x-grid-empty, .x-grid-empty-text, .x-fieldset, fieldset, .x-fieldset-body, .x-fieldset-header, .bgimport',
      )
      for (var f = 0; f < force.length; f++) paintDark(force[f])
    }
    restyleDashboardChartsForTheme('dark')
  }

  function repairDashboardChartLayout() {
    try {
      if (typeof Ext === 'undefined' || !Ext.getCmp) return
      // Clear accidental 48px crush from Device Usage chrome walk
      var crushed = document.querySelectorAll(
        '#DashboardCard .pa-section-title-bar, #DashboardCard .pa-flat-device-usage-bar, #DashboardCard .pa-banner-ancestor',
      )
      for (var i = 0; i < crushed.length; i++) {
        var n = crushed[i]
        if (n.querySelector && n.querySelector('#appidchart, #appidchart1, #DashboardRadarChart')) {
          n.style.removeProperty('height')
          n.style.removeProperty('max-height')
          n.style.removeProperty('min-height')
          n.classList.remove('pa-section-title-bar', 'pa-flat-device-usage-bar')
        }
      }

      var cardEl = document.getElementById('DashboardCard-body') || document.getElementById('DashboardCard')
      var avail = cardEl ? Math.floor(cardEl.getBoundingClientRect().width) : 0
      if (avail < 200) return

      var a = Ext.getCmp('appidchart')
      if (!a) return
      // polar → wrap panel → hbox row
      var wrap = a.ownerCt
      var row = wrap && wrap.ownerCt
      var cellW = Math.max(220, Math.floor((avail - 48) / 3))
      var rowH = 300

      if (row) {
        try {
          if (row.setSize) row.setSize(avail - 8, rowH)
          else {
            if (row.setWidth) row.setWidth(avail - 8)
            if (row.setHeight) row.setHeight(rowH)
          }
          var rowEl = row.getEl && row.getEl()
          if (rowEl && rowEl.dom) {
            rowEl.dom.style.setProperty('width', avail - 8 + 'px', 'important')
            rowEl.dom.style.setProperty('height', rowH + 'px', 'important')
            rowEl.dom.style.setProperty('min-width', avail - 8 + 'px', 'important')
            rowEl.dom.style.setProperty('max-width', '100%', 'important')
          }
          if (row.updateLayout) row.updateLayout(true)
        } catch (eRow) {
          /* ignore */
        }
      }

      ;['appidchart', 'appidchart1', 'DashboardRadarChart'].forEach(function (id) {
        var chart = Ext.getCmp(id)
        if (!chart) return
        try {
          var parent = chart.ownerCt
          if (parent) {
            if (parent.setSize) parent.setSize(cellW, rowH)
            var pEl = parent.getEl && parent.getEl()
            if (pEl && pEl.dom) {
              pEl.dom.style.setProperty('width', cellW + 'px', 'important')
              pEl.dom.style.setProperty('height', rowH + 'px', 'important')
              pEl.dom.style.setProperty('max-width', cellW + 'px', 'important')
            }
            if (parent.updateLayout) parent.updateLayout(true)
          }
          var chartW = Math.max(200, cellW - 12)
          var chartH = id === 'DashboardRadarChart' ? 250 : 260
          if (chart.setSize) chart.setSize(chartW, chartH)
          var host = chart.getEl && chart.getEl()
          if (host && host.dom) {
            host.dom.style.setProperty('width', chartW + 'px', 'important')
            host.dom.style.setProperty('height', chartH + 'px', 'important')
            host.dom.style.setProperty('max-width', chartW + 'px', 'important')
            host.dom.style.setProperty('min-height', '200px', 'important')
          }
          if (chart.updateLayout) chart.updateLayout(true)
          // Surfaces often stay 0×0 after a crushed layout — size them explicitly
          try {
            if (chart.surfaceMap && Ext.Object && Ext.Object.each) {
              Ext.Object.each(chart.surfaceMap, function (key, surf) {
                if (!surf) return
                if (surf.setSize) surf.setSize(chartW, chartH)
                else if (surf.setWidth && surf.setHeight) {
                  surf.setWidth(chartW)
                  surf.setHeight(chartH)
                }
                if (surf.renderFrame) surf.renderFrame()
              })
            } else if (chart.getSurface) {
              var surf = chart.getSurface()
              if (surf && surf.setSize) surf.setSize(chartW, chartH)
              if (surf && surf.renderFrame) surf.renderFrame()
            }
          } catch (eSurf) {
            /* ignore */
          }
          if (chart.redraw) chart.redraw()
          if (chart.renderFrame) chart.renderFrame()
        } catch (eC) {
          /* ignore */
        }
      })
    } catch (e) {
      /* ignore */
    }
  }

  function restyleDashboardChartsForTheme(theme) {
    theme = theme === 'light' ? 'light' : 'dark'
    try {
      repairDashboardChartLayout()
      // Undo any prior scrub paint on chart hosts (was covering canvases)
      ;['appidchart', 'appidchart1', 'DashboardRadarChart'].forEach(function (id) {
        var host = document.getElementById(id)
        if (!host) return
        var scrubbed = host.querySelectorAll('[data-pa-dark-scrub="1"]')
        for (var s = 0; s < scrubbed.length; s++) {
          var el = scrubbed[s]
          el.style.removeProperty('background')
          el.style.removeProperty('background-color')
          el.style.removeProperty('background-image')
          el.style.removeProperty('color')
          el.removeAttribute('data-pa-dark-scrub')
        }
        if (host.getAttribute('data-pa-dark-scrub') === '1') {
          host.style.removeProperty('background')
          host.style.removeProperty('background-color')
          host.style.removeProperty('background-image')
          host.style.removeProperty('color')
          host.removeAttribute('data-pa-dark-scrub')
        }
        var surfaces = host.querySelectorAll(
          '.x-surface, .x-surface-canvas, canvas, .x-draw-container, .x-legend, .x-legend-container',
        )
        for (var u = 0; u < surfaces.length; u++) {
          surfaces[u].style.removeProperty('background')
          surfaces[u].style.removeProperty('background-color')
          surfaces[u].style.removeProperty('background-image')
          // Do not force visibility — that leaks charts onto Import when Dashboard is Ext-hidden
          surfaces[u].style.removeProperty('opacity')
          surfaces[u].style.removeProperty('visibility')
        }
        var card = host.closest('.myborder, .x-panel')
        if (card) card.classList.add('pa-basepoint-card')
        host.classList.add('pa-basepoint-chart')
      })

      if (typeof Ext === 'undefined' || !Ext.getCmp) return
      var dark = theme === 'dark'
      var titleFill = dark ? '#e8eef7' : '#64748b'
      var labelBg = dark ? 'rgba(248,250,252,0.94)' : 'rgba(255,255,255,0.96)'
      var labelFg = '#0f172a'
      // High-contrast Basepoint-ish colors — remainder must stay visible on dark cards
      var appidColors = dark ? ['#34d399', '#64748b'] : ['#10b981', '#cbd5e1']
      var useridColors = dark ? ['#60a5fa', '#64748b'] : ['#2563eb', '#cbd5e1']
      var radarColors = dark
        ? ['#34d399', '#60a5fa', '#f87171', '#fb923c', '#fbbf24', '#c084fc', '#22d3ee', '#94a3b8', '#fb923c']
        : ['#10b981', '#3b82f6', '#ef4444', '#f97316', '#eab308', '#a855f7', '#06b6d4', '#64748b', '#f97316']

      function restoreStockPieSeries(series) {
        if (!series) return
        // Previous builds mutated donut/label and blanked the canvas — put stock config back
        try {
          if (series.setDonut) series.setDonut(60)
          else if (series.setConfig) series.setConfig({ donut: 60 })
          else series.donut = 60
        } catch (e0) {
          /* ignore */
        }
        try {
          var stockLabel = {
            field: 'label',
            display: 'rotate',
            font: '12px Inter, Arial, sans-serif',
            color: dark ? '#e2e8f0' : '#334155',
          }
          if (series.setLabel) series.setLabel(stockLabel)
          else if (series.setConfig) series.setConfig({ label: stockLabel })
        } catch (e1) {
          /* ignore */
        }
        try {
          // Subtle slice gap without breaking fill
          if (series.setStyle) {
            series.setStyle({
              strokeStyle: dark ? '#1a2230' : '#ffffff',
              lineWidth: 2,
            })
          }
        } catch (e2) {
          /* ignore */
        }
      }

      function touchTitleSprites(chart) {
        try {
          var cfgSprites = chart.config && chart.config.sprites
          if (cfgSprites) {
            var cfgList = Ext.isArray(cfgSprites) ? cfgSprites : [cfgSprites]
            for (var c = 0; c < cfgList.length; c++) {
              if (cfgList[c] && cfgList[c].type === 'text') {
                cfgList[c].fillStyle = titleFill
              }
            }
          }
          // Only config-declared title sprites — never walk all surface sprites
          if (chart.sprites && chart.sprites.type === 'text' && chart.sprites.setAttributes) {
            chart.sprites.setAttributes({ fillStyle: titleFill })
          }
        } catch (e1) {
          /* ignore */
        }
      }

      function redraw(chart) {
        try {
          if (chart.redraw) chart.redraw()
          else if (chart.refresh) chart.refresh()
          else if (chart.scheduleLayout) chart.scheduleLayout()
        } catch (e2) {
          /* ignore */
        }
      }

      function ensureBadge(host, title) {
        if (!host || !title) return
        var badge = host.querySelector('.pa-pie-center-badge')
        if (!badge) {
          badge = document.createElement('div')
          badge.className = 'pa-pie-center-badge'
          host.appendChild(badge)
        }
        badge.textContent = title
        badge.style.setProperty('background', labelBg, 'important')
        badge.style.setProperty('color', labelFg, 'important')
      }

      function clearChartWhiteBg(chart) {
        if (!chart || !dark) return
        try {
          if (chart.setBackground) chart.setBackground('none')
          else chart.background = 'none'
          var bgSurf = chart.getSurface && chart.getSurface('background')
          if (bgSurf && bgSurf.removeAll) bgSurf.removeAll(true)
          if (bgSurf && bgSurf.renderFrame) bgSurf.renderFrame()
        } catch (eBg) {
          /* ignore */
        }
      }

      function touchPie(id, colors, title, doReload) {
        var chart = Ext.getCmp(id)
        if (!chart) return
        clearChartWhiteBg(chart)
        try {
          if (chart.setColors) chart.setColors(colors)
          else chart.colors = colors
        } catch (e0) {
          /* ignore */
        }
        try {
          var seriesList = chart.getSeries ? chart.getSeries() : chart.series
          restoreStockPieSeries(seriesList && seriesList[0])
        } catch (eS) {
          /* ignore */
        }
        touchTitleSprites(chart)
        try {
          var el = chart.getEl && chart.getEl()
          if (el && el.dom) {
            el.dom.classList.add('pa-basepoint-chart')
            ensureBadge(el.dom, title)
          }
        } catch (eBadge) {
          /* ignore */
        }
        if (doReload) {
          try {
            var store = chart.getStore && chart.getStore()
            if (store && store.load && !store.isLoading()) {
              store.load({
                callback: function () {
                  redraw(chart)
                },
              })
              return
            }
          } catch (eLoad) {
            /* fall through */
          }
        }
        redraw(chart)
      }

      function touchRadar(id, doReload) {
        var chart = Ext.getCmp(id)
        if (!chart) return
        clearChartWhiteBg(chart)
        try {
          if (chart.setColors) chart.setColors(radarColors)
          else chart.colors = radarColors
        } catch (e0) {
          /* ignore */
        }
        touchTitleSprites(chart)
        if (doReload) {
          try {
            var store = chart.getStore && chart.getStore()
            if (store && store.load && !store.isLoading()) {
              store.load({
                callback: function () {
                  redraw(chart)
                  paintFallbackRadar(id)
                },
              })
              return
            }
          } catch (eLoad) {
            /* fall through */
          }
        }
        redraw(chart)
        paintFallbackRadar(id)
      }

      // Soft pass every call; hard reload+restore at most every 2.5s
      var now = Date.now()
      var hard = !window._paChartHardAt || now - window._paChartHardAt > 2500
      if (hard) window._paChartHardAt = now
      touchPie('appidchart', appidColors, 'App-ID', hard)
      touchPie('appidchart1', useridColors, 'User-ID', hard)
      touchRadar('DashboardRadarChart', hard)
      restyleGaugeCharts(dark)
      if (hard) {
        setTimeout(function () {
          touchPie('appidchart', appidColors, 'App-ID', false)
          touchPie('appidchart1', useridColors, 'User-ID', false)
          touchRadar('DashboardRadarChart', false)
          restyleGaugeCharts(dark)
        }, 500)
      }
    } catch (e) {
      /* ignore */
    }
  }

  // Ext polar gauges default to theme background:'white' — kills dark UI.
  // Must use setBackground('none') — null leaves a white rect on the background surface.
  // Also re-size crushed surfaces (often land at 1×65 after layout thrash).
  function restyleGaugeCharts(dark) {
    try {
      if (typeof Ext === 'undefined' || !Ext.ComponentQuery) return
      var charts = Ext.ComponentQuery.query('polar')
      for (var i = 0; i < charts.length; i++) {
        var chart = charts[i]
        if (!chart) continue
        var seriesList = []
        try {
          seriesList = chart.getSeries ? chart.getSeries() : chart.series || []
        } catch (eS) {
          seriesList = []
        }
        var isGauge = false
        for (var s = 0; s < (seriesList.length || 0); s++) {
          var ser = seriesList[s]
          var t = (ser && (ser.type || (ser.getType && ser.getType()))) || ''
          if (String(t).toLowerCase() === 'gauge') {
            isGauge = true
            break
          }
        }
        var store = null
        try {
          store = chart.getStore && chart.getStore()
        } catch (eSt) {
          /* ignore */
        }
        var sid = (store && (store.storeId || (store.getStoreId && store.getStoreId()))) || ''
        if (!isGauge && String(sid).indexOf('SystemCPU') === -1) continue

        // Restore usable size — crushed canvases (1×N) draw nothing
        try {
          var parent = chart.ownerCt
          var wantW = 180
          var wantH = 112
          if (parent && parent.getEl && parent.getEl()) {
            var pr = parent.getEl().dom.getBoundingClientRect()
            if (pr.width > 80) wantW = Math.floor(pr.width)
            if (pr.height > 60) wantH = Math.floor(Math.max(100, pr.height - 4))
          }
          if (chart.setSize) chart.setSize(wantW, wantH)
          var host = chart.getEl && chart.getEl()
          if (host && host.dom) {
            host.dom.style.setProperty('width', wantW + 'px', 'important')
            host.dom.style.setProperty('height', wantH + 'px', 'important')
            host.dom.style.setProperty('min-width', '120px', 'important')
            host.dom.style.setProperty('min-height', '100px', 'important')
            host.dom.style.setProperty('background', 'transparent', 'important')
            host.dom.style.setProperty('background-color', 'transparent', 'important')
          }
          if (chart.surfaceMap && Ext.Object && Ext.Object.each) {
            Ext.Object.each(chart.surfaceMap, function (key, surf) {
              if (!surf) return
              if (surf.setSize) surf.setSize(wantW, wantH)
            })
          }
        } catch (eSz) {
          /* ignore */
        }

        try {
          if (dark) {
            if (chart.setBackground) chart.setBackground('none')
            else chart.background = 'none'
          } else if (chart.setBackground) {
            chart.setBackground('#ffffff')
          }
        } catch (eBg) {
          /* ignore */
        }
        // Soften track (#dfdfe1 → dark) without dropping gradient fills (url(#c1))
        try {
          if (dark) {
            var cols = chart.getColors ? chart.getColors() : chart.colors
            if (cols && cols.length >= 2) {
              var next = cols.slice()
              var last = String(next[next.length - 1] || '')
              if (last.indexOf('url(') === -1 && /#dfdfe1|#e[0-9a-f]{5}|rgb\(22[0-9]/i.test(last)) {
                next[next.length - 1] = '#2a3344'
                if (chart.setColors) chart.setColors(next)
                else chart.colors = next
              } else if (last === '#dfdfe1' || last.toLowerCase() === '#dfdfe1') {
                next[next.length - 1] = '#2a3344'
                if (chart.setColors) chart.setColors(next)
                else chart.colors = next
              } else {
                // Always retint trailing solid track when present
                if (last.charAt(0) === '#' || last.indexOf('rgb') === 0) {
                  next[next.length - 1] = '#2a3344'
                  if (chart.setColors) chart.setColors(next)
                  else chart.colors = next
                }
              }
            }
          }
        } catch (eCol) {
          /* ignore */
        }
        try {
          if (chart.redraw) chart.redraw()
          else if (chart.renderFrame) chart.renderFrame()
        } catch (eR) {
          /* ignore */
        }
      }
    } catch (e) {
      /* ignore */
    }
  }

  function ensureUserAndProjectButtonLabels() {
    try {
      if (typeof Ext === 'undefined' || !Ext.getCmp) return
      var userBtn = Ext.getCmp('username_button')
      if (userBtn && userBtn.setText) {
        var uname = ''
        try {
          uname = localStorage.getItem('username') || ''
        } catch (e) {
          /* ignore */
        }
        var cur = (userBtn.getText && userBtn.getText()) || ''
        var curPlain = String(cur).replace(/<[^>]+>/g, '').trim()
        if (!curPlain || curPlain === 'Username') {
          userBtn.setText('<b>' + (uname || 'admin') + '</b>')
        }
      }
      var projBtn = Ext.getCmp('projectsettings')
      if (projBtn && projBtn.setText) {
        var pname = ''
        try {
          if (typeof MySharedData !== 'undefined' && MySharedData.project) {
            pname = MySharedData.project
          }
        } catch (e2) {
          /* ignore */
        }
        var pcur = (projBtn.getText && projBtn.getText()) || ''
        var pPlain = String(pcur).replace(/<[^>]+>/g, '').trim()
        if (!pPlain && pname) {
          projBtn.setText('<b>' + pname + '</b>')
        }
      }
      enhanceAgentStateButtons()
    } catch (err) {
      /* ignore */
    }
  }

  // Task Manager status LEDs (agentStateGlobalButton / Button2) — display-only in stock UI;
  // restore a readable Running/Stopped chip and explain on click.
  function enhanceAgentStateButtons() {
    try {
      if (typeof Ext === 'undefined' || !Ext.getCmp) return
      // Keep chip in sync when /bin/jobs/check.php polls
      if (!window._paTmStoreHooked && Ext.getStore) {
        var st = Ext.getStore('agentStatus')
        if (st) {
          window._paTmStoreHooked = true
          st.on('load', function () {
            setTimeout(enhanceAgentStateButtons, 30)
          })
        }
      }
      ;['agentStateGlobalButton', 'agentStateGlobalButton2'].forEach(function (id) {
        var btn = Ext.getCmp(id)
        if (!btn || !btn.setText) return
        var html = String(btn.getText ? btn.getText() : '') || ''
        var stopped =
          html.indexOf('exclamation') !== -1 ||
          html.indexOf('#ce4482') !== -1 ||
          html.indexOf('fa-exclamation') !== -1
        var running =
          html.indexOf('check-circle') !== -1 ||
          html.indexOf('#5fba7d') !== -1 ||
          html.indexOf('fa-check') !== -1
        // Empty / invisible FA-only markup → force a readable chip
        var plain = html.replace(/<[^>]+>/g, '').replace(/\s+/g, '').trim()
        if (!plain || !btn.el || !btn.el.dom.querySelector('.fa, i')) {
          if (running) stopped = false
          else if (!stopped && !running) stopped = true // default unknown → stopped look
        }
        var label = running && !stopped ? 'TM Running' : 'TM Stopped'
        var color = running && !stopped ? '#34c759' : '#ff453a'
        var tip =
          (running && !stopped
            ? 'Task Manager is running.'
            : 'Task Manager is stopped.') +
          ' This is a status indicator only — start/stop it from the user menu (Start Task Manager) or Dashboard Jobs.'
        var next =
          '<span class="pa-tm-status" style="color:' +
          color +
          '"><i class="fa ' +
          (running && !stopped ? 'fa-check-circle' : 'fa-exclamation-circle') +
          '" aria-hidden="true"></i> ' +
          label +
          '</span>'
        if (html.indexOf('pa-tm-status') === -1 || html.indexOf(label) === -1) {
          btn.setText(next)
        }
        if (btn.setTooltip) btn.setTooltip(tip)
        if (btn.el && btn.el.dom) {
          btn.el.dom.setAttribute('title', tip)
          btn.el.dom.setAttribute('aria-label', tip)
          btn.el.dom.classList.add('pa-tm-status-btn')
        }
        if (!btn._paTmClickBound) {
          btn._paTmClickBound = true
          btn.on('click', function () {
            try {
              if (Ext.toast) {
                Ext.toast({
                  html: tip,
                  title: 'Task Manager State',
                  align: 't',
                  slideInDuration: 200,
                  minWidth: 280,
                })
              } else if (Ext.Msg) {
                Ext.Msg.alert('Task Manager State', tip)
              }
            } catch (e3) {
              /* ignore */
            }
          })
        }
      })
    } catch (e) {
      /* ignore */
    }
  }

  function fixAllLayouts() {
    styleLoginCard()
    fixTabPanelLayout('mainpaneltabs')
    fixTabPanelLayout('projectOptions')
    stripPanwChrome(document)
    applyIcons(document)
    hideJunkTabs(document)
    applyFlatObjectIcons(document)
    enhanceVendorTabs(document)
    enhanceProfileToolbarButtons(document)
    scrubImportAdvertising()
    flattenDeviceUsageChrome()
    scrubActiveTabUnderline()
    enhanceDashboardHero(document)
    enhanceLibraryTiles()
    polishDashboardWidgets()
    ensureUserAndProjectButtonLabels()
    scrubLightSurfacesInDarkMode()
    ensureLoginThemeToggle()
    applyLoginTheme(getLoginTheme())
    repairDashboardChartLayout()
    // Always apply Basepoint chart chrome for current theme (light or dark)
    restyleDashboardChartsForTheme(getLoginTheme())
    if (window.paConverterRepairCharts) window.paConverterRepairCharts()
    syncDashboardChartVisibility()
  }

  function whenExtReady(fn) {
    var tries = 0
    var t = setInterval(function () {
      tries++
      if (typeof Ext !== 'undefined' && typeof Ext.onReady === 'function') {
        clearInterval(t)
        Ext.onReady(fn)
      } else if (tries > 150) {
        clearInterval(t)
        fn()
      }
    }, 200)
  }

  function recreatePolarChart(id, colors, titleSprite) {
    try {
      if (typeof Ext === 'undefined' || !Ext.getCmp) return false
      var old = Ext.getCmp(id)
      if (!old || !old.ownerCt) return false
      var parent = old.ownerCt
      var store = old.getStore && old.getStore()
      var idx = parent.items ? parent.items.indexOf(old) : -1
      if (idx < 0) return false
      var dark = document.documentElement.classList.contains('pa-theme-dark')
      var avail = 0
      var cardEl = document.getElementById('DashboardCard-body')
      if (cardEl) avail = Math.floor(cardEl.getBoundingClientRect().width)
      var cellW = Math.max(220, Math.floor((Math.max(avail, 900) - 48) / 3) - 12)
      var cellH = 260
      var cfg = {
        xtype: 'polar',
        id: id,
        flex: 1,
        width: cellW,
        height: cellH,
        colors: colors,
        store: store,
        innerPadding: 20,
        sprites: {
          type: 'text',
          fillStyle: dark ? '#e8eef7' : '#64748b',
          text: titleSprite || '',
          fontSize: 16,
          width: 100,
          height: 30,
          x: 16,
          y: 28,
        },
        series: [
          {
            type: 'pie',
            angleField: 'rules',
            donut: 60,
            rotation: 90,
            label: {
              field: 'label',
              display: 'rotate',
              font: '12px Inter, Arial, sans-serif',
              color: dark ? '#e2e8f0' : '#334155',
            },
            style: {
              strokeStyle: dark ? '#1a2230' : '#ffffff',
              lineWidth: 2,
            },
            tooltip: {
              trackMouse: true,
              width: 140,
              height: 28,
              renderer: function (tool, record) {
                try {
                  tool.setHtml((record.get('label') || '') + '')
                } catch (e) {
                  /* ignore */
                }
              },
            },
          },
        ],
        interactions: [{ type: 'rotate' }],
      }
      parent.remove(old, true)
      parent.insert(idx, cfg)
      if (parent.updateLayout) parent.updateLayout(true)
      var neu = Ext.getCmp(id)
      if (neu) {
        if (neu.setSize) neu.setSize(cellW, cellH)
        if (neu.redraw) neu.redraw()
        if (store && store.getCount && store.getCount() === 0 && store.load) {
          try {
            store.load()
          } catch (eL) {
            /* ignore */
          }
        }
      }
      return true
    } catch (e) {
      return false
    }
  }

  function paintSvgDonut(host, records, colors, title, dark) {
    if (!host) return false
    var w = Math.max(180, Math.floor(host.getBoundingClientRect().width) || 320)
    var h = Math.max(180, Math.floor(host.getBoundingClientRect().height) || 240)
    var cx = w / 2
    var cy = h / 2 + 6
    var R = Math.min(w, h) * 0.36
    var r = R * 0.58
    var total = 0
    var i
    for (i = 0; i < records.length; i++) total += Number(records[i].rules) || 0
    if (total <= 0) {
      records = [
        { rules: 1, label: 'No data' },
        { rules: 1, label: '' },
      ]
      total = 2
      colors = dark ? ['#334155', '#1f2937'] : ['#cbd5e1', '#e2e8f0']
    }
    var gap = 0.04
    var angle = -Math.PI / 2
    var paths = []
    var pills = []
    for (i = 0; i < records.length; i++) {
      var val = Number(records[i].rules) || 0
      var slice = (val / total) * Math.PI * 2
      var a0 = angle + gap / 2
      var a1 = angle + slice - gap / 2
      if (a1 <= a0) a1 = a0 + 0.01
      function pt(rad, a) {
        return [cx + rad * Math.cos(a), cy + rad * Math.sin(a)]
      }
      var p0 = pt(R, a0)
      var p1 = pt(R, a1)
      var p2 = pt(r, a1)
      var p3 = pt(r, a0)
      var large = slice - gap > Math.PI ? 1 : 0
      var d =
        'M' +
        p0[0] +
        ' ' +
        p0[1] +
        ' A' +
        R +
        ' ' +
        R +
        ' 0 ' +
        large +
        ' 1 ' +
        p1[0] +
        ' ' +
        p1[1] +
        ' L' +
        p2[0] +
        ' ' +
        p2[1] +
        ' A' +
        r +
        ' ' +
        r +
        ' 0 ' +
        large +
        ' 0 ' +
        p3[0] +
        ' ' +
        p3[1] +
        ' Z'
      var color = colors[i % colors.length]
      paths.push('<path d="' + d + '" fill="' + color + '" stroke="none"></path>')
      var mid = (a0 + a1) / 2
      var lx = cx + ((R + r) / 2) * Math.cos(mid)
      var ly = cy + ((R + r) / 2) * Math.sin(mid)
      var pct = ((val / total) * 100).toFixed(1) + '%'
      var count = Math.round(val).toLocaleString()
      pills.push(
        '<g transform="translate(' +
          lx +
          ',' +
          ly +
          ')">' +
          '<rect x="-28" y="-16" width="56" height="32" rx="8" fill="' +
          (dark ? 'rgba(248,250,252,0.95)' : 'rgba(255,255,255,0.96)') +
          '" stroke="' +
          (dark ? 'rgba(15,23,42,0.08)' : 'rgba(15,23,42,0.06)') +
          '"/>' +
          '<text text-anchor="middle" y="-2" font-family="Inter,system-ui,sans-serif" font-size="11" font-weight="700" fill="#0f172a">' +
          count +
          '</text>' +
          '<text text-anchor="middle" y="12" font-family="Inter,system-ui,sans-serif" font-size="10" fill="#64748b">' +
          pct +
          '</text>' +
          '</g>',
      )
      angle += slice
    }
    var legend = ''
    for (i = 0; i < records.length; i++) {
      if (!records[i].label) continue
      legend +=
        '<div class="pa-svg-pie-legend-item"><span class="pa-svg-pie-swatch" style="background:' +
        colors[i % colors.length] +
        '"></span>' +
        String(records[i].label).replace(/</g, '') +
        '</div>'
    }
    var mount = host.querySelector('.pa-svg-pie')
    if (!mount) {
      mount = document.createElement('div')
      mount.className = 'pa-svg-pie'
      host.appendChild(mount)
    }
    mount.innerHTML =
      '<div class="pa-svg-pie-title">' +
      (title || '') +
      '</div>' +
      '<div class="pa-svg-pie-legend">' +
      legend +
      '</div>' +
      '<svg viewBox="0 0 ' +
      w +
      ' ' +
      h +
      '" width="100%" height="' +
      h +
      '" role="img" aria-label="' +
      (title || 'chart') +
      '">' +
      paths.join('') +
      pills.join('') +
      '</svg>'
    return true
  }

  function paintFallbackPies() {
    var dark = document.documentElement.classList.contains('pa-theme-dark')
    var pairs = [
      ['appidchart', dark ? ['#34d399', '#64748b'] : ['#10b981', '#cbd5e1'], 'App-ID'],
      ['appidchart1', dark ? ['#60a5fa', '#64748b'] : ['#2563eb', '#cbd5e1'], 'User-ID'],
    ]
    for (var p = 0; p < pairs.length; p++) {
      var id = pairs[p][0]
      var colors = pairs[p][1]
      var title = pairs[p][2]
      var host = document.getElementById(id)
      if (!host) continue
      host.classList.add('pa-basepoint-chart', 'pa-svg-pie-host')
      // Hide dead Ext surface chrome; keep host for sizing
      var body = document.getElementById(id + '-body')
      if (body) body.style.setProperty('opacity', '0', 'important')
      var records = []
      try {
        var cmp = Ext.getCmp(id)
        var store = cmp && cmp.getStore && cmp.getStore()
        if (store && store.each) {
          store.each(function (rec) {
            records.push({
              rules: Number(rec.get('rules')) || 0,
              label: rec.get('label') || '',
            })
          })
        }
      } catch (e) {
        /* ignore */
      }
      paintSvgDonut(host, records, colors, title, dark)
    }
  }

  function paintFallbackRadar(id) {
    id = id || 'DashboardRadarChart'
    var host = document.getElementById(id)
    if (!host) return false
    var dark = document.documentElement.classList.contains('pa-theme-dark')
    var canvas = host.querySelector('canvas')
    var alive = false
    if (canvas && canvas.width > 10 && canvas.height > 10) {
      try {
        var ctx = canvas.getContext('2d')
        var data = ctx.getImageData(0, 0, Math.min(canvas.width, 40), Math.min(canvas.height, 40)).data
        for (var i = 0; i < data.length; i += 16) {
          if (data[i + 3] > 10 && (data[i] > 20 || data[i + 1] > 20 || data[i + 2] > 20)) {
            alive = true
            break
          }
        }
      } catch (e) {
        /* ignore */
      }
    }
    if (alive) {
      var old = host.querySelector('.pa-svg-radar')
      if (old) old.remove()
      return false
    }
    host.classList.add('pa-basepoint-chart', 'pa-svg-pie-host')
    var body = document.getElementById(id + '-body')
    if (body) body.style.setProperty('opacity', '0', 'important')
    var values = []
    var labels = []
    try {
      var cmp = Ext.getCmp(id)
      var store = cmp && cmp.getStore && cmp.getStore()
      if (store && store.each) {
        store.each(function (rec) {
          var keys = rec.getFields ? rec.getFields() : null
          // Best-practice radar stores often use named axes
          var data = rec.getData ? rec.getData() : rec.data
          if (!data) return
          Object.keys(data).forEach(function (k) {
            if (k === 'id' || k === 'name' || k === 'label') return
            var n = Number(data[k])
            if (!isNaN(n)) {
              if (labels.indexOf(k) === -1) labels.push(k)
            }
          })
        })
        if (labels.length) {
          store.each(function (rec) {
            var row = []
            for (var li = 0; li < labels.length; li++) {
              row.push(Number(rec.get(labels[li])) || 0)
            }
            values.push(row)
          })
        }
      }
    } catch (e2) {
      /* ignore */
    }
    if (!labels.length) {
      labels = ['Security', 'Network', 'Decryption', 'App-ID', 'User-ID', 'WildFire']
      values = [[0.7, 0.55, 0.4, 0.8, 0.6, 0.5]]
    }
    var w = Math.max(200, Math.floor(host.getBoundingClientRect().width) || 320)
    var h = Math.max(200, Math.floor(host.getBoundingClientRect().height) || 240)
    var cx = w / 2
    var cy = h / 2 + 8
    var R = Math.min(w, h) * 0.32
    var n = labels.length
    var rings = ''
    var axes = ''
    var ri
    for (ri = 1; ri <= 4; ri++) {
      var rr = (R * ri) / 4
      var pts = []
      for (var a = 0; a < n; a++) {
        var ang = -Math.PI / 2 + (a * 2 * Math.PI) / n
        pts.push(cx + rr * Math.cos(ang) + ',' + (cy + rr * Math.sin(ang)))
      }
      rings +=
        '<polygon points="' +
        pts.join(' ') +
        '" fill="none" stroke="' +
        (dark ? 'rgba(148,163,184,0.25)' : 'rgba(100,116,139,0.3)') +
        '" stroke-width="1"/>'
    }
    for (var ai = 0; ai < n; ai++) {
      var ang2 = -Math.PI / 2 + (ai * 2 * Math.PI) / n
      var x2 = cx + R * Math.cos(ang2)
      var y2 = cy + R * Math.sin(ang2)
      axes +=
        '<line x1="' +
        cx +
        '" y1="' +
        cy +
        '" x2="' +
        x2 +
        '" y2="' +
        y2 +
        '" stroke="' +
        (dark ? 'rgba(148,163,184,0.35)' : 'rgba(100,116,139,0.35)') +
        '" stroke-width="1"/>'
      var lx = cx + (R + 16) * Math.cos(ang2)
      var ly = cy + (R + 16) * Math.sin(ang2)
      axes +=
        '<text x="' +
        lx +
        '" y="' +
        ly +
        '" text-anchor="middle" dominant-baseline="middle" font-family="Inter,system-ui,sans-serif" font-size="10" fill="' +
        (dark ? '#cbd5e1' : '#64748b') +
        '">' +
        String(labels[ai]).replace(/</g, '').slice(0, 14) +
        '</text>'
    }
    var polys = ''
    var palette = dark
      ? ['rgba(52,211,153,0.35)', 'rgba(96,165,250,0.35)']
      : ['rgba(16,185,129,0.3)', 'rgba(37,99,235,0.3)']
    var strokes = dark ? ['#34d399', '#60a5fa'] : ['#10b981', '#2563eb']
    for (var vi = 0; vi < values.length; vi++) {
      var row = values[vi]
      var max = 1
      for (var m = 0; m < row.length; m++) if (row[m] > max) max = row[m]
      var ppts = []
      for (var pi = 0; pi < n; pi++) {
        var v = (row[pi] || 0) / max
        var ang3 = -Math.PI / 2 + (pi * 2 * Math.PI) / n
        ppts.push(cx + R * v * Math.cos(ang3) + ',' + (cy + R * v * Math.sin(ang3)))
      }
      polys +=
        '<polygon points="' +
        ppts.join(' ') +
        '" fill="' +
        palette[vi % palette.length] +
        '" stroke="' +
        strokes[vi % strokes.length] +
        '" stroke-width="2"/>'
    }
    var mount = host.querySelector('.pa-svg-radar')
    if (!mount) {
      mount = document.createElement('div')
      mount.className = 'pa-svg-radar pa-svg-pie'
      host.appendChild(mount)
    }
    mount.innerHTML =
      '<div class="pa-svg-pie-title">Best practices</div>' +
      '<svg viewBox="0 0 ' +
      w +
      ' ' +
      h +
      '" width="100%" height="' +
      h +
      '" role="img" aria-label="Best practices radar">' +
      rings +
      axes +
      polys +
      '</svg>'
    return true
  }

  function isDashboardTabActive() {
    try {
      // Prefer project tab bar when a project workspace is open (main tabs stay stale)
      var poEl = document.getElementById('projectOptions')
      var projectOpen =
        !!poEl &&
        getComputedStyle(poEl).display !== 'none' &&
        !poEl.classList.contains('x-hidden') &&
        !poEl.classList.contains('x-hide-display')
      var sel = projectOpen
        ? '#projectOptions .x-tab-active, #ProjectOptionsTabBar .x-tab-active'
        : '#mainpaneltabs .x-tab-active'
      var tabs = document.querySelectorAll(sel)
      for (var i = 0; i < tabs.length; i++) {
        var tx = String(tabs[i].textContent || '')
          .replace(/\s+/g, ' ')
          .trim()
          .toLowerCase()
        if (tx.indexOf('dashboard') !== -1) return true
      }
      if (typeof Ext !== 'undefined' && Ext.getCmp) {
        var panel = projectOpen ? Ext.getCmp('projectOptions') : Ext.getCmp('mainpaneltabs')
        if (panel && panel.getActiveTab) {
          var at = panel.getActiveTab()
          if (at) {
            var title = String(
              at.title || at.itemId || (at.getItemId && at.getItemId()) || '',
            ).toLowerCase()
            var id = String((at.getId && at.getId()) || '').toLowerCase()
            if (title.indexOf('dashboard') !== -1 || id.indexOf('dashboard') !== -1) return true
          }
        }
      }
    } catch (e) {
      /* ignore */
    }
    return false
  }

  function syncDashboardChartVisibility() {
    try {
      var active = isDashboardTabActive()
      ;['appidchart', 'appidchart1', 'DashboardRadarChart'].forEach(function (id) {
        var host = document.getElementById(id)
        if (!host) return
        var overlays = host.querySelectorAll('.pa-svg-pie, .pa-svg-radar, .pa-pie-center-badge')
        for (var i = 0; i < overlays.length; i++) {
          if (active) {
            overlays[i].style.removeProperty('display')
            overlays[i].style.removeProperty('visibility')
            overlays[i].style.removeProperty('opacity')
          } else {
            overlays[i].style.setProperty('display', 'none', 'important')
            overlays[i].style.setProperty('visibility', 'hidden', 'important')
            overlays[i].style.setProperty('opacity', '0', 'important')
          }
        }
        if (!active) {
          host.style.setProperty('visibility', 'hidden', 'important')
          host.style.setProperty('opacity', '0', 'important')
        } else {
          host.style.removeProperty('visibility')
          host.style.removeProperty('opacity')
        }
      })
    } catch (e) {
      /* ignore */
    }
  }

  window.paConverterRepairCharts = function () {
    try {
      fixTabPanelLayout('mainpaneltabs')
      fixTabPanelLayout('projectOptions')
      repairDashboardChartLayout()
      restyleDashboardChartsForTheme(getLoginTheme())
      repairDashboardChartLayout()
      paintFallbackPies()
      paintFallbackRadar('DashboardRadarChart')
      restyleGaugeCharts(document.documentElement.classList.contains('pa-theme-dark'))
      syncDashboardChartVisibility()
    } catch (e) {}
  }

  function boot() {
    document.documentElement.classList.add('pa-converter-ui')
    applyLoginTheme(getLoginTheme())
    stripPanwChrome(document)

    var obsTimer = null
    var obs = new MutationObserver(function () {
      if (obsTimer) return
      obsTimer = setTimeout(function () {
        obsTimer = null
        styleLoginCard()
        var mainBar = document.querySelector('#mainpaneltabs .x-tab-bar-left')
        if (mainBar) enhanceTabBar(mainBar, { project: false })
        var projBar = document.querySelector('#projectOptions .x-tab-bar-left, #ProjectOptionsTabBar')
        if (projBar) enhanceTabBar(projBar, { project: true })
        // If project tab bar is still horizontal, force left via Ext
        fixAllLayouts()
      }, 80)
    })
    obs.observe(document.documentElement, { childList: true, subtree: true })

    whenExtReady(function () {
      styleLoginCard()
      fixAllLayouts()
      ;[200, 500, 1000, 2000, 3500].forEach(function (ms) {
        setTimeout(function () {
          styleLoginCard()
          fixAllLayouts()
        }, ms)
      })
      window.addEventListener('resize', function () {
        styleLoginCard()
        fixAllLayouts()
      })

      try {
        ;['mainpaneltabs', 'projectOptions'].forEach(function (id) {
          var cmp = Ext.getCmp(id)
          if (!cmp || !cmp.on) return
          cmp.on('tabchange', function () {
            setTimeout(fixAllLayouts, 40)
          })
          cmp.on('afterlayout', function () {
            var w = cmp.body && cmp.body.getWidth && cmp.body.getWidth()
            if (!w || w < 50) fixAllLayouts()
          })
          cmp.on('show', function () {
            setTimeout(fixAllLayouts, 40)
          })
        })

        var card = Ext.getCmp('mainpanelcard')
        if (card && card.on) {
          card.on('afterlayout', function () {
            setTimeout(fixAllLayouts, 60)
          })
        }
      } catch (e) {
        /* ignore */
      }
    })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot)
  } else {
    boot()
  }
})()
