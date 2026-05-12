// Get API key from localStorage or prompt user
function getApiKey() {
  let key = localStorage.getItem('dlp_api_key');
  if (!key) {
    key = prompt('Enter API key (check dlp_api_key.txt file):');
    if (key) localStorage.setItem('dlp_api_key', key);
  }
  return key;
}

async function apiGet(url) {
  const key = getApiKey();
  const res = await fetch(url, { 
    headers: { 
      'Accept': 'application/json',
      'X-API-Key': key || ''
    } 
  });
  if (res.status === 401) {
    localStorage.removeItem('dlp_api_key');
    throw new Error('Invalid API key. Please refresh and enter correct key.');
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return await res.json();
}

async function apiPost(url, body) {
  const key = getApiKey();
  const res = await fetch(url, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json', 
      'Accept': 'application/json',
      'X-API-Key': key || ''
    },
    body: JSON.stringify(body || {})
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    localStorage.removeItem('dlp_api_key');
    throw new Error('Invalid API key. Please refresh and enter correct key.');
  }
  if (!res.ok) {
    const msg = data && data.error ? data.error : `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}

function setPill(isMonitoring) {
  const pill = document.getElementById('statusPill');
  if (!pill) return;
  if (isMonitoring) {
    pill.textContent = '⬤ MONITORING';
    pill.classList.remove('pill--stopped');
    pill.classList.add('pill--running');
  } else {
    pill.textContent = '⬤ STOPPED';
    pill.classList.remove('pill--running');
    pill.classList.add('pill--stopped');
  }
}

function fmtTime(ts) {
  if (!ts) return '—';
  try {
    const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString();
  } catch {
    return '—';
  }
}

async function refreshStatus() {
  const st = await apiGet('/api/status');
  setPill(!!st.is_monitoring);

  const hint = document.getElementById('statusHint');
  if (hint) {
    const last = fmtTime(st.last_scan_time);
    const network = st.network_scan || {};
    const networkLast = fmtTime(network.last_scan_time);
    const networkStats = network.stats || {};
    const networkRisks = networkStats.last_risks_found ?? networkStats.risks_found_total ?? 0;
    const networkState = network.enabled
      ? `ON (last: ${networkLast}, risks: ${networkRisks})`
      : 'OFF';
    const err = st.last_scan_error ? ` • Error: ${st.last_scan_error}` : '';
    hint.textContent = `Monitoring: ${st.is_monitoring ? 'ON' : 'OFF'} • Last file scan: ${last} • Network scan: ${networkState}${err}`;
  }

  const btnStart = document.getElementById('btnStart');
  const btnStop = document.getElementById('btnStop');
  if (btnStart && btnStop) {
    btnStart.disabled = !!st.is_monitoring;
    btnStop.disabled = !st.is_monitoring;
  }
}

async function initMonitoring() {
  console.log('Initializing monitoring page...');
  
  // Drag and drop functionality
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const transferFile = document.getElementById('transferFile');
  
  console.log('Drop zone elements:', { dropZone, fileInput, transferFile });
  
  if (dropZone && fileInput && transferFile) {
    console.log('Setting up drag and drop handlers...');
    
    // Click to browse
    dropZone.addEventListener('click', () => {
      console.log('Drop zone clicked');
      fileInput.click();
    });
    
    // File input change (from browse button)
    fileInput.addEventListener('change', (e) => {
      console.log('File input changed');
      const files = e.target.files;
      if (files.length > 0) {
        const fileName = files[0].name;
        console.log('File selected:', fileName);
        transferFile.value = `monitored_data/${fileName}`;
        showToast(`File selected: ${fileName}`, 'success');
        
        // Update drop zone text but keep structure
        dropZone.querySelector('div:first-child').textContent = '✅';
        dropZone.querySelector('div:nth-child(2)').textContent = `File selected: ${fileName}`;
        dropZone.querySelector('div:nth-child(3)').textContent = 'Click to select another file';
      }
    });
    
    // Drag over
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('drop-zone-active');
    });
    
    // Drag leave
    dropZone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('drop-zone-active');
    });
    
    // Drop
    dropZone.addEventListener('drop', (e) => {
      console.log('File dropped!');
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('drop-zone-active');
      
      const files = e.dataTransfer.files;
      console.log('Dropped files:', files);
      if (files.length > 0) {
        const fileName = files[0].name;
        console.log('Using file:', fileName);
        transferFile.value = `monitored_data/${fileName}`;
        showToast(`File dropped: ${fileName}`, 'success');
        
        // Update drop zone text but keep structure
        dropZone.querySelector('div:first-child').textContent = '✅';
        dropZone.querySelector('div:nth-child(2)').textContent = `File dropped: ${fileName}`;
        dropZone.querySelector('div:nth-child(3)').textContent = 'Click to select another file';
      }
    });
  } else {
    console.error('Drop zone elements not found!');
  }
  
  // Auto-refresh toggle
  let autoRefreshEnabled = true;
  let refreshInterval;
  
  const toggleBtn = document.getElementById('btnToggleAutoRefresh');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      autoRefreshEnabled = !autoRefreshEnabled;
      toggleBtn.textContent = autoRefreshEnabled ? '⏸ Pause Refresh' : '▶️ Resume Refresh';
      if (autoRefreshEnabled) {
        refreshInterval = setInterval(refreshStatus, 2000);
      } else {
        clearInterval(refreshInterval);
      }
    });
  }

  document.getElementById('btnStart')?.addEventListener('click', async () => {
    try {
      await apiPost('/api/start');
      await refreshStatus();
      showToast('Monitoring started', 'success');
    } catch (e) {
      showToast(`Error: ${e.message}`, 'error');
    }
  });

  document.getElementById('btnStop')?.addEventListener('click', async () => {
    try {
      await apiPost('/api/stop');
      await refreshStatus();
      showToast('Monitoring stopped', 'info');
    } catch (e) {
      showToast(`Error: ${e.message}`, 'error');
    }
  });

  document.getElementById('btnScan')?.addEventListener('click', async () => {
    const hint = document.getElementById('statusHint');
    const progressBar = document.getElementById('scanProgress');
    const progressInfo = document.getElementById('scanProgressInfo');
    
    try {
      if (hint) hint.textContent = 'Starting scan…';
      if (progressBar) {
        progressBar.style.width = '30%';
        progressBar.parentElement.style.display = 'block';
      }
      if (progressInfo) progressInfo.textContent = 'Scanning...';
      
      const scanStart = Date.now();
      await apiPost('/api/scan');
      const duration = (Date.now() - scanStart) / 1000;
      
      if (progressBar) progressBar.style.width = '100%';
      if (progressInfo) progressInfo.textContent = `Completed in ${formatDuration(duration)}`;
      
      await refreshStatus();
      showToast(`Scan completed in ${formatDuration(duration)}`, 'success');
      
      setTimeout(() => {
        if (progressBar) progressBar.parentElement.style.display = 'none';
        if (progressInfo) progressInfo.textContent = '';
      }, 3000);
    } catch (e) {
      if (progressBar) progressBar.parentElement.style.display = 'none';
      showToast(`Scan error: ${e.message}`, 'error');
    }
  });

  document.getElementById('btnNetworkScan')?.addEventListener('click', async (e) => {
    e.preventDefault();
    const out = document.getElementById('networkScanResult');
    if (out) out.textContent = 'Running network risk scan...';

    try {
      const response = await apiPost('/api/network-scan', { force: true });
      const result = response.result || {};

      if (result.status === 'completed') {
        const summary = `Network scan complete: hosts=${result.hosts_scanned || 0}, open ports=${result.open_ports_found || 0}, risks=${result.risks_found || 0}, alerts=${result.alerts_created || 0}`;
        if (out) out.textContent = summary;
        showToast(summary, (result.risks_found || 0) > 0 ? 'info' : 'success');
      } else {
        const statusMsg = `Network scan status: ${result.status || 'unknown'}`;
        if (out) out.textContent = statusMsg;
        showToast(statusMsg, 'info');
      }

      await refreshStatus();
    } catch (e) {
      const msg = `Network scan error: ${e.message}`;
      if (out) out.textContent = msg;
      showToast(msg, 'error');
    }
  });

  // Note: Transfer test handled by form submission to /action/test-transfer
  // Keeping this handler for potential future client-side implementation
  document.getElementById('btnTransfer')?.addEventListener('click', async () => {
    const file_path = document.getElementById('transferFile')?.value || '';
    const destination = document.getElementById('transferDest')?.value || '';
    const out = document.getElementById('transferResult');
    if (out) out.textContent = 'Running…';
    try {
      const r = await apiPost('/api/test-transfer', { file_path, destination });
      const msg = r.allowed ? '✓ Transfer allowed' : '✗ Transfer blocked';
      if (out) out.textContent = msg;
      showToast(msg, r.allowed ? 'success' : 'error');
    } catch (e) {
      if (out) out.textContent = `Error: ${e.message}`;
      showToast(`Error: ${e.message}`, 'error');
    }
  });

  // Quick Actions
  document.getElementById('btnQuickScanDownloads')?.addEventListener('click', async () => {
    try {
      showToast('Scanning Downloads folder...', 'info');
      await apiPost('/api/scan', { path: 'Downloads' });
      showToast('Downloads scan completed', 'success');
      await refreshStatus();
    } catch (e) {
      showToast(`Scan error: ${e.message}`, 'error');
    }
  });

  document.getElementById('btnQuickScanDocuments')?.addEventListener('click', async () => {
    try {
      showToast('Scanning Documents folder...', 'info');
      await apiPost('/api/scan', { path: 'Documents' });
    } catch (e) {
      showToast(`Scan error: ${e.message}`, 'error');
    }
  });

  await refreshStatus();
  refreshInterval = setInterval(refreshStatus, 2000);
}

async function initConfig() {
  console.log('initConfig: Starting initialization...');
  
  // Folder picker functionality
  const folderPicker = document.getElementById('folderPicker');
  const btnBrowseFolder = document.getElementById('btnBrowseFolder');
  const newPathInput = document.getElementById('newPath');
  
  console.log('initConfig: Elements found:', { 
    folderPicker: !!folderPicker, 
    btnBrowseFolder: !!btnBrowseFolder, 
    newPathInput: !!newPathInput 
  });
  
  if (btnBrowseFolder && folderPicker) {
    console.log('initConfig: Setting up folder picker');
    btnBrowseFolder.addEventListener('click', () => {
      console.log('Browse folder clicked');
      folderPicker.click();
    });
    
    folderPicker.addEventListener('change', (e) => {
      console.log('Folder picker changed, files:', e.target.files.length);
      const files = e.target.files;
      if (files.length > 0 && newPathInput) {
        // Get the directory path from the first file
        const firstFile = files[0];
        const path = firstFile.webkitRelativePath || firstFile.path || '';
        const dirPath = path.substring(0, path.lastIndexOf('/'));
        const finalPath = dirPath || firstFile.name;
        console.log('Setting path to:', finalPath);
        newPathInput.value = finalPath;
        showToast(`Folder selected: ${finalPath}`, 'success');
      }
    });
  } else {
    console.error('initConfig: Missing elements!', { btnBrowseFolder, folderPicker });
  }

  const save = async () => {
    if (!confirm('Save configuration changes?')) return;
    
    const cfg = await apiGet('/api/config');
    cfg.alert_email = document.getElementById('alertEmail')?.value || '';

    const paths = [];
    document.querySelectorAll('#pathsList [data-remove-path]')?.forEach(btn => {
      const p = btn.getAttribute('data-remove-path');
      if (p) paths.push(p);
    });

    const dests = [];
    document.querySelectorAll('#destList [data-remove-dest]')?.forEach(btn => {
      const d = btn.getAttribute('data-remove-dest');
      if (d) dests.push(d);
    });

    cfg.monitored_paths = paths;
    cfg.authorized_destinations = dests;

    const parseTargets = (raw) =>
      raw
        .split(/[\n,]+/)
        .map(v => v.trim())
        .filter(Boolean);

    const parsePorts = (raw) => {
      const uniquePorts = new Set();
      raw.split(',').forEach(v => {
        const p = parseInt(v.trim(), 10);
        if (!Number.isNaN(p)) uniquePorts.add(p);
      });
      return Array.from(uniquePorts).sort((a, b) => a - b);
    };

    const clampNumber = (value, min, max, fallback) => {
      if (!Number.isFinite(value)) return fallback;
      return Math.max(min, Math.min(max, value));
    };

    const networkScanEnabled = !!document.getElementById('networkScanEnabled')?.checked;
    const networkTargets = parseTargets(document.getElementById('networkTargets')?.value || '');
    const networkPorts = parsePorts(document.getElementById('networkPorts')?.value || '');
    const intervalInput = parseInt(document.getElementById('networkScanInterval')?.value || '900', 10);
    const timeoutInput = parseFloat(document.getElementById('networkTimeout')?.value || '0.35');
    const maxHostsInput = parseInt(document.getElementById('networkMaxHosts')?.value || '32', 10);
    const cooldownInput = parseInt(document.getElementById('networkAlertCooldown')?.value || '1800', 10);

    if (networkScanEnabled && networkTargets.length === 0) {
      showToast('Please configure at least one network target when network scan is enabled.', 'error');
      return;
    }

    if (networkScanEnabled && networkPorts.length === 0) {
      showToast('Please configure at least one network port when network scan is enabled.', 'error');
      return;
    }

    cfg.network_scan = {
      ...(cfg.network_scan || {}),
      enabled: networkScanEnabled,
      targets: networkTargets,
      ports: networkPorts,
      scan_interval_seconds: clampNumber(intervalInput, 30, 86400, 900),
      timeout_seconds: clampNumber(timeoutInput, 0.1, 5, 0.35),
      max_hosts_per_cidr: clampNumber(maxHostsInput, 1, 4096, 32),
      alert_cooldown_seconds: clampNumber(cooldownInput, 60, 86400, 1800),
    };

    const out = document.getElementById('saveConfigResult');
    if (out) {
      out.textContent = '⏳ Saving configuration...';
      out.style.color = 'var(--muted)';
    }
    try {
      await apiPost('/api/config', cfg);
      if (out) {
        out.textContent = '✅ Configuration saved successfully!';
        out.style.color = 'var(--good)';
      }
      showToast('Configuration saved successfully', 'success');
      setTimeout(() => {
        if (out) out.textContent = '';
      }, 3000);
    } catch (e) {
      if (out) {
        out.textContent = `❌ Error: ${e.message}`;
        out.style.color = 'var(--bad)';
      }
      showToast(`Save failed: ${e.message}`, 'error');
    }
  };

  document.getElementById('btnSaveConfig')?.addEventListener('click', save);

  const btnAddPath = document.getElementById('btnAddPath');
  const btnAddDest = document.getElementById('btnAddDest');
  
  console.log('initConfig: Add buttons found:', { btnAddPath: !!btnAddPath, btnAddDest: !!btnAddDest });

  if (btnAddPath) {
    btnAddPath.addEventListener('click', () => {
      console.log('Add path button clicked');
      const v = (document.getElementById('newPath')?.value || '').trim();
      console.log('Path value:', v);
      if (!v) {
        showToast('Please enter a path', 'error');
        return;
      }
      const ul = document.getElementById('pathsList');
      if (!ul) {
        console.error('pathsList not found');
        return;
      }
      
      // Remove "(none)" placeholder if exists
      const placeholder = ul.querySelector('li:only-child');
      if (placeholder && placeholder.textContent.trim() === '(none)') {
        placeholder.remove();
      }
      
      const li = document.createElement('li');
      li.className = 'list__item';
      li.innerHTML = `<span></span><button class="btn btn--xs btn--ghost" type="button" data-remove-path=""></button>`;
      li.querySelector('span').textContent = v;
      const b = li.querySelector('button');
      b.textContent = '🗑️ Remove';
      b.setAttribute('data-remove-path', v);
      ul.appendChild(li);
      document.getElementById('newPath').value = '';
      showToast(`Path added: ${v}`, 'success');
      console.log('Path added successfully');
    });
  } else {
    console.error('btnAddPath not found!');
  }

  if (btnAddDest) {
    btnAddDest.addEventListener('click', () => {
      console.log('Add destination button clicked');
      const v = (document.getElementById('newDest')?.value || '').trim();
      console.log('Destination value:', v);
      if (!v) {
        showToast('Please enter a destination', 'error');
        return;
      }
      const ul = document.getElementById('destList');
      if (!ul) {
        console.error('destList not found');
        return;
      }
      
      // Remove "(none)" placeholder if exists
      const placeholder = ul.querySelector('li:only-child');
      if (placeholder && placeholder.textContent.trim() === '(none)') {
        placeholder.remove();
      }
      
      const li = document.createElement('li');
      li.className = 'list__item';
      li.innerHTML = `<span></span><button class="btn btn--xs btn--ghost" type="button" data-remove-dest=""></button>`;
      li.querySelector('span').textContent = v;
      const b = li.querySelector('button');
      b.textContent = '🗑️ Remove';
      b.setAttribute('data-remove-dest', v);
      ul.appendChild(li);
      document.getElementById('newDest').value = '';
      showToast(`Destination added: ${v}`, 'success');
      console.log('Destination added successfully');
    });
  } else {
    console.error('btnAddDest not found!');
  }

  document.addEventListener('click', (e) => {
    let t = e.target;
    if (!(t instanceof HTMLElement)) return;
    
    // Check if clicked element or its parent button has the data attribute
    if (!t.hasAttribute('data-remove-path') && !t.hasAttribute('data-remove-dest')) {
      // Check parent button
      const parentBtn = t.closest('button[data-remove-path], button[data-remove-dest]');
      if (parentBtn) {
        t = parentBtn;
      } else {
        return;
      }
    }
    
    console.log('Remove button clicked:', t);
    
    if (t.hasAttribute('data-remove-path')) {
      const path = t.getAttribute('data-remove-path');
      console.log('Removing path:', path);
      if (confirm(`Remove path: ${path}?`)) {
        const li = t.closest('li');
        if (li) {
          li.remove();
          showToast('Path removed', 'info');
        }
      }
    } else if (t.hasAttribute('data-remove-dest')) {
      const dest = t.getAttribute('data-remove-dest');
      console.log('Removing destination:', dest);
      if (confirm(`Remove destination: ${dest}?`)) {
        const li = t.closest('li');
        if (li) {
          li.remove();
          showToast('Destination removed', 'info');
        }
      }
    }
  });

  await refreshStatus();
  setInterval(refreshStatus, 2000);
}

async function initLogs() {
  let allLogsText = '';
  
  const applyFilter = () => {
    const searchTerm = (document.getElementById('searchLogs')?.value || '').toLowerCase();
    const levelFilter = document.getElementById('filterLogLevel')?.value || '';
    const box = document.getElementById('logsBox');
    const stats = document.getElementById('logStats');
    
    if (!allLogsText) {
      if (box) box.textContent = '';
      return;
    }
    
    const lines = allLogsText.split('\n');
    let filteredLines = lines;
    
    if (searchTerm) {
      filteredLines = filteredLines.filter(line => line.toLowerCase().includes(searchTerm));
    }
    
    if (levelFilter) {
      filteredLines = filteredLines.filter(line => line.includes(levelFilter));
    }
    
    if (box) box.textContent = filteredLines.join('\n');
    if (stats) stats.textContent = `Showing ${filteredLines.length} of ${lines.length} log lines`;
  };
  
  const refresh = async () => {
    const lines = parseInt(document.getElementById('logLines')?.value || '250', 10);
    const hint = document.getElementById('logsHint');
    if (hint) hint.textContent = 'Loading…';
    try {
      const r = await apiGet(`/api/logs?lines=${encodeURIComponent(lines)}`);
      allLogsText = r.text || '';
      applyFilter();
      if (hint) hint.textContent = 'Loaded.';
      showToast('Logs refreshed', 'info');
    } catch (e) {
      if (hint) hint.textContent = `Error: ${e.message}`;
      showToast(`Error: ${e.message}`, 'error');
    }
  };

  document.getElementById('btnRefreshLogs')?.addEventListener('click', refresh);
  document.getElementById('searchLogs')?.addEventListener('input', applyFilter);
  document.getElementById('filterLogLevel')?.addEventListener('change', applyFilter);
  document.getElementById('btnClearLogFilter')?.addEventListener('click', () => {
    document.getElementById('searchLogs').value = '';
    document.getElementById('filterLogLevel').value = '';
    applyFilter();
  });
  
  await refresh();
  await refreshStatus();
  setInterval(refreshStatus, 2000);
}

async function initAlerts() {
  let allAlerts = [];
  let filteredAlerts = [];
  let currentPage = 1;
  const alertsPerPage = 20;
  let autoRefreshEnabled = true;
  let refreshInterval;
  
  const getSeverityClass = (severity) => {
    const sev = (severity || '').toUpperCase();
    if (sev === 'CRITICAL') return 'severity-critical';
    if (sev === 'HIGH') return 'severity-high';
    if (sev === 'MEDIUM') return 'severity-medium';
    if (sev === 'LOW') return 'severity-low';
    return '';
  };
  
  const renderAlerts = () => {
    const tbody = document.querySelector('#alertsTable tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    const start = (currentPage - 1) * alertsPerPage;
    const end = start + alertsPerPage;
    const pageAlerts = filteredAlerts.slice(start, end);
    
    pageAlerts.forEach((a, idx) => {
      const tr = document.createElement('tr');
      tr.className = 'alert-row';
      tr.dataset.index = start + idx;
      
      const t = (a.timestamp || '').replace('T', ' ').slice(0, 19);
      const details = a.details || {};
      
      // Create human-readable details with file size
      let detailsText = JSON.stringify(details, null, 2);
      if (details.file_size) {
        detailsText += `\\n\\nFile Size: ${formatFileSize(details.file_size)}`;
      }
      
      tr.innerHTML = `
        <td style="text-align: center;">▶</td>
        <td>${t || '—'}</td>
        <td class="${getSeverityClass(a.severity)}">${a.severity || '—'}</td>
        <td>${a.message || '—'}</td>
      `;
      
      // Create details row (hidden by default)
      const detailsRow = document.createElement('tr');
      detailsRow.className = 'alert-details-row';
      detailsRow.style.display = 'none';
      detailsRow.innerHTML = `
        <td colspan="4">
          <div class="alert-details">
            <strong>Details:</strong>
            <pre style="margin-top: 10px; white-space: pre-wrap; font-size: 12px;">${detailsText}</pre>
          </div>
        </td>
      `;
      
      // Toggle details on click
      tr.addEventListener('click', () => {
        const isExpanded = tr.classList.contains('is-expanded');
        tr.classList.toggle('is-expanded');
        detailsRow.style.display = isExpanded ? 'none' : 'table-row';
        tr.children[0].textContent = isExpanded ? '▶' : '▼';
      });
      
      tbody.appendChild(tr);
      tbody.appendChild(detailsRow);
    });
    
    // Update pagination info
    const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage) || 1;
    const paginationInfo = document.getElementById('paginationInfo');
    if (paginationInfo) {
      paginationInfo.textContent = `Page ${currentPage} of ${totalPages} (${filteredAlerts.length} alerts)`;
    }
    
    // Update pagination buttons
    document.getElementById('btnFirstPage').disabled = currentPage === 1;
    document.getElementById('btnPrevPage').disabled = currentPage === 1;
    document.getElementById('btnNextPage').disabled = currentPage === totalPages;
    document.getElementById('btnLastPage').disabled = currentPage === totalPages;
  };
  
  const filterAlerts = () => {
    const searchTerm = (document.getElementById('searchAlerts')?.value || '').toLowerCase();
    const severityFilter = document.getElementById('filterSeverity')?.value || '';
    
    filteredAlerts = allAlerts.filter(a => {
      const matchesSearch = !searchTerm || 
        (a.message || '').toLowerCase().includes(searchTerm) ||
        (a.severity || '').toLowerCase().includes(searchTerm) ||
        JSON.stringify(a.details || {}).toLowerCase().includes(searchTerm);
      
      const matchesSeverity = !severityFilter || a.severity === severityFilter;
      
      return matchesSearch && matchesSeverity;
    });
    
    currentPage = 1;
    renderAlerts();
  };

  const refresh = async () => {
    const hint = document.getElementById('alertsHint');
    if (hint) hint.textContent = 'Loading…';
    try {
      const r = await apiGet('/api/alerts');
      allAlerts = (r.alerts || []).slice().reverse();
      filterAlerts();
      if (hint) hint.textContent = `Loaded ${allAlerts.length} alerts.`;
    } catch (e) {
      if (hint) hint.textContent = `Error: ${e.message}`;
    }
  };

  // Search and filter handlers
  document.getElementById('searchAlerts')?.addEventListener('input', filterAlerts);
  document.getElementById('filterSeverity')?.addEventListener('change', filterAlerts);
  
  // Pagination handlers
  document.getElementById('btnFirstPage')?.addEventListener('click', () => {
    currentPage = 1;
    renderAlerts();
  });
  
  document.getElementById('btnPrevPage')?.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderAlerts();
    }
  });
  
  document.getElementById('btnNextPage')?.addEventListener('click', () => {
    const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
    if (currentPage < totalPages) {
      currentPage++;
      renderAlerts();
    }
  });
  
  document.getElementById('btnLastPage')?.addEventListener('click', () => {
    currentPage = Math.ceil(filteredAlerts.length / alertsPerPage) || 1;
    renderAlerts();
  });
  
  // Print handler
  document.getElementById('btnPrintAlerts')?.addEventListener('click', () => {
    window.print();
  });
  
  // Auto-refresh toggle
  const toggleBtn = document.getElementById('btnToggleAutoRefreshAlerts');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      autoRefreshEnabled = !autoRefreshEnabled;
      toggleBtn.textContent = autoRefreshEnabled ? '⏸ Pause' : '▶️ Resume';
      if (autoRefreshEnabled) {
        refreshInterval = setInterval(refresh, 5000);
      } else {
        clearInterval(refreshInterval);
      }
    });
  }

  document.getElementById('btnRefreshAlerts')?.addEventListener('click', refresh);
  document.getElementById('btnClearAlerts')?.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to clear all alerts? This action cannot be undone.')) return;
    await apiPost('/api/alerts/clear');
    await refresh();
  });

  await refresh();
  await refreshStatus();
  refreshInterval = setInterval(refresh, 5000);
  setInterval(refreshStatus, 2000);
}

// Initialize theme and keyboard shortcuts immediately
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initKeyboardShortcuts();
  });
} else {
  // DOM already loaded
  initTheme();
  initKeyboardShortcuts();
}

async function main() {
  console.log('Main function starting, DLP_PAGE =', window.DLP_PAGE);
  try {
    if (window.DLP_PAGE === 'monitoring') {
      console.log('Calling initMonitoring');
      return initMonitoring();
    }
    if (window.DLP_PAGE === 'config') {
      console.log('Calling initConfig');
      return initConfig();
    }
    if (window.DLP_PAGE === 'logs') {
      console.log('Calling initLogs');
      return initLogs();
    }
    if (window.DLP_PAGE === 'alerts') {
      console.log('Calling initAlerts');
      return initAlerts();
    }
    if (window.DLP_PAGE === 'dashboard') {
      console.log('Calling initDashboard');
      return initDashboard();
    }
    if (window.DLP_PAGE === 'advanced') {
      console.log('Calling initAdvanced');
      return initAdvanced();
    }
    console.log('No page match, calling refreshStatus');
    await refreshStatus();
  } catch (e) {
    console.error('Main function error:', e);
  }
}

// Wait for DOM to be ready, then run main
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', main);
} else {
  main();
}

async function initDashboard() {
  const refresh = async () => {
    try {
      const [reportRes, statsRes, quarantineRes] = await Promise.all([
        apiGet('/api/report'),
        apiGet('/api/statistics'),
        apiGet('/api/quarantine/status')
      ]);
      
      // Update summary cards
      document.getElementById('totalAlerts').textContent = reportRes.total_alerts || 0;
      document.getElementById('criticalAlerts').textContent = reportRes.critical_alerts || 0;
      document.getElementById('highAlerts').textContent = reportRes.high_alerts || 0;
      document.getElementById('whitelistCount').textContent = statsRes.statistics?.whitelist_count || 0;
      
      // Update scan stats
      const scanStats = statsRes.scan_stats || {};
      document.getElementById('totalScans').textContent = scanStats.total_scans || 0;
      document.getElementById('filesChecked').textContent = scanStats.files_checked || 0;
      const duration = scanStats.last_scan_duration || 0;
      document.getElementById('lastScanDuration').textContent = duration ? formatDuration(duration) : 'N/A';
      
      // Update quarantine status
      const qStatus = document.getElementById('quarantineStatus');
      if (qStatus) {
        qStatus.textContent = quarantineRes.enabled ? 'ENABLED' : 'DISABLED';
        qStatus.style.color = quarantineRes.enabled ? 'var(--good)' : 'var(--bad)';
      }
      
      // Render severity chart
      const severityBars = document.getElementById('severityBars');
      if (severityBars && statsRes.statistics?.by_severity) {
        severityBars.innerHTML = '';
        const sev = statsRes.statistics.by_severity;
        const total = Object.values(sev).reduce((a, b) => a + b, 0) || 1;
        
        Object.entries(sev).forEach(([name, count]) => {
          const pct = ((count / total) * 100).toFixed(1);
          const bar = document.createElement('div');
          bar.style.cssText = `
            display: flex; justify-content: space-between; align-items: center;
            padding: 8px; margin-bottom: 8px; border-radius: 8px;
            background: ${name === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(255,152,0,0.2)'};
            border-left: 4px solid ${name === 'CRITICAL' ? 'var(--bad)' : '#ff9800'};
          `;
          bar.innerHTML = `<span>${name}</span><span>${count} (${pct}%)</span>`;
          severityBars.appendChild(bar);
        });
      }
      
      // Render pattern chart
      const patternBars = document.getElementById('patternBars');
      if (patternBars && statsRes.statistics?.by_pattern) {
        patternBars.innerHTML = '';
        const patterns = statsRes.statistics.by_pattern;
        const total = Object.values(patterns).reduce((a, b) => a + b, 0) || 1;
        
        Object.entries(patterns).sort((a, b) => b[1] - a[1]).forEach(([name, count]) => {
          const pct = ((count / total) * 100).toFixed(1);
          const bar = document.createElement('div');
          bar.style.cssText = `
            display: flex; justify-content: space-between; align-items: center;
            padding: 8px; margin-bottom: 8px; border-radius: 8px;
            background: rgba(34,197,94,0.2); border-left: 4px solid var(--good);
          `;
          bar.innerHTML = `<span>${name}</span><span>${count} (${pct}%)</span>`;
          patternBars.appendChild(bar);
        });
      }
    } catch (e) {
      console.error('Dashboard refresh error:', e);
    }
  };
  
  document.getElementById('btnExportCSV')?.addEventListener('click', async () => {
    const status = document.getElementById('exportStatus');
    try {
      if (status) status.textContent = 'Exporting...';
      const r = await apiGet('/api/export/csv');
      if (status) status.textContent = `✓ Exported to ${r.file}`;
    } catch (e) {
      if (status) status.textContent = `Error: ${e.message}`;
    }
  });
  
  document.getElementById('btnExportJSON')?.addEventListener('click', async () => {
    const status = document.getElementById('exportStatus');
    try {
      if (status) status.textContent = 'Exporting...';
      const r = await apiGet('/api/export/json');
      if (status) status.textContent = `✓ Exported to ${r.file}`;
    } catch (e) {
      if (status) status.textContent = `Error: ${e.message}`;
    }
  });
  
  document.getElementById('btnToggleQuarantine')?.addEventListener('click', async () => {
    try {
      const current = await apiGet('/api/quarantine/status');
      if (current.enabled) {
        await apiPost('/api/quarantine/disable');
      } else {
        await apiPost('/api/quarantine/enable');
      }
      await refresh();
    } catch (e) {
      console.error('Quarantine toggle error:', e);
    }
  });
  
  await refresh();
  await refreshStatus();
  setInterval(refresh, 5000);
  setInterval(refreshStatus, 2000);
}

async function initAdvanced() {
  const refreshWhitelist = async () => {
    try {
      const r = await apiGet('/api/whitelist');
      const ul = document.getElementById('whitelistList');
      if (!ul) return;
      ul.innerHTML = '';
      (r.whitelist || []).forEach(item => {
        const li = document.createElement('li');
        li.className = 'list__item';
        li.innerHTML = `<span></span><button class="btn btn--xs btn--ghost">Remove</button>`;
        li.querySelector('span').textContent = item;
        li.querySelector('button').addEventListener('click', async () => {
          await apiPost('/api/whitelist/remove', { item });
          await refreshWhitelist();
        });
        ul.appendChild(li);
      });
    } catch (e) {
      console.error('Whitelist refresh error:', e);
    }
  };
  
  const refreshQuarantine = async () => {
    try {
      const r = await apiGet('/api/quarantine/status');
      const status = document.getElementById('quarantineStatusAdv');
      const btn = document.getElementById('btnToggleQuarantineAdv');
      if (status) {
        status.textContent = r.enabled ? 'ENABLED' : 'DISABLED';
        status.style.color = r.enabled ? 'var(--good)' : 'var(--bad)';
      }
      if (btn) {
        btn.textContent = r.enabled ? 'Disable Quarantine' : 'Enable Quarantine';
      }
    } catch (e) {
      console.error('Quarantine status error:', e);
    }
  };
  
  document.getElementById('btnAddWhitelist')?.addEventListener('click', async () => {
    const input = document.getElementById('whitelistInput');
    const hint = document.getElementById('whitelistHint');
    const item = input?.value?.trim();
    if (!item) return;
    try {
      if (hint) hint.textContent = 'Adding...';
      await apiPost('/api/whitelist/add', { item });
      if (input) input.value = '';
      if (hint) hint.textContent = '✓ Added to whitelist';
      await refreshWhitelist();
    } catch (e) {
      if (hint) hint.textContent = `Error: ${e.message}`;
    }
  });
  
  document.getElementById('btnToggleQuarantineAdv')?.addEventListener('click', async () => {
    try {
      const current = await apiGet('/api/quarantine/status');
      if (current.enabled) {
        await apiPost('/api/quarantine/disable');
      } else {
        await apiPost('/api/quarantine/enable');
      }
      await refreshQuarantine();
    } catch (e) {
      console.error('Quarantine toggle error:', e);
    }
  });
  
  document.getElementById('btnCreateBackup')?.addEventListener('click', async () => {
    const status = document.getElementById('backupStatus');
    try {
      if (status) status.textContent = 'Creating backup...';
      const r = await apiPost('/api/backup/create');
      if (status) status.textContent = `✓ Backup created: ${r.backup_file}`;
    } catch (e) {
      if (status) status.textContent = `Error: ${e.message}`;
    }
  });
  
  document.getElementById('btnRestoreBackup')?.addEventListener('click', async () => {
    const input = document.getElementById('restoreFile');
    const status = document.getElementById('backupStatus');
    const file = input?.value?.trim();
    if (!file) {
      if (status) status.textContent = 'Please enter backup file path';
      return;
    }
    if (!confirm('Are you sure? This will restore configuration from backup.')) return;
    try {
      if (status) status.textContent = 'Restoring...';
      await apiPost('/api/backup/restore', { backup_file: file });
      if (status) status.textContent = '✓ Backup restored successfully';
    } catch (e) {
      if (status) status.textContent = `Error: ${e.message}`;
    }
  });
  
  document.getElementById('btnClearAllAlerts')?.addEventListener('click', async () => {
    if (!confirm('Clear all alerts?')) return;
    const status = document.getElementById('actionStatus');
    try {
      await apiPost('/api/alerts/clear');
      if (status) status.textContent = '✓ All alerts cleared';
    } catch (e) {
      if (status) status.textContent = `Error: ${e.message}`;
    }
  });
  
  document.getElementById('btnViewQuarantine')?.addEventListener('click', () => {
    alert('Quarantine folder: ./quarantine/\\nOpen this folder in your file explorer.');
  });

  document.getElementById('btnExportConfigAdv')?.addEventListener('click', async () => {
    try {
      const cfg = await apiGet('/api/config');
      const json = JSON.stringify(cfg, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dlp_config_export_${new Date().toISOString().slice(0,10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Configuration exported successfully', 'success');
    } catch (e) {
      showToast(`Export failed: ${e.message}`, 'error');
    }
  });
  
  await refreshWhitelist();
  await refreshQuarantine();
  await refreshStatus();
  setInterval(refreshStatus, 2000);
}

// Toast Notification System
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  const icons = { success: '✓', error: '✗', info: 'ℹ' };
  toast.innerHTML = `
    <div class="toast-icon">${icons[type] || 'ℹ'}</div>
    <div class="toast-message">${message}</div>
  `;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideIn 0.3s ease reverse';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Format file size
function formatFileSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Format duration
function formatDuration(seconds) {
  if (!seconds || seconds < 1) return '< 1s';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

// Theme Toggle
function initTheme() {
  const toggle = document.getElementById('themeToggle');
  if (!toggle) {
    console.log('Theme toggle button not found');
    return;
  }
  
  console.log('Theme toggle initialized');
  const theme = localStorage.getItem('theme') || 'dark';
  console.log('Current theme:', theme);
  
  if (theme === 'light') {
    document.documentElement.classList.add('light-mode');
    toggle.textContent = '☀️';
  } else {
    toggle.textContent = '🌙';
  }
  
  toggle.addEventListener('click', () => {
    const isLight = document.documentElement.classList.toggle('light-mode');
    toggle.textContent = isLight ? '☀️' : '🌙';
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    console.log('Theme switched to:', isLight ? 'light' : 'dark');
    // Show toast if function is available
    if (typeof showToast === 'function') {
      showToast(`Switched to ${isLight ? 'light' : 'dark'} mode`, 'info');
    }
  });
}

// Keyboard Shortcuts
function initKeyboardShortcuts() {
  document.addEventListener('keydown', async (e) => {
    // Ctrl+S: Start monitoring
    if (e.ctrlKey && e.key === 's') {
      e.preventDefault();
      const btnStart = document.getElementById('btnStart');
      if (btnStart && !btnStart.disabled) {
        btnStart.click();
      }
    }
    // Ctrl+X: Stop monitoring
    if (e.ctrlKey && e.key === 'x') {
      e.preventDefault();
      const btnStop = document.getElementById('btnStop');
      if (btnStop && !btnStop.disabled) {
        btnStop.click();
      }
    }
  });
}
