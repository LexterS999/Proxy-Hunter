#!/usr/bin/env python3
"""
Генератор HTML-отчёта для Proxy Channel Dashboard.
Создаёт файл assets/performance_report.html с динамической загрузкой данных из configs/channel_stats.json.
"""

import os
import json
from datetime import datetime

# Путь к выходному файлу (относительно корня проекта)
OUTPUT_PATH = os.path.join("assets", "performance_report.html")

# Исправленный HTML-шаблон (без пагинации, с обработкой CORS)
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy Channel Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #f1f5f9; font-family: system-ui, -apple-system, sans-serif; padding: 20px; color: #0f172a; }
    .container { max-width: 1300px; margin: 0 auto; }
    .card { background: white; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.06); padding: 24px; margin-bottom: 24px; }
    .header { text-align: center; }
    .header h1 { font-size: 28px; font-weight: 700; }
    .header .sub { font-size: 14px; color: #475569; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap: 16px; margin-bottom: 20px; }
    .stat-item { background: #f8fafc; padding: 16px; border-radius: 12px; text-align: center; }
    .stat-item .value { font-size: 28px; font-weight: 700; }
    .stat-item .label { font-size: 13px; color: #64748b; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th { background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 600; color: #334155; user-select: none; cursor: pointer; }
    th:hover { background: #e2e8f0; }
    td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }
    .badge { display: inline-block; padding: 2px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
    .badge.active { background: #dcfce7; color: #166534; }
    .badge.inactive { background: #fee2e2; color: #991b1b; }
    .score { font-weight: 600; }
    .score.high { color: #16a34a; }
    .score.mid { color: #ca8a04; }
    .score.low { color: #dc2626; }
    .progress { background: #e2e8f0; border-radius: 20px; height: 6px; width: 100px; display: inline-block; vertical-align: middle; margin-left: 6px; }
    .progress .fill { height: 100%; border-radius: 20px; transition: width 0.2s; }
    .proto-icons { letter-spacing: 2px; font-size: 16px; white-space: nowrap; }
    .clickable-row { cursor: pointer; transition: background 0.15s; }
    .clickable-row:hover { background: #f1f5f9; }
    .ping-fast { background: #dcfce7; color: #166534; font-weight: 500; border-radius: 4px; padding: 2px 8px; display: inline-block; }
    .ping-mid { background: #fef9c3; color: #854d0e; font-weight: 500; border-radius: 4px; padding: 2px 8px; display: inline-block; }
    .ping-slow { background: #fee2e2; color: #991b1b; font-weight: 500; border-radius: 4px; padding: 2px 8px; display: inline-block; }
    .modal-overlay { position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.4); display:none; align-items:center; justify-content:center; z-index:1000; }
    .modal-overlay.active { display:flex; }
    .modal { background: white; border-radius: 16px; padding: 32px; max-width: 480px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.2); }
    .modal .close { float: right; background: none; border: none; font-size: 24px; cursor: pointer; color: #94a3b8; }
    .modal .detail-item { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #f1f5f9; }
    .modal .detail-item .label { color: #64748b; }
    .toolbar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; align-items: center; }
    .toolbar select, .toolbar input { padding: 6px 12px; border: 1px solid #e2e8f0; border-radius: 8px; background: white; font-size: 14px; }
    .toolbar input { min-width: 180px; }
    .btn { background: #e2e8f0; border: none; padding: 6px 18px; border-radius: 40px; font-size: 14px; cursor: pointer; transition: 0.2s; }
    .btn:hover { background: #cbd5e1; }
    .btn-primary { background: #2563eb; color: white; }
    .btn-primary:hover { background: #1d4ed8; }
    .error-message { background: #fee2e2; color: #991b1b; padding: 16px; border-radius: 12px; margin-bottom: 16px; text-align: center; }
    .footer { text-align: center; font-size: 13px; color: #94a3b8; margin-top: 12px; }
  </style>
</head>
<body>
<div class="container">
  <div class="card header">
    <h1>📡 Proxy Channel Dashboard</h1>
    <div class="sub" id="timestamp">Загрузка данных…</div>
  </div>

  <div class="stats" id="stats"></div>

  <div class="card">
    <div id="errorContainer" class="error-message" style="display:none;"></div>
    <div class="toolbar">
      <select id="statusFilter"><option value="all">All status</option><option value="active">Active</option><option value="inactive">Inactive</option></select>
      <input type="text" id="searchInput" placeholder="🔍 Search channel...">
      <button class="btn btn-primary" id="exportCsvBtn">📥 Export CSV</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th data-sort="name">Channel</th>
            <th data-sort="status">Status</th>
            <th data-sort="score">Score</th>
            <th data-sort="resp">Response</th>
            <th data-sort="valid">Valid / Total</th>
            <th>Protocols</th>
            <th data-sort="last">Last OK</th>
          </tr>
        </thead>
        <tbody id="table-body"></tbody>
      </table>
    </div>
  </div>
  <div class="footer">Data from channel_stats.json · Auto-refreshes on page load</div>
</div>

<!-- Modal -->
<div class="modal-overlay" id="modalOverlay">
  <div class="modal">
    <button class="close" id="modalClose">&times;</button>
    <h2 id="modalTitle">Channel details</h2>
    <div id="modalBody"></div>
  </div>
</div>

<script>
  let allData = [];
  let sortKey = null, sortAsc = true;
  const tbody = document.getElementById('table-body');
  const modal = document.getElementById('modalOverlay');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const errorContainer = document.getElementById('errorContainer');

  const PROTO_ICONS = {
    'vless://': '🔷', 'vmess://': '🔶', 'trojan://': '⚡',
    'ss://': '📦', 'hysteria2://': '🔹', 'wireguard://': '🟢', 'tuic://': '🟣'
  };

  function getProtoIcons(metrics) {
    const counts = metrics?.protocol_counts || {};
    return Object.entries(counts).filter(([k,v]) => v > 0).map(([k]) => PROTO_ICONS[k] || '•').join('');
  }

  function timeAgo(date) {
    if (!date) return '—';
    const diff = (Date.now() - new Date(date).getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff/60)+'m ago';
    if (diff < 86400) return Math.floor(diff/3600)+'h ago';
    if (diff < 604800) return Math.floor(diff/86400)+'d ago';
    return new Date(date).toLocaleDateString();
  }

  function getScoreClass(score) { return score >= 90 ? 'high' : score >= 70 ? 'mid' : 'low'; }

  function getPingClass(resp) {
    if (resp < 0.5) return 'ping-fast';
    if (resp < 1.0) return 'ping-mid';
    return 'ping-slow';
  }

  function renderRow(c) {
    const m = c.metrics || {};
    const score = m.overall_score || 0;
    const valid = m.valid_configs || 0;
    const total = m.total_configs || 0;
    const pct = total > 0 ? (valid / total * 100) : 0;
    const color = pct > 80 ? '#16a34a' : pct > 50 ? '#ca8a04' : '#dc2626';
    const resp = m.avg_response_time || 0;
    const status = c.enabled ? 'Active' : 'Inactive';
    const badgeClass = c.enabled ? 'active' : 'inactive';
    const protoIcons = getProtoIcons(m);
    const lastOk = timeAgo(m.last_success);
    const pingClass = getPingClass(resp);

    const tr = document.createElement('tr');
    tr.className = 'clickable-row';
    tr.innerHTML = `
      <td><strong>${c.url?.replace('https://t.me/s/', '') || '—'}</strong></td>
      <td><span class="badge ${badgeClass}">${status}</span></td>
      <td><span class="score ${getScoreClass(score)}">${score.toFixed(1)}%</span></td>
      <td><span class="${pingClass}">${resp.toFixed(2)}s</span></td>
      <td>${valid}/${total} <span class="progress"><span class="fill" style="width:${pct}%;background:${color}"></span></span></td>
      <td class="proto-icons">${protoIcons || '—'}</td>
      <td>${lastOk}</td>
    `;
    tr.addEventListener('click', () => showModal(c));
    return tr;
  }

  function showModal(c) {
    const m = c.metrics || {};
    modalTitle.textContent = c.url?.replace('https://t.me/s/', '') || 'Unknown';
    const protocols = Object.entries(m.protocol_counts || {}).filter(([k,v]) => v > 0).map(([k,v]) => `${PROTO_ICONS[k]||''} ${k.replace('://','')}: ${v}`).join('<br>') || '—';
    modalBody.innerHTML = `
      <div class="detail-item"><span class="label">Status</span><span>${c.enabled ? '✅ Active' : '❌ Inactive'}</span></div>
      <div class="detail-item"><span class="label">Overall Score</span><span>${(m.overall_score||0).toFixed(1)}%</span></div>
      <div class="detail-item"><span class="label">Valid / Total</span><span>${m.valid_configs||0} / ${m.total_configs||0}</span></div>
      <div class="detail-item"><span class="label">Avg Response</span><span>${(m.avg_response_time||0).toFixed(2)}s</span></div>
      <div class="detail-item"><span class="label">Last Success</span><span>${m.last_success ? new Date(m.last_success).toLocaleString() : '—'}</span></div>
      <div class="detail-item" style="border-bottom:none;"><span class="label">Protocols</span><span>${protocols}</span></div>
    `;
    modal.classList.add('active');
  }

  document.getElementById('modalClose').addEventListener('click', () => modal.classList.remove('active'));
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });

  function getFiltered() {
    const statusFilter = document.getElementById('statusFilter').value;
    const search = document.getElementById('searchInput').value.toLowerCase();
    return allData.filter(c => {
      if (statusFilter === 'active' && !c.enabled) return false;
      if (statusFilter === 'inactive' && c.enabled) return false;
      if (search && !(c.url||'').toLowerCase().includes(search)) return false;
      return true;
    });
  }

  function sortData(arr) {
    if (!sortKey) return arr;
    const keyMap = {
      name: c => c.url || '',
      status: c => c.enabled ? 1 : 0,
      score: c => c.metrics?.overall_score || 0,
      resp: c => c.metrics?.avg_response_time || 0,
      valid: c => { const m=c.metrics; return m?.total_configs > 0 ? (m.valid_configs/m.total_configs) : 0; },
      last: c => c.metrics?.last_success ? new Date(c.metrics.last_success).getTime() : 0
    };
    const fn = keyMap[sortKey] || (() => 0);
    return arr.slice().sort((a,b) => {
      const va = fn(a), vb = fn(b);
      return sortAsc ? (va > vb ? 1 : va < vb ? -1 : 0) : (va < vb ? 1 : va > vb ? -1 : 0);
    });
  }

  function render() {
    const filtered = sortData(getFiltered());
    tbody.innerHTML = '';
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#94a3b8;">No channels found</td></tr>';
      return;
    }
    filtered.forEach(c => tbody.appendChild(renderRow(c)));
  }

  // Сортировка по клику
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sortKey === key) sortAsc = !sortAsc;
      else { sortKey = key; sortAsc = true; }
      render();
    });
  });

  document.getElementById('statusFilter').addEventListener('change', render);
  document.getElementById('searchInput').addEventListener('input', render);

  // === Экспорт в CSV ===
  document.getElementById('exportCsvBtn').addEventListener('click', () => {
    const filtered = sortData(getFiltered());
    if (filtered.length === 0) {
      alert('No data to export.');
      return;
    }
    const headers = ['Channel', 'Status', 'Score (%)', 'Response (s)', 'Valid', 'Total', 'Last Success', 'Protocols'];
    const rows = filtered.map(c => {
      const m = c.metrics || {};
      const protocols = Object.entries(m.protocol_counts || {}).filter(([k,v]) => v > 0).map(([k,v]) => `${k.replace('://','')}:${v}`).join('; ') || '—';
      return [
        c.url?.replace('https://t.me/s/', '') || '—',
        c.enabled ? 'Active' : 'Inactive',
        (m.overall_score || 0).toFixed(1),
        (m.avg_response_time || 0).toFixed(2),
        m.valid_configs || 0,
        m.total_configs || 0,
        m.last_success ? new Date(m.last_success).toLocaleString() : '—',
        protocols
      ];
    });

    const escapeCSV = (v) => typeof v === 'string' && (v.includes(',') || v.includes('"') || v.includes('\\n')) ? `"${v.replace(/"/g, '""')}"` : v;
    const headerLine = headers.map(h => escapeCSV(h)).join(',');
    const dataLines = rows.map(row => row.map(v => escapeCSV(v)).join(','));
    const csv = [headerLine, ...dataLines].join('\\n');

    const blob = new Blob(['\\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `proxy_channels_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  });

  // ========== Загрузка данных ==========
  function showError(msg) {
    errorContainer.style.display = 'block';
    errorContainer.innerHTML = msg;
    document.getElementById('timestamp').textContent = 'Ошибка загрузки';
  }

  // Запасные данные для демонстрации (если ничего не загрузится)
  const fallbackData = {
    timestamp: new Date().toISOString(),
    channels: [
      { url: "https://t.me/s/example1", enabled: true, metrics: { total_configs: 10, valid_configs: 8, overall_score: 85, avg_response_time: 0.5, last_success: new Date().toISOString(), protocol_counts: { 'vless://': 5, 'trojan://': 3 } } },
      { url: "https://t.me/s/example2", enabled: false, metrics: { total_configs: 0, valid_configs: 0, overall_score: 15, avg_response_time: 0, last_success: null, protocol_counts: {} } }
    ]
  };

  function loadData() {
    const possiblePaths = [
      '../configs/channel_stats.json',
      'configs/channel_stats.json',
      './configs/channel_stats.json',
      '/configs/channel_stats.json'
    ];

    let attemptIndex = 0;

    function tryNextPath() {
      if (attemptIndex >= possiblePaths.length) {
        showError(`
          ⚠️ Не удалось загрузить данные из файла channel_stats.json.
          <br>Убедитесь, что файл находится в папке <code>configs/</code> рядом с <code>assets/</code>.
          <br>Для локального просмотра <strong>запустите простой веб-сервер</strong>, например:
          <br><code>python3 -m http.server</code> или <code>npx serve</code>.
          <br>Показаны тестовые данные.
        `);
        applyData(fallbackData);
        return;
      }

      const path = possiblePaths[attemptIndex];
      fetch(path)
        .then(response => {
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return response.json();
        })
        .then(data => {
          applyData(data);
        })
        .catch(() => {
          attemptIndex++;
          tryNextPath();
        });
    }

    function applyData(data) {
      allData = data.channels || [];
      document.getElementById('timestamp').textContent = `Last Updated: ${data.timestamp ? new Date(data.timestamp).toLocaleString() : '—'}`;
      const channels = allData;
      const active = channels.filter(c => c.enabled).length;
      const totalConfigs = channels.reduce((s,c) => s + (c.metrics?.total_configs||0), 0);
      const validConfigs = channels.reduce((s,c) => s + (c.metrics?.valid_configs||0), 0);
      const avgScore = channels.length ? (channels.reduce((s,c) => s + (c.metrics?.overall_score||0), 0) / channels.length) : 0;
      const avgResp = channels.length ? (channels.reduce((s,c) => s + (c.metrics?.avg_response_time||0), 0) / channels.length) : 0;
      document.getElementById('stats').innerHTML = `
        <div class="stat-item"><div class="label">Active</div><div class="value">${active} <span style="font-size:16px;color:#94a3b8;">/ ${channels.length}</span></div></div>
        <div class="stat-item"><div class="label">Valid Configs</div><div class="value">${validConfigs.toLocaleString()}</div></div>
        <div class="stat-item"><div class="label">Avg Score</div><div class="value">${avgScore.toFixed(1)}%</div></div>
        <div class="stat-item"><div class="label">Avg Response</div><div class="value">${avgResp.toFixed(2)}s</div></div>
      `;
      render();
    }

    tryNextPath();
  }

  loadData();
</script>
</body>
</html>'''

def generate_report():
    """Создаёт HTML-отчёт в папке assets."""
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write(HTML_TEMPLATE)
    print(f"✅ Отчёт сгенерирован: {OUTPUT_PATH}")

if __name__ == "__main__":
    generate_report()
