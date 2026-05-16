/* ═══════════════════════════════════════════
   Network Scan Dashboard — Charts & Interactivity
   ═══════════════════════════════════════════ */

function initNetworkCharts(chartData) {
  if (typeof Chart === 'undefined') return;

  const defaultColors = [
    '#6366f1', '#818cf8', '#a78bfa', '#c4b5fd',
    '#f472b6', '#fb923c', '#fbbf24', '#34d399',
    '#2dd4bf', '#38bdf8',
  ];

  /* ── Severity Distribution (Donut) ── */
  const sevCanvas = document.getElementById('chartSeverity');
  if (sevCanvas && chartData.severity) {
    const s = chartData.severity;
    const hasData = s.critical + s.high + s.medium + s.low > 0;
    new Chart(sevCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: hasData
            ? [s.critical, s.high, s.medium, s.low]
            : [1],
          backgroundColor: hasData
            ? ['#7f1d1d', '#dc2626', '#ea580c', '#16a34a']
            : ['#e2e8f0'],
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 10, font: { size: 11 } } },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                return ctx.label + ': ' + ctx.parsed;
              },
            },
          },
        },
      },
    });
  }

  /* ── Top Exposed Ports (Horizontal Bar) ── */
  const portsCanvas = document.getElementById('chartTopPorts');
  if (portsCanvas && chartData.topPorts && chartData.topPorts.length) {
    const labels = chartData.topPorts.map(function (p) { return p.port; });
    const values = chartData.topPorts.map(function (p) { return p.count; });
    new Chart(portsCanvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Hosts',
          data: values,
          backgroundColor: values.map(function (v, i) {
            return defaultColors[i % defaultColors.length];
          }),
          borderRadius: 4,
          borderSkipped: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                return ctx.parsed.x + ' host(s)';
              },
            },
          },
        },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } },
          y: { ticks: { font: { size: 10, family: 'monospace' } } },
        },
      },
    });
  } else if (portsCanvas) {
    showNoData(portsCanvas, 'No port data');
  }

  /* ── Services Distribution (Donut) ── */
  const svcCanvas = document.getElementById('chartServices');
  if (svcCanvas && chartData.services && chartData.services.length) {
    const labels = chartData.services.map(function (s) { return s.service; });
    const values = chartData.services.map(function (s) { return s.count; });
    const total = values.reduce(function (a, b) { return a + b; }, 0);
    new Chart(svcCanvas, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: values.map(function (v, i) {
            return defaultColors[i % defaultColors.length];
          }),
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              boxWidth: 10,
              font: { size: 10 },
              generateLabels: function (chart) {
                const orig = Chart.defaults.plugins.legend.labels.generateLabels(chart);
                orig.forEach(function (label, i) {
                  const pct = total > 0 ? Math.round((values[i] / total) * 100) : 0;
                  if (label.text) label.text = label.text + '  ' + pct + '%';
                });
                return orig;
              },
            },
          },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                const pct = total > 0 ? Math.round((ctx.parsed / total) * 100) : 0;
                return ctx.label + ': ' + ctx.parsed + ' (' + pct + '%)';
              },
            },
          },
        },
      },
    });
  } else if (svcCanvas) {
    showNoData(svcCanvas, 'No service data');
  }

  /* ── OS Distribution (Horizontal Bar) ── */
  const osCanvas = document.getElementById('chartOS');
  if (osCanvas && chartData.osDistribution && Object.keys(chartData.osDistribution).length) {
    const entries = Object.entries(chartData.osDistribution);
    const labels = entries.map(function (e) { return e[0]; });
    const values = entries.map(function (e) { return e[1]; });
    const osColors = {
      windows: '#3b82f6', linux: '#f59e0b', macos: '#8b5cf6',
      android: '#22c55e', unknown: '#94a3b8',
    };
    new Chart(osCanvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Hosts',
          data: values,
          backgroundColor: labels.map(function (l) {
            const key = l.toLowerCase();
            for (var k in osColors) {
              if (key.indexOf(k) !== -1) return osColors[k];
            }
            return '#6366f1';
          }),
          borderRadius: 4,
          borderSkipped: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } },
          y: { ticks: { font: { size: 10 } } },
        },
      },
    });
  } else if (osCanvas) {
    showNoData(osCanvas, 'No OS data');
  }

  /* ── Attack Surface Radar ── */
  const surfaceCanvas = document.getElementById('chartAttackSurface');
  if (surfaceCanvas && chartData.attackSurface) {
    const as = chartData.attackSurface;
    const labels = ['Web', 'Database', 'Remote Access', 'File Sharing', 'Mail', 'IoT'];
    const values = [
      as.risk_breakdown ? (as.risk_breakdown.web || 0) : 0,
      as.risk_breakdown ? (as.risk_breakdown.database || 0) : 0,
      as.risk_breakdown ? (as.risk_breakdown.remote_access || 0) : 0,
      as.risk_breakdown ? (as.risk_breakdown.file_sharing || 0) : 0,
      as.risk_breakdown ? (as.risk_breakdown.mail || 0) : 0,
      as.risk_breakdown ? (as.risk_breakdown.iot || 0) : 0,
    ];
    const hasData = values.some(function (v) { return v > 0; });
    if (hasData) {
      new Chart(surfaceCanvas, {
        type: 'radar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Exposed Services',
            data: values,
            backgroundColor: 'rgba(99,102,241,0.15)',
            borderColor: '#6366f1',
            borderWidth: 2,
            pointBackgroundColor: '#6366f1',
            pointRadius: 4,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            r: {
              beginAtZero: true,
              ticks: { font: { size: 9 }, backdropColor: 'transparent' },
              grid: { color: 'rgba(0,0,0,0.06)' },
              angleLines: { color: 'rgba(0,0,0,0.06)' },
              pointLabels: { font: { size: 10 } },
            },
          },
        },
      });
    } else {
      showNoData(surfaceCanvas, 'No attack surface data');
    }
  } else if (surfaceCanvas) {
    showNoData(surfaceCanvas, 'No attack surface data');
  }
}

function showNoData(canvas, msg) {
  var parent = canvas.parentElement;
  parent.style.position = 'relative';
  var overlay = document.createElement('div');
  overlay.className = 'ni-chart-overlay';
  overlay.textContent = msg;
  overlay.style.cssText =
    'position:absolute;inset:0;display:flex;align-items:center;' +
    'justify-content:center;color:#94a3b8;font-size:13px;' +
    'background:rgba(255,255,255,0.7);z-index:5;border-radius:8px;';
  parent.appendChild(overlay);
}

/* ── Host detail row expand/collapse ── */
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.ni-expand-btn');
  if (!btn) return;
  e.preventDefault();

  var row = btn.closest('tr');
  var detailRow = row.nextElementSibling;

  if (detailRow && detailRow.classList.contains('ni-empty-row')) {
    var collapsed = detailRow.style.display === 'none' ||
      getComputedStyle(detailRow).display === 'none' ||
      !detailRow._expanded;

    if (collapsed) {
      detailRow.style.display = '';
      detailRow._expanded = true;
      btn.classList.add('expanded');
      row.classList.add('ni-row-expanded');
    } else {
      detailRow.style.display = 'none';
      detailRow._expanded = false;
      btn.classList.remove('expanded');
      row.classList.remove('ni-row-expanded');
    }
  }
});

/* ── Safe scroll to element ── */
function niScrollTo(id) {
  var el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
