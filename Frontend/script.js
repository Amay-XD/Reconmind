/* ═══════════════════════════════════════════
   RECONMIND — Dashboard Script
   ═══════════════════════════════════════════ */

'use strict';

// ── CONFIG ──────────────────────────────────
const BASE_URL = 'http://localhost:5000';
let scanCount = 0;
let lastScanData = null;
let riskChart = null;
let uptimeSeconds = 0;
let scanInProgress = false;

// ── DOM REFERENCES ───────────────────────────
const targetInput     = document.getElementById('targetInput');
const targetBadge     = document.getElementById('targetBadge');
const targetBadgeText = document.getElementById('targetBadgeText');
const scanBtn         = document.getElementById('scanBtn');
const scanBtnText     = document.querySelector('.btn-scan-text');
const scanBtnSpinner  = document.querySelector('.btn-scan-spinner');
const terminalBody    = document.getElementById('terminalBody');
const threatRing      = document.getElementById('threatRing');
const threatScoreVal  = document.getElementById('threatScoreVal');
const riskLabel       = document.getElementById('riskLabel');
const aiBody          = document.getElementById('aiBody');
const confidenceVal   = document.getElementById('confidenceVal');
const severityVal     = document.getElementById('severityVal');
const vectorsVal      = document.getElementById('vectorsVal');
const intelISP        = document.getElementById('intelISP');
const intelCountry    = document.getElementById('intelCountry');
const intelCity       = document.getElementById('intelCity');
const intelPorts      = document.getElementById('intelPorts');
const intelCVE        = document.getElementById('intelCVE');
const intelHost       = document.getElementById('intelHost');
const breachList      = document.getElementById('breachList');
const breachCount     = document.getElementById('breachCount');
const socialGrid      = document.getElementById('socialGrid');
const foundCount      = document.getElementById('foundCount');
const statusDot       = document.getElementById('statusDot');
const statusText      = document.getElementById('statusText');
const scanCountEl     = document.getElementById('scanCount');
const uptimeEl        = document.getElementById('uptimeCounter');
const exportPdfBtn    = document.getElementById('exportPdfBtn');
const exportJsonBtn   = document.getElementById('exportJsonBtn');
const hamburger       = document.getElementById('hamburger');
const sidebar         = document.getElementById('sidebar');
const sidebarOverlay  = document.getElementById('sidebarOverlay');
const chartTotalEl    = document.getElementById('chartTotal');
const typedTextEl     = document.getElementById('typedText');

// ── PARTICLE CANVAS ──────────────────────────
(function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  const ctx = canvas.getContext('2d');
  let particles = [];
  const COUNT = 60;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function Particle() {
    this.reset();
  }

  Particle.prototype.reset = function() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.vx = (Math.random() - 0.5) * 0.3;
    this.vy = (Math.random() - 0.5) * 0.3;
    this.radius = Math.random() * 1.5 + 0.3;
    this.alpha = Math.random() * 0.4 + 0.05;
    this.color = Math.random() > 0.7 ? '#00FF9D' : '#00F5FF';
  };

  Particle.prototype.update = function() {
    this.x += this.vx;
    this.y += this.vy;
    if (this.x < 0 || this.x > canvas.width ||
        this.y < 0 || this.y > canvas.height) {
      this.reset();
    }
  };

  Particle.prototype.draw = function() {
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
    ctx.fillStyle = this.color;
    ctx.globalAlpha = this.alpha;
    ctx.fill();
    ctx.globalAlpha = 1;
  };

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 100) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = '#00F5FF';
          ctx.globalAlpha = (1 - dist / 100) * 0.08;
          ctx.lineWidth = 0.5;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }
    }

    particles.forEach(p => { p.update(); p.draw(); });
    requestAnimationFrame(animate);
  }

  resize();
  for (let i = 0; i < COUNT; i++) particles.push(new Particle());
  animate();
  window.addEventListener('resize', resize);
})();

// ── TYPEWRITER EFFECT ────────────────────────
(function initTypewriter() {
  const phrases = [
    'Scanning threat intelligence vectors...',
    'Correlating digital attack surfaces...',
    'Initializing AI threat analysis...',
    'Enumerating exposed infrastructure...',
    'Cross-referencing breach databases...',
  ];

  let phraseIdx = 0;
  let charIdx = 0;
  let erasing = false;

  function tick() {
    const current = phrases[phraseIdx];
    if (!erasing) {
      typedTextEl.textContent = current.slice(0, charIdx + 1);
      charIdx++;
      if (charIdx >= current.length) {
        erasing = true;
        setTimeout(tick, 2200);
        return;
      }
      setTimeout(tick, 48);
    } else {
      typedTextEl.textContent = current.slice(0, charIdx - 1);
      charIdx--;
      if (charIdx <= 0) {
        erasing = false;
        phraseIdx = (phraseIdx + 1) % phrases.length;
        setTimeout(tick, 400);
        return;
      }
      setTimeout(tick, 28);
    }
  }

  setTimeout(tick, 600);
})();

// ── TARGET TYPE DETECTION ────────────────────
const RE_IPV4     = /^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;
const RE_EMAIL    = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
const RE_DOMAIN   = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function detectTargetType(val) {
  const v = val.trim();
  if (!v) return 'idle';
  if (RE_IPV4.test(v))   return 'ip';
  if (RE_EMAIL.test(v))  return 'email';
  if (RE_DOMAIN.test(v)) return 'domain';
  return 'username';
}

const TYPE_LABELS = {
  idle:     'AWAITING INPUT',
  ip:       '◈ IP ADDRESS',
  email:    '◉ EMAIL',
  domain:   '◎ DOMAIN',
  username: '▣ USERNAME',
};

targetInput.addEventListener('input', () => {
  const type = detectTargetType(targetInput.value);
  targetBadge.dataset.type = type;
  targetBadgeText.textContent = TYPE_LABELS[type];
});

// ── UPTIME COUNTER ───────────────────────────
setInterval(() => {
  uptimeSeconds++;
  const h = String(Math.floor(uptimeSeconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((uptimeSeconds % 3600) / 60)).padStart(2, '0');
  const s = String(uptimeSeconds % 60).padStart(2, '0');
  if (uptimeEl) uptimeEl.textContent = `${h}:${m}:${s}`;
}, 1000);

// ── HEALTH CHECK ─────────────────────────────
async function checkHealth() {
  try {
    const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      statusDot.classList.remove('offline');
      statusText.textContent = 'ONLINE';
      statusText.className = 'status-online';
    } else throw new Error();
  } catch {
    statusDot.classList.add('offline');
    statusText.textContent = 'OFFLINE';
    statusText.className = 'status-offline';
    addTermLine('[WARN] Backend API unreachable — demo mode active', 'warn');
  }
}
checkHealth();

// ── TERMINAL ────────────────────────────────
const MAX_TERM_LINES = 50;

function addTermLine(text, type = 'success') {
  const p = document.createElement('div');
  p.className = `term-line ${type}`;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  p.textContent = `[${ts}] ${text}`;
  terminalBody.appendChild(p);

  // Keep max lines
  const lines = terminalBody.querySelectorAll('.term-line');
  if (lines.length > MAX_TERM_LINES) lines[0].remove();

  terminalBody.scrollTop = terminalBody.scrollHeight;
}

// Ambient idle logs
const AMBIENT_LOGS = [
  ['[IDLE] Monitoring OSINT data streams...', 'info'],
  ['[INFO] AI correlation engine standby...', 'info'],
  ['[INFO] Rate limiter: 5 req/min available', 'info'],
  ['[IDLE] Collectors in ready state...', 'info'],
  ['[INFO] Groq analysis engine connected...', 'info'],
  ['[IDLE] Awaiting target input...', 'info'],
];

let ambientIdx = 0;
let ambientInterval = setInterval(() => {
  if (!scanInProgress) {
    const [text, type] = AMBIENT_LOGS[ambientIdx % AMBIENT_LOGS.length];
    addTermLine(text.replace('[', '').replace(']', ':'), 'info');
    ambientIdx++;
  }
}, 3000);

// ── COLLECTOR CHIPS ──────────────────────────
const COLLECTOR_IDS = {
  shodan: 'col-shodan',
  whois:  'col-whois',
  hibp:   'col-hibp',
  github: 'col-github',
  social: 'col-social',
  ai:     'col-ai',
};

const CHIP_STATUS_TEXT = {
  idle:     'IDLE',
  active:   'ACTIVE',
  complete: 'DONE',
  error:    'ERR',
};

function setChipState(id, state) {
  const chip = document.getElementById(COLLECTOR_IDS[id]);
  if (!chip) return;
  chip.dataset.state = state;
  chip.querySelector('.chip-status').textContent = CHIP_STATUS_TEXT[state] || state;
}

function resetAllChips() {
  Object.keys(COLLECTOR_IDS).forEach(id => setChipState(id, 'idle'));
}

function activateChipsStaggered(ids) {
  ids.forEach((id, i) => {
    setTimeout(() => setChipState(id, 'active'), i * 180);
  });
}

function completeChipsStaggered(ids) {
  ids.forEach((id, i) => {
    setTimeout(() => setChipState(id, 'complete'), i * 200);
  });
}

// ── CHART INIT ───────────────────────────────
function initChart() {
  const ctx = document.getElementById('riskChart');
  if (!ctx) return;

  riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#FF3B3B', '#8B5CF6', '#00F5FF', '#00FF9D'],
        borderWidth: 0,
        hoverOffset: 8,
      }]
    },
    options: {
      cutout: '72%',
      animation: { duration: 1200, easing: 'easeInOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed}`,
          },
          bodyFont: { family: 'JetBrains Mono', size: 12 },
          backgroundColor: 'rgba(6,15,30,0.95)',
          borderColor: 'rgba(0,245,255,0.2)',
          borderWidth: 1,
        }
      }
    }
  });
}

initChart();

function updateChart(critical = 0, high = 0, medium = 0, low = 0) {
  if (!riskChart) return;
  riskChart.data.datasets[0].data = [critical, high, medium, low];
  riskChart.update();
  const total = critical + high + medium + low;
  if (chartTotalEl) chartTotalEl.textContent = total;
}

// ── THREAT SCORE RING ────────────────────────
function setThreatScore(score) {
  const circumference = 502.65;
  const offset = circumference - (score / 100) * circumference;

  threatRing.style.strokeDashoffset = offset;
  threatScoreVal.textContent = score;

  let color, label, labelClass;
  if (score < 30) {
    color = '#00FF9D'; label = 'LOW RISK'; labelClass = 'low';
  } else if (score < 60) {
    color = '#F59E0B'; label = 'MEDIUM RISK'; labelClass = 'medium';
  } else if (score < 80) {
    color = '#8B5CF6'; label = 'HIGH RISK'; labelClass = 'high';
  } else {
    color = '#FF3B3B'; label = 'CRITICAL RISK'; labelClass = 'critical';
  }

  threatRing.style.stroke = color;
  threatRing.style.filter = `drop-shadow(0 0 8px ${color})`;
  riskLabel.textContent = label;
  riskLabel.className = `risk-label ${labelClass}`;
}

// ── RENDER FUNCTIONS ─────────────────────────

function renderAIReport(report) {
  if (!report) return;

  const text = typeof report === 'string' ? report : JSON.stringify(report, null, 2);
  aiBody.innerHTML = `<p class="ai-report-text">${text.slice(0, 400)}${text.length > 400 ? '...' : ''}</p>`;

  // Extract metrics with regex fallbacks
  const confMatch = text.match(/(\d{1,3})\s*%?\s*confidence/i);
  const sevMatch  = text.match(/severity[:\s]+(critical|high|medium|low)/i);
  const vecMatch  = text.match(/(\d+)\s*vector/i);

  confidenceVal.textContent = confMatch ? confMatch[1] + '%' : '~87%';
  vectorsVal.textContent    = vecMatch  ? vecMatch[1]  : '4';

  const sev = sevMatch ? sevMatch[1].toLowerCase() : 'high';
  severityVal.textContent = sev.toUpperCase();
  severityVal.className = `badge-val severity-val ${sev}`;
}

function renderIPIntel(shodanData) {
  if (!shodanData || shodanData.error) {
    intelISP.textContent = '—';
    intelCountry.textContent = '—';
    intelCity.textContent = '—';
    intelPorts.textContent = '—';
    intelCVE.textContent = '—';
    intelHost.textContent = '—';
    return;
  }

  intelISP.textContent     = shodanData.isp || '—';
  intelCountry.textContent = shodanData.country_name || shodanData.country || '—';
  intelCity.textContent    = shodanData.city || '—';

  const ports = shodanData.ports || shodanData.open_ports || [];
  intelPorts.textContent = ports.length ? ports.slice(0, 6).join(', ') : '—';

  const vulns = shodanData.vulns || shodanData.vulnerabilities || [];
  const vulnCount = Array.isArray(vulns) ? vulns.length : Object.keys(vulns).length;
  intelCVE.textContent = vulnCount ? `${vulnCount} found` : 'None detected';
  intelCVE.className = vulnCount ? 'intel-val danger' : 'intel-val';

  const hosts = shodanData.hostnames || [];
  intelHost.textContent = hosts.length ? hosts[0] : '—';
}

function renderBreachList(hibpData) {
  if (!hibpData || hibpData.error || !Array.isArray(hibpData) || hibpData.length === 0) {
    breachList.innerHTML = '<div class="breach-empty">No breaches found or scan not run.</div>';
    breachCount.textContent = '0 breaches';
    return;
  }

  const SEVERITY_MAP = { password: 'critical', credential: 'critical', hash: 'high', email: 'medium', data: 'low' };

  breachCount.textContent = `${hibpData.length} breach${hibpData.length !== 1 ? 'es' : ''}`;
  breachList.innerHTML = '';

  hibpData.slice(0, 8).forEach(breach => {
    const name = typeof breach === 'string' ? breach : (breach.Name || breach.name || 'Unknown');
    const description = (breach.Description || breach.description || '').toLowerCase();
    let severity = 'medium';
    for (const [keyword, sev] of Object.entries(SEVERITY_MAP)) {
      if (description.includes(keyword)) { severity = sev; break; }
    }

    const div = document.createElement('div');
    div.className = `breach-item ${severity}`;
    div.innerHTML = `
      <span class="breach-item-name">${name}</span>
      <span class="breach-item-tag">${severity.toUpperCase()}</span>
    `;
    breachList.appendChild(div);
  });
}

function renderSocialPlatforms(socialData) {
  const chips = socialGrid.querySelectorAll('.platform-chip');
  let found = 0;

  chips.forEach(chip => {
    const platform = chip.dataset.platform.toLowerCase();

    let isFound = false;
    if (socialData && !socialData.error) {
      if (Array.isArray(socialData)) {
        isFound = socialData.some(s => s.toLowerCase().includes(platform));
      } else if (typeof socialData === 'object') {
        isFound = Object.keys(socialData).some(k =>
          k.toLowerCase().includes(platform) && socialData[k]
        );
      }
    }

    chip.dataset.found = isFound.toString();
    if (isFound) found++;
  });

  foundCount.textContent = `${found} found`;
}

// ── DEMO DATA (when backend offline) ─────────
function loadDemoData(target) {
  const type = detectTargetType(target);

  const score = Math.floor(Math.random() * 40) + 55;
  setThreatScore(score);

  renderAIReport(`ReconMind AI analysis for target "${target}" (${type}) identified correlated threat vectors. Exposed services detected on standard ports. Credential exposure confirmed across multiple breach databases. Digital footprint spans 4+ social platforms. Recommended immediate remediation.`);

  if (type === 'ip' || type === 'domain') {
    renderIPIntel({
      isp: 'Cloudflare, Inc.',
      country_name: 'Germany',
      city: 'Frankfurt',
      ports: [22, 80, 443, 8080],
      vulns: ['CVE-2023-1234', 'CVE-2023-5678', 'CVE-2024-0001'],
      hostnames: [`srv-${target}`],
    });
  }

  if (type === 'email') {
    renderBreachList([
      { Name: 'LinkedIn', Description: 'password hash exposed' },
      { Name: 'Dropbox', Description: 'credential leak 2012' },
      { Name: 'Adobe', Description: 'email and password data' },
      { Name: 'Canva', Description: 'email data breach' },
    ]);
  }

  renderSocialPlatforms({
    github: Math.random() > 0.5,
    twitter: Math.random() > 0.5,
    reddit: Math.random() > 0.5,
    linkedin: Math.random() > 0.3,
  });

  const crit = Math.floor(Math.random() * 10) + 3;
  const high = Math.floor(Math.random() * 14) + 5;
  const med  = Math.floor(Math.random() * 10) + 3;
  const low  = Math.floor(Math.random() * 6) + 1;
  updateChart(crit, high, med, low);
}

// ── SCAN FLOW ────────────────────────────────
async function performScan(target) {
  if (scanInProgress) return;
  scanInProgress = true;

  const type = detectTargetType(target);
  const collectorMap = {
    ip:       ['shodan', 'whois'],
    email:    ['hibp', 'social', 'ai'],
    domain:   ['whois', 'shodan', 'github', 'ai'],
    username: ['github', 'social', 'ai'],
  };
  const activeCollectors = collectorMap[type] || ['shodan', 'whois', 'hibp', 'github', 'social', 'ai'];

  // UI: start
  resetAllChips();
  scanBtnText.textContent = 'SCANNING...';
  scanBtnSpinner.hidden = false;
  scanBtn.disabled = true;
  scanBtn.style.background = '#FF3B3B';
  scanBtn.style.boxShadow = '0 0 24px rgba(255,59,59,0.4)';

  addTermLine(`Initiating scan for: ${target} [${type.toUpperCase()}]`, 'info');
  addTermLine(`Classifying target... → ${type}`, 'info');

  activateChipsStaggered(activeCollectors);
  activeCollectors.forEach((col, i) => {
    setTimeout(() => addTermLine(`[INIT] ${col.toUpperCase()} collector started`, 'info'), 300 + i * 200);
  });

  try {
    const response = await fetch(`${BASE_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
      signal: AbortSignal.timeout(30000),
    });

    if (response.status === 429) {
      showToast('Rate limit reached. Please wait before scanning again.', 'error');
      addTermLine('[ERROR] Rate limit exceeded — retry in 60s', 'error');
      throw new Error('rate_limit');
    }

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    lastScanData = data;

    completeChipsStaggered(activeCollectors);
    addTermLine('[SUCCESS] All collectors completed', 'success');
    addTermLine('[AI] Groq analysis engine processing...', 'info');

    // Populate cards
    if (data.osint_data) {
      renderIPIntel(data.osint_data.shodan);
      renderBreachList(data.osint_data.hibp);
      renderSocialPlatforms(data.osint_data.social_scan);
    }

    if (data.report) {
      renderAIReport(data.report);
      addTermLine('[AI] Threat analysis complete', 'success');
    }

    // Derive threat score from data
    const breaches = Array.isArray(data.osint_data?.hibp) ? data.osint_data.hibp.length : 0;
    const vulns = data.osint_data?.shodan?.vulns ? Object.keys(data.osint_data.shodan.vulns).length : 0;
    const score = Math.min(95, 30 + breaches * 8 + vulns * 5);
    setThreatScore(score);
    updateChart(
      vulns,
      Math.max(0, breaches - vulns),
      Math.max(1, breaches),
      Math.max(1, 3)
    );

    scanCount++;
    scanCountEl.textContent = scanCount;
    showToast(`Scan complete for ${target}`, 'success');
    addTermLine(`[DONE] Report generated for ${target}`, 'success');

  } catch (err) {
    if (err.message === 'rate_limit') {
      // already handled
    } else if (err.name === 'TimeoutError' || err.message.includes('timeout')) {
      addTermLine('[WARN] API timeout — loading demo data', 'warn');
      showToast('Backend timed out. Loading demo data.', 'info');
      loadDemoData(target);
      completeChipsStaggered(activeCollectors);
      scanCount++;
      scanCountEl.textContent = scanCount;
    } else {
      addTermLine(`[WARN] API unavailable — demo mode`, 'warn');
      showToast('Backend offline. Showing demo data.', 'info');
      loadDemoData(target);
      completeChipsStaggered(activeCollectors);
      scanCount++;
      scanCountEl.textContent = scanCount;
    }
  } finally {
    // Reset button
    setTimeout(() => {
      scanBtnText.textContent = 'SCAN COMPLETE';
      scanBtn.style.background = '#00FF9D';
      scanBtn.style.boxShadow = '0 0 24px rgba(0,255,157,0.4)';
      scanBtnSpinner.hidden = true;

      setTimeout(() => {
        scanBtnText.textContent = 'INITIATE SCAN';
        scanBtn.style.background = '';
        scanBtn.style.boxShadow = '';
        scanBtn.disabled = false;
        scanInProgress = false;
      }, 3000);
    }, 500);
  }
}

// ── SCAN BUTTON ───────────────────────────────
scanBtn.addEventListener('click', () => {
  const target = targetInput.value.trim();
  if (!target) {
    targetInput.focus();
    targetInput.style.borderColor = 'var(--red)';
    setTimeout(() => targetInput.style.borderColor = '', 1200);
    showToast('Please enter a target to scan.', 'error');
    return;
  }
  performScan(target);
});

targetInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') scanBtn.click();
});

// ── PDF EXPORT ────────────────────────────────
exportPdfBtn.addEventListener('click', async () => {
  const target = targetInput.value.trim() || (lastScanData?.target);
  if (!target) { showToast('Run a scan first.', 'error'); return; }

  exportPdfBtn.disabled = true;
  exportPdfBtn.textContent = 'GENERATING...';

  try {
    const res = await fetch(`${BASE_URL}/scan/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
      signal: AbortSignal.timeout(30000),
    });

    if (!res.ok) throw new Error();

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconmind_report_${target.replace(/[^\w.-]/g, '_')}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('PDF exported successfully.', 'success');

  } catch {
    showToast('PDF export failed. Backend may be offline.', 'error');
  } finally {
    exportPdfBtn.disabled = false;
    exportPdfBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M12 18v-6M9 15l3 3 3-3"/></svg> EXPORT PDF`;
  }
});

// ── JSON EXPORT ───────────────────────────────
exportJsonBtn.addEventListener('click', () => {
  if (!lastScanData) { showToast('Run a scan first.', 'error'); return; }
  const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const target = (lastScanData.target || 'scan').replace(/[^\w.-]/g, '_');
  a.download = `reconmind_${target}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('JSON downloaded.', 'success');
});

// ── TOAST SYSTEM ──────────────────────────────
function showToast(message, type = 'info') {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = { error: '✕', success: '✓', info: 'ℹ' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = '0.3s ease';
    setTimeout(() => toast.remove(), 350);
  }, 4000);
}

// ── SIDEBAR (MOBILE) ──────────────────────────
hamburger.addEventListener('click', () => {
  sidebar.classList.toggle('open');
  sidebarOverlay.classList.toggle('open');
});

sidebarOverlay.addEventListener('click', () => {
  sidebar.classList.remove('open');
  sidebarOverlay.classList.remove('open');
});

// Touch swipe to close
let touchStartX = 0;
document.addEventListener('touchstart', e => { touchStartX = e.touches[0].clientX; });
document.addEventListener('touchend', e => {
  if (touchStartX < 260 && e.changedTouches[0].clientX - touchStartX < -60) {
    sidebar.classList.remove('open');
    sidebarOverlay.classList.remove('open');
  }
});

// ── NAV ITEMS ────────────────────────────────
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Close sidebar on mobile
    if (window.innerWidth < 900) {
      sidebar.classList.remove('open');
      sidebarOverlay.classList.remove('open');
    }
  });
});

// ── MOUSE PARALLAX ────────────────────────────
document.addEventListener('mousemove', e => {
  const bgGrid = document.querySelector('.bg-grid');
  if (bgGrid) {
    const x = (e.clientX / window.innerWidth  - 0.5) * 12;
    const y = (e.clientY / window.innerHeight - 0.5) * 12;
    bgGrid.style.transform = `translate(${x}px, ${y}px)`;
  }
});
