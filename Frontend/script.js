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

  // Auto-scroll to latest
  terminalBody.scrollTop = terminalBody.scrollHeight;

  // Limit lines
  const lines = terminalBody.querySelectorAll('.term-line');
  if (lines.length > MAX_TERM_LINES) {
    lines[0].remove();
  }
}

// ── THREAT SCORE ─────────────────────────────
function setThreatScore(score) {
  const max = 100;
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / max) * circumference;

  threatRing.setAttribute('stroke-dashoffset', offset);
  threatScoreVal.textContent = Math.round(score);

  // Update color and label
  if (score < 35) {
    threatRing.style.stroke = '#10B981';
    riskLabel.textContent = 'LOW RISK';
    riskLabel.style.color = '#10B981';
  } else if (score < 60) {
    threatRing.style.stroke = '#F59E0B';
    riskLabel.textContent = 'MEDIUM RISK';
    riskLabel.style.color = '#F59E0B';
  } else if (score < 80) {
    threatRing.style.stroke = '#EF4444';
    riskLabel.textContent = 'HIGH RISK';
    riskLabel.style.color = '#EF4444';
  } else {
    threatRing.style.stroke = '#DC2626';
    riskLabel.textContent = 'CRITICAL';
    riskLabel.style.color = '#DC2626';
  }
}

// ── RENDER FUNCTIONS ─────────────────────────
function renderIPIntel(data) {
  if (!data) return;
  intelISP.textContent = data.isp || '—';
  intelCountry.textContent = data.country || '—';
  intelCity.textContent = data.city || '—';
  intelPorts.textContent = data.ports ? data.ports.length : '—';
  intelCVE.textContent = data.vulns ? Object.keys(data.vulns).length : '—';
  intelHost.textContent = data.hostnames ? data.hostnames.join(', ') : '—';
}

function renderBreachList(breaches) {
  breachList.innerHTML = '';
  if (!Array.isArray(breaches) || breaches.length === 0) {
    breachList.innerHTML = '<div class="breach-empty">No breaches found.</div>';
    breachCount.textContent = '0 breaches';
    return;
  }
  breaches.forEach(breach => {
    const div = document.createElement('div');
    div.className = 'breach-item';
    div.innerHTML = `<span>${breach.name}</span><span class="date">${breach.date || 'Unknown'}</span>`;
    breachList.appendChild(div);
  });
  breachCount.textContent = `${breaches.length} breaches`;
}

function renderSocialPlatforms(social) {
  if (!social) return;
  const chips = document.querySelectorAll('.platform-chip');
  chips.forEach(chip => {
    const platform = chip.dataset.platform;
    const found = social[platform];
    if (found) {
      chip.dataset.found = 'true';
      chip.style.opacity = '1';
    } else {
      chip.data.found = 'false';
      chip.style.opacity = '0.3';
    }
  });
  const count = Object.values(social).filter(v => v).length;
  foundCount.textContent = `${count} found`;
}

function renderAIReport(report) {
  if (!report) return;
  aiBody.innerHTML = '';
  const summary = report.summary || report.analysis || 'No analysis available.';
  aiBody.innerHTML = `<p>${summary}</p>`;
  confidenceVal.textContent = report.confidence ? `${report.confidence}%` : '—';
  severityVal.textContent = report.severity || '—';
  vectorsVal.textContent = report.vectors || '—';
}

function loadDemoData(target) {
  const demoReport = {
    summary: `Demo analysis for ${target}. In production, this would contain real threat intelligence from Groq AI.`,
    confidence: 85,
    severity: 'MEDIUM',
    vectors: 4,
  };

  const demoOSINT = {
    shodan: { isp: 'Example ISP', country: 'US', city: 'Unknown', ports: [80, 443], vulns: {} },
    hibp: ['Demo Breach 1'],
    social_scan: { github: true, twitter: false },
  };

  renderAIReport(demoReport);
  renderIPIntel(demoOSINT.shodan);
  renderBreachList(demoOSINT.hibp);
  renderSocialPlatforms(demoOSINT.social_scan);
  setThreatScore(45);
}

// ── CHART ────────────────────────────────────
function updateChart(critical, high, medium, low) {
  const ctx = document.getElementById('riskChart');
  if (!ctx) return;

  if (riskChart) riskChart.destroy();

  riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [critical, high, medium, low],
        backgroundColor: ['#DC2626', '#EF4444', '#F59E0B', '#10B981'],
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
    },
  });

  const total = critical + high + medium + low;
  chartTotalEl.textContent = total;
}

// ── COLLECTOR CHIPS ──────────────────────────
function activateChipsStaggered(collectors) {
  const chips = document.querySelectorAll('.chip');
  collectors.forEach((col, i) => {
    setTimeout(() => {
      const chip = document.querySelector(`[data-collector="${col}"]`);
      if (chip) {
        chip.classList.add('active');
        chip.querySelector('.chip-status').textContent = 'RUNNING';
      }
    }, i * 300);
  });
}

function completeChipsStaggered(collectors) {
  const chips = document.querySelectorAll('.chip');
  collectors.forEach((col, i) => {
    setTimeout(() => {
      const chip = document.querySelector(`[data-collector="${col}"]`);
      if (chip) {
        chip.classList.remove('active');
        chip.classList.add('complete');
        chip.querySelector('.chip-status').textContent = 'COMPLETE';
      }
    }, i * 200);
  });
}

// ── PERFORM SCAN ─────────────────────────────
async function performScan(target) {
  if (scanInProgress) return;
  scanInProgress = true;

  const type = detectTargetType(target);
  const activeCollectors = ['shodan', 'whois', 'hibp', 'github', 'google', 'social_scan'];

  scanBtn.disabled = true;
  scanBtnText.textContent = 'INITIATING...';
  scanBtnSpinner.hidden = false;
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

// ═══════════════════════════════════════════════════════════════
// ── PDF EXPORT - UPDATED VERSION ────────────────────────────────
// ═══════════════════════════════════════════════════════════════

exportPdfBtn.addEventListener('click', async () => {
  const target = lastScanData?.target || targetInput.value.trim();
  if (!target) {
    showToast('Run a scan first.', 'error');
    return;
  }

  exportPdfBtn.disabled = true;
  exportPdfBtn.innerHTML = '<span>⏳</span> GENERATING...';

  try {
    const res = await fetch(`${BASE_URL}/scan/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: lastScanData?.target || target,
        report: lastScanData?.report || null,
        osint_data: lastScanData?.osint_data || null,
      }),
      signal: AbortSignal.timeout(30000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconmind_report_${target.replace(/[^\w.-]/g, '_')}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('PDF exported successfully.', 'success');
  } catch (error) {
    console.error('PDF export error:', error);
    showToast('PDF export failed. Backend may be offline.', 'error');
  } finally {
    exportPdfBtn.disabled = false;
    exportPdfBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M12 18v-6M9 15l3 3 3-3"/></svg> EXPORT PDF`;
  }
});

// ═══════════════════════════════════════════════════════════════
// ── JSON EXPORT - UPDATED VERSION ───────────────────────────────
// ═══════════════════════════════════════════════════════════════

exportJsonBtn.addEventListener('click', () => {
  if (!lastScanData) {
    showToast('Run a scan first.', 'error');
    return;
  }

  try {
    const dataToExport = {
      metadata: {
        exportDate: new Date().toISOString(),
        target: lastScanData.target || targetInput.value.trim(),
        version: '2.0.0',
      },
      report: lastScanData.report || {},
      osint_data: lastScanData.osint_data || {},
    };

    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const target = (lastScanData.target || 'scan').replace(/[^\w.-]/g, '_');
    a.download = `reconmind_${target}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('JSON downloaded successfully.', 'success');
  } catch (error) {
    console.error('JSON export error:', error);
    showToast('JSON export failed.', 'error');
  }
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

/* ═══════════════════════════════════════════════════════════════
   UPDATES MADE:
   
   ✅ PDF Export (Lines 652-679):
      • Sends target + report + osint_data to backend
      • Shows animated "⏳ GENERATING..." button state
      • Better error handling with console.error()
      • Proper finally block for button reset
   
   ✅ JSON Export (Lines 681-708):
      • Includes metadata (exportDate, target, version)
      • Structured format: metadata + report + osint_data
      • Unique filename with timestamp
      • Error handling with console.error()
   
   All Copyright Reserved © 2025 ReconMind
   ═══════════════════════════════════════════════════════════════ */
