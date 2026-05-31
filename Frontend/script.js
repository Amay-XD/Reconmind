/* ═══════════════════════════════════════════════════════════════
   RECONMIND — Professional Frontend Script
   AI-Powered OSINT Intelligence Engine
   ═══════════════════════════════════════════════════════════════ */

'use strict';

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const API_BASE = 'http://localhost:5000'; // Change to Railway URL for production

// ═══════════════════════════════════════════════════════════════
// STATE MANAGEMENT
// ═══════════════════════════════════════════════════════════════

let scanCount = 0;
let lastScanData = null;
let scanInProgress = false;
let scanHistory = [];

// ═══════════════════════════════════════════════════════════════
// DOM REFERENCES
// ═══════════════════════════════════════════════════════════════

const targetInput = document.getElementById('targetInput');
const autoDetectBadge = document.getElementById('autoDetectBadge');
const scanBtn = document.getElementById('scanBtn');
const scanCountDisplay = document.getElementById('scanCountDisplay');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');

const scanAnimation = document.getElementById('scanAnimation');
const resultsSection = document.getElementById('resultsSection');
const emptyState = document.getElementById('emptyState');

const collectorsGrid = document.getElementById('collectorsGrid');
const aiAnalysisPhase = document.getElementById('aiAnalysisPhase');
const aiAnalysisText = document.getElementById('aiAnalysisText');

const progressPhase = document.getElementById('progressPhase');
const progressPercent = document.getElementById('progressPercent');
const progressBar = document.getElementById('progressBar');

// Results elements
const gaugeProgress = document.getElementById('gaugeProgress');
const gaugeText = document.getElementById('gaugeText');
const threatLevel = document.getElementById('threatLevel');
const threatSummary = document.getElementById('threatSummary');
const summaryText = document.getElementById('summaryText');
const findingsList = document.getElementById('findingsList');
const threatsList = document.getElementById('threatsList');
const recommendationsList = document.getElementById('recommendationsList');

const shodanData = document.getElementById('shodan-data');
const whoisData = document.getElementById('whois-data');
const githubData = document.getElementById('github-data');
const socialData = document.getElementById('social-data');

const pdfBtn = document.getElementById('pdfBtn');
const jsonBtn = document.getElementById('jsonBtn');
const newScanBtn = document.getElementById('newScanBtn');

const scanHistory_el = document.getElementById('scanHistory');
const criticalAlert = document.getElementById('criticalAlert');
const typewriterText = document.getElementById('typewriterText');

// ═══════════════════════════════════════════════════════════════
// PARTICLE CANVAS ANIMATION
// ═══════════════════════════════════════════════════════════════

(function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  const ctx = canvas.getContext('2d');
  let particles = [];
  const COUNT = 40;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  class Particle {
    constructor() {
      this.reset();
    }

    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - 0.5) * 0.2;
      this.vy = (Math.random() - 0.5) * 0.2;
      this.radius = Math.random() * 1 + 0.3;
      this.alpha = Math.random() * 0.3 + 0.05;
      this.color = Math.random() > 0.6 ? '#00F5FF' : '#7c3aed';
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;
      if (this.x < 0 || this.x > canvas.width || this.y < 0 || this.y > canvas.height) {
        this.reset();
      }
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.globalAlpha = this.alpha;
      ctx.fill();
      ctx.globalAlpha = 1;
    }
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = '#00F5FF';
          ctx.globalAlpha = (1 - dist / 120) * 0.06;
          ctx.lineWidth = 0.5;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }
    }

    particles.forEach(p => {
      p.update();
      p.draw();
    });
    requestAnimationFrame(animate);
  }

  resize();
  for (let i = 0; i < COUNT; i++) particles.push(new Particle());
  animate();
  window.addEventListener('resize', resize);
})();

// ═══════════════════════════════════════════════════════════════
// TYPEWRITER EFFECT
// ═══════════════════════════════════════════════════════════════

(function initTypewriter() {
  const phrases = [
    'Scanning the digital footprint of any target...',
    '6 collectors. 1 AI. Complete threat intelligence.',
    'Know what the internet knows about you.',
    'Real-time OSINT analysis powered by Groq AI',
  ];

  let phraseIdx = 0;
  let charIdx = 0;
  let isErasing = false;

  function tick() {
    const current = phrases[phraseIdx];
    if (!isErasing) {
      typewriterText.textContent = current.slice(0, charIdx + 1);
      charIdx++;
      if (charIdx >= current.length) {
        isErasing = true;
        setTimeout(tick, 2500);
        return;
      }
      setTimeout(tick, 40);
    } else {
      typewriterText.textContent = current.slice(0, charIdx - 1);
      charIdx--;
      if (charIdx <= 0) {
        isErasing = false;
        phraseIdx = (phraseIdx + 1) % phrases.length;
        setTimeout(tick, 300);
        return;
      }
      setTimeout(tick, 20);
    }
  }

  setTimeout(tick, 600);
})();

// ═══════════════════════════════════════════════════════════════
// TARGET TYPE DETECTION
// ═══════════════════════════════════════════════════════════════

const RE_IPV4 = /^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;
const RE_EMAIL = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
const RE_DOMAIN = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function detectTargetType(val) {
  const v = val.trim();
  if (!v) return 'idle';
  if (RE_IPV4.test(v)) return 'ip';
  if (RE_EMAIL.test(v)) return 'email';
  if (RE_DOMAIN.test(v)) return 'domain';
  return 'username';
}

const TYPE_LABELS = {
  idle: 'AWAITING INPUT',
  ip: '◈ IP ADDRESS',
  email: '◉ EMAIL',
  domain: '◎ DOMAIN',
  username: '▣ USERNAME',
};

targetInput.addEventListener('input', () => {
  const type = detectTargetType(targetInput.value);
  autoDetectBadge.textContent = TYPE_LABELS[type];
  autoDetectBadge.setAttribute('data-type', type);
});

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════

async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      statusDot.classList.remove('offline');
      statusText.textContent = 'ONLINE';
    } else throw new Error();
  } catch {
    statusDot.classList.add('offline');
    statusText.textContent = 'OFFLINE';
  }
}

checkHealth();
setInterval(checkHealth, 30000);

// ═══════════════════════════════════════════════════════════════
// SCANNING ANIMATION PHASES
// ═══════════════════════════════════════════════════════════════

async function animatePhase1() {
  // INITIALIZING
  progressPhase.textContent = 'INITIALIZING';
  progressPercent.textContent = '0%';
  progressBar.style.width = '0%';

  await new Promise(resolve => setTimeout(resolve, 500));

  progressBar.style.width = '5%';
  progressPercent.textContent = '5%';
  await new Promise(resolve => setTimeout(resolve, 500));
}

async function animatePhase2(collectors) {
  // COLLECTING
  progressPhase.textContent = 'COLLECTING';
  progressBar.style.width = '10%';
  progressPercent.textContent = '10%';

  const collectorElements = {
    shodan: collectorsGrid.querySelector('[data-collector="shodan"]'),
    whois: collectorsGrid.querySelector('[data-collector="whois"]'),
    hibp: collectorsGrid.querySelector('[data-collector="hibp"]'),
    github: collectorsGrid.querySelector('[data-collector="github"]'),
    google: collectorsGrid.querySelector('[data-collector="google"]'),
    social_scan: collectorsGrid.querySelector('[data-collector="social_scan"]'),
  };

  // Simulate staggered collector completion
  let progressIncrement = 60 / collectors.length;
  for (let i = 0; i < collectors.length; i++) {
    await new Promise(resolve => setTimeout(resolve, 1500));

    const collectorName = collectors[i];
    const el = collectorElements[collectorName];
    if (el) {
      el.classList.add('complete');
      el.querySelector('.progress-mini').style.width = '100%';
    }

    const newProgress = Math.min(70, 10 + (i + 1) * progressIncrement);
    progressBar.style.width = newProgress + '%';
    progressPercent.textContent = Math.round(newProgress) + '%';
  }
}

async function animatePhase3() {
  // AI ANALYSIS
  progressPhase.textContent = 'AI ANALYSIS';
  aiAnalysisPhase.style.display = 'block';
  progressBar.style.width = '80%';
  progressPercent.textContent = '80%';

  // Simulate AI analysis text
  const analysisTexts = [
    'Correlating 6 data sources...',
    'Identifying attack vectors...',
    'Calculating risk score...',
    'Generating recommendations...',
    'Finalizing threat assessment...',
  ];

  for (const text of analysisTexts) {
    aiAnalysisText.textContent = text;
    await new Promise(resolve => setTimeout(resolve, 800));
  }

  progressBar.style.width = '95%';
  progressPercent.textContent = '95%';
}

async function animatePhase4() {
  // COMPLETE
  progressPhase.textContent = 'COMPLETE';
  progressBar.style.width = '100%';
  progressPercent.textContent = '100%';
  progressBar.style.background = 'linear-gradient(90deg, #10b981, #059669)';

  await new Promise(resolve => setTimeout(resolve, 500));
}

// ═══════════════════════════════════════════════════════════════
// THREAT GAUGE ANIMATION
// ═══════════════════════════════════════════════════════════════

function animateThreatGauge(score) {
  return new Promise(resolve => {
    let currentScore = 0;
    const targetScore = score;
    const duration = 2000; // 2 seconds
    const startTime = Date.now();

    function update() {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);

      currentScore = Math.round(targetScore * progress);
      gaugeText.textContent = currentScore;

      // Update gauge progress
      const circumference = 565;
      const offset = circumference - (progress * circumference);
      gaugeProgress.style.strokeDashoffset = offset;

      // Update gauge color based on score
      let color = '#10b981'; // Low - Green
      if (targetScore >= 80) color = '#ef4444'; // Critical - Red
      else if (targetScore >= 60) color = '#ef4444'; // High - Red
      else if (targetScore >= 35) color = '#f59e0b'; // Medium - Amber

      gaugeProgress.style.stroke = color;

      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        resolve();
      }
    }

    requestAnimationFrame(update);
  });
}

// ═══════════════════════════════════════════════════════════════
// RENDER RESULTS
// ═══════════════════════════════════════════════════════════════

function renderResults(data) {
  const report = data.report || {};
  const osintData = data.osint_data || {};

  // Threat Score
  const riskScore = report.risk_score || 0;
  const riskLevelMap = {
    low: { label: 'LOW', color: '#10b981' },
    medium: { label: 'MEDIUM', color: '#f59e0b' },
    high: { label: 'HIGH', color: '#ef4444' },
    critical: { label: 'CRITICAL', color: '#ef4444' },
  };

  const riskLevel = report.risk_level || 'low';
  const riskInfo = riskLevelMap[riskLevel] || riskLevelMap.low;

  threatLevel.textContent = riskInfo.label;
  threatLevel.className = `threat-level ${riskLevel}`;
  threatSummary.textContent = report.summary || 'No summary available.';

  // Animate gauge
  animateThreatGauge(riskScore);

  // Executive Summary
  summaryText.textContent = report.summary || 'Analysis complete. Review findings and recommendations below.';

  // Key Findings
  findingsList.innerHTML = '';
  if (report.findings && Array.isArray(report.findings)) {
    report.findings.forEach((finding, idx) => {
      const item = document.createElement('div');
      item.className = 'finding-item';
      item.innerHTML = `
        <div class="finding-icon">⚠</div>
        <div class="finding-text">
          <strong>[${String(idx + 1).padStart(2, '0')}]</strong> ${finding}
        </div>
        <button class="copy-btn" title="Copy">📋</button>
      `;
      item.querySelector('.copy-btn').addEventListener('click', () => {
        copyToClipboard(finding);
      });
      findingsList.appendChild(item);
    });
  }

  // Threats Identified
  threatsList.innerHTML = '';
  if (report.threats && Array.isArray(report.threats)) {
    report.threats.forEach((threat) => {
      const item = document.createElement('div');
      item.className = 'threat-item';
      item.innerHTML = `
        <div class="threat-icon">☠</div>
        <div class="threat-text">${threat}</div>
        <button class="copy-btn" title="Copy">📋</button>
      `;
      item.querySelector('.copy-btn').addEventListener('click', () => {
        copyToClipboard(threat);
      });
      threatsList.appendChild(item);
    });
  }

  // Recommendations
  recommendationsList.innerHTML = '';
  if (report.recommendations && Array.isArray(report.recommendations)) {
    report.recommendations.forEach((rec, idx) => {
      const item = document.createElement('div');
      item.className = 'recommendation-item';
      item.innerHTML = `
        <div class="recommendation-icon">✓</div>
        <div class="recommendation-text">
          <strong>[${String(idx + 1).padStart(2, '0')}]</strong> ${rec}
        </div>
        <button class="copy-btn" title="Copy">📋</button>
      `;
      item.querySelector('.copy-btn').addEventListener('click', () => {
        copyToClipboard(rec);
      });
      recommendationsList.appendChild(item);
    });
  }

  // OSINT Data
  renderOsintData('shodan', osintData.shodan || {}, shodanData);
  renderOsintData('whois', osintData.whois || {}, whoisData);
  renderOsintData('github', osintData.github || {}, githubData);
  renderOsintData('social_scan', osintData.social_scan || {}, socialData);

  // Critical Alert
  if (riskLevel === 'critical') {
    criticalAlert.style.display = 'flex';
  } else {
    criticalAlert.style.display = 'none';
  }
}

function renderOsintData(name, data, container) {
  container.innerHTML = '';

  if (!data || Object.keys(data).length === 0) {
    container.innerHTML = '<div style="padding: 12px; color: var(--text-secondary);">No data available</div>';
    return;
  }

  const lines = [];
  Object.entries(data).forEach(([key, value]) => {
    let displayValue = value;
    if (Array.isArray(value)) {
      displayValue = value.join(', ');
    } else if (typeof value === 'object') {
      displayValue = JSON.stringify(value);
    }
    lines.push(`<div class="osint-item"><span class="osint-key">${key}:</span> <span class="osint-value">${displayValue}</span></div>`);
  });

  container.innerHTML = lines.join('');
}

// ═══════════════════════════════════════════════════════════════
// OSINT DATA TOGGLE
// ═══════════════════════════════════════════════════════════════

document.querySelectorAll('.osint-card .card-header.clickable').forEach(header => {
  header.addEventListener('click', () => {
    const toggle = header.getAttribute('data-toggle');
    const content = document.getElementById(toggle);
    const isOpen = content.style.display !== 'none';

    content.style.display = isOpen ? 'none' : 'block';
    header.classList.toggle('open');
  });
});

// ═══════════════════════════════════════════════════════════════
// COPY TO CLIPBOARD
// ═══════════════════════════════════════════════════════════════

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard', 'success');
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
}

// ═══════════════════════════════════════════════════════════════
// SCAN HISTORY
// ═══════════════════════════════════════════════════════════════

function addToScanHistory(target, riskLevel, riskScore) {
  const now = new Date();
  const dateStr = now.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const entry = {
    target,
    riskLevel,
    riskScore,
    date: dateStr,
    timestamp: now.getTime(),
  };

  scanHistory.unshift(entry);
  if (scanHistory.length > 5) scanHistory.pop();

  renderScanHistory();
}

function renderScanHistory() {
  scanHistory_el.innerHTML = '';
  scanHistory.forEach(entry => {
    const item = document.createElement('div');
    item.className = 'scan-history-item';
    item.innerHTML = `
      <div>
        <span class="history-target">${entry.target}</span>
      </div>
      <div style="display: flex; gap: 12px; align-items: center;">
        <span class="history-badge ${entry.riskLevel}">${entry.riskLevel.toUpperCase()}</span>
        <span class="history-date">${entry.date}</span>
      </div>
    `;
    item.addEventListener('click', () => {
      targetInput.value = entry.target;
      targetInput.dispatchEvent(new Event('input'));
      window.scrollTo(0, 0);
    });
    scanHistory_el.appendChild(item);
  });
}

// ═══════════════════════════════════════════════════════════════
// TOAST NOTIFICATION
// ═══════════════════════════════════════════════════════════════

function showToast(message, type = 'info') {
  const icons = { error: '✕', success: '✓', info: 'ℹ' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;

  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = '0.3s ease';
    setTimeout(() => toast.remove(), 350);
  }, 4000);
}

// Add toast styles
const toastStyle = document.createElement('style');
toastStyle.textContent = `
  .toast-container {
    position: fixed;
    bottom: 20px;
    right: 20px;
    z-index: 10000;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .toast {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 12px 16px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    animation: slideInRight 0.3s ease-out;
    font-family: 'Orbitron', monospace;
  }

  .toast.success {
    border-color: var(--accent-green);
    color: var(--accent-green);
  }

  .toast.error {
    border-color: var(--accent-red);
    color: var(--accent-red);
  }

  @keyframes slideInRight {
    from {
      opacity: 0;
      transform: translateX(20px);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }
`;
document.head.appendChild(toastStyle);

// ═══════════════════════════════════════════════════════════════
// MAIN SCAN FUNCTION
// ═══════════════════════════════════════════════════════════════

async function performScan(target) {
  if (scanInProgress) return;
  scanInProgress = true;

  // Hide empty state and previous results
  emptyState.style.display = 'none';
  resultsSection.style.display = 'none';
  scanAnimation.style.display = 'block';
  aiAnalysisPhase.style.display = 'none';
  criticalAlert.style.display = 'none';

  // Reset collectors
  collectorsGrid.querySelectorAll('.collector-card').forEach(card => {
    card.classList.remove('complete', 'running');
    card.querySelector('.progress-mini').style.width = '20%';
  });

  // Disable input
  scanBtn.disabled = true;
  scanBtn.querySelector('.btn-scan-text').textContent = 'SCANNING...';
  scanBtn.querySelector('.btn-scan-spinner').style.display = 'flex';

  try {
    // Phase 1: Initialize
    await animatePhase1();

    // Determine collectors needed
    const type = detectTargetType(target);
    const collectors = ['shodan', 'whois', 'hibp', 'github', 'google', 'social_scan'];

    // Phase 2: Collecting
    await animatePhase2(collectors);

    // Make API call
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      if (response.status === 429) {
        throw new Error('Rate limited');
      }
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    lastScanData = data;

    // Phase 3: AI Analysis
    await animatePhase3();

    // Phase 4: Complete
    await animatePhase4();

    // Render results
    await new Promise(resolve => setTimeout(resolve, 500));
    scanAnimation.style.display = 'none';
    resultsSection.style.display = 'block';
    renderResults(data);

    // Update scan counter
    scanCount++;
    scanCountDisplay.textContent = scanCount;

    // Add to history
    addToScanHistory(target, data.report?.risk_level || 'low', data.report?.risk_score || 0);

    showToast(`Scan complete for ${target}`, 'success');

  } catch (error) {
    console.error('Scan error:', error);
    scanAnimation.style.display = 'none';

    if (error.message === 'Rate limited') {
      showToast('Rate limited. Please wait before scanning again.', 'error');
    } else if (error.name === 'TimeoutError') {
      showToast('Scan timed out. Backend may be offline.', 'error');
    } else {
      showToast('Scan failed. Check backend connection.', 'error');
    }

    emptyState.style.display = 'flex';

  } finally {
    scanBtn.disabled = false;
    scanBtn.querySelector('.btn-scan-text').textContent = 'INITIATE SCAN';
    scanBtn.querySelector('.btn-scan-spinner').style.display = 'none';
    scanInProgress = false;
  }
}

// ═══════════════════════════════════════════════════════════════
// EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════

scanBtn.addEventListener('click', () => {
  const target = targetInput.value.trim();
  if (!target) {
    targetInput.focus();
    showToast('Please enter a target to scan.', 'error');
    return;
  }
  performScan(target);
});

targetInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scanBtn.click();
});

// PDF Export
pdfBtn.addEventListener('click', async () => {
  const target = targetInput.value.trim() || lastScanData?.target;
  if (!target) {
    showToast('Run a scan first.', 'error');
    return;
  }

  pdfBtn.disabled = true;
  pdfBtn.textContent = 'GENERATING...';

  try {
    const res = await fetch(`${API_BASE}/scan/pdf`, {
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
    a.download = `reconmind_${target.replace(/[^\w.-]/g, '_')}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('PDF exported.', 'success');
  } catch {
    showToast('PDF export failed.', 'error');
  } finally {
    pdfBtn.disabled = false;
    pdfBtn.innerHTML = '<span>📄</span> DOWNLOAD PDF REPORT';
  }
});

// JSON Export
jsonBtn.addEventListener('click', () => {
  if (!lastScanData) {
    showToast('Run a scan first.', 'error');
    return;
  }

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

// New Scan
newScanBtn.addEventListener('click', () => {
  targetInput.value = '';
  targetInput.focus();
  autoDetectBadge.textContent = 'AWAITING INPUT';
  resultsSection.style.display = 'none';
  emptyState.style.display = 'flex';
  criticalAlert.style.display = 'none';
});

/* ═══════════════════════════════════════════════════════════════
   All Copyright Reserved © 2025 ReconMind
   AI-Powered OSINT Intelligence Engine
   ═══════════════════════════════════════════════════════════════ */

