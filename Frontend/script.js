// ============================================
// RECONMIND - JAVASCRIPT
// AI-Powered OSINT Intelligence Engine
// ============================================

// API Configuration
const API_BASE = "http://localhost:5000"; // Change to Railway URL for production

// Global State
let scansToday = 0;
let scanHistory = [];
let currentScanResult = null;
let isScanning = false;

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initializeParticleBackground();
    initializeTypewriter();
    setupEventListeners();
    loadScansToday();
    loadScanHistory();
});

// ============================================
// PARTICLE BACKGROUND
// ============================================

function initializeParticleBackground() {
    const canvas = document.getElementById('particleCanvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const particles = [];
    const particleCount = 80;
    
    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.radius = Math.random() * 1.5;
            this.vx = (Math.random() - 0.5) * 0.3;
            this.vy = (Math.random() - 0.5) * 0.3;
            this.opacity = Math.random() * 0.5 + 0.1;
        }
        
        update() {
            this.x += this.vx;
            this.y += this.vy;
            
            if (this.x < 0) this.x = canvas.width;
            if (this.x > canvas.width) this.x = 0;
            if (this.y < 0) this.y = canvas.height;
            if (this.y > canvas.height) this.y = 0;
        }
        
        draw() {
            ctx.fillStyle = `rgba(0, 245, 255, ${this.opacity})`;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fill();
        }
    }
    
    // Initialize particles
    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }
    
    // Draw lines between nearby particles
    function drawLines() {
        ctx.strokeStyle = 'rgba(0, 245, 255, 0.1)';
        ctx.lineWidth = 0.5;
        
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance < 150) {
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
    }
    
    // Animation loop
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        particles.forEach(particle => {
            particle.update();
            particle.draw();
        });
        
        drawLines();
        requestAnimationFrame(animate);
    }
    
    animate();
    
    // Resize handler
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ============================================
// TYPEWRITER EFFECT
// ============================================

function initializeTypewriter() {
    const phrases = [
        "Scanning the digital footprint of any target...",
        "6 collectors. 1 AI. Complete threat intelligence.",
        "Know what the internet knows about you.",
        "Real-time OSINT analysis powered by Groq AI"
    ];
    
    let currentPhraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    const typewriterElement = document.getElementById('typewriter');
    
    function type() {
        const currentPhrase = phrases[currentPhraseIndex];
        
        if (isDeleting) {
            charIndex--;
        } else {
            charIndex++;
        }
        
        typewriterElement.textContent = currentPhrase.substring(0, charIndex);
        
        let typeSpeed = isDeleting ? 30 : 50;
        
        if (!isDeleting && charIndex === currentPhrase.length) {
            typeSpeed = 2000;
            isDeleting = true;
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            currentPhraseIndex = (currentPhraseIndex + 1) % phrases.length;
            typeSpeed = 500;
        }
        
        setTimeout(type, typeSpeed);
    }
    
    type();
}

// ============================================
// EVENT LISTENERS
// ============================================

function setupEventListeners() {
    const targetInput = document.getElementById('targetInput');
    const scanButton = document.getElementById('scanButton');
    const newScanButton = document.getElementById('newScanButton');
    const downloadPdfButton = document.getElementById('downloadPdfButton');
    const downloadJsonButton = document.getElementById('downloadJsonButton');
    
    // Input detection
    targetInput.addEventListener('input', handleInputDetection);
    
    // Scan button
    scanButton.addEventListener('click', initiateScanning);
    
    // New scan button
    newScanButton.addEventListener('click', resetToScan);
    
    // Download buttons
    downloadPdfButton.addEventListener('click', downloadPdfReport);
    downloadJsonButton.addEventListener('click', downloadJsonReport);
}

// ============================================
// INPUT DETECTION
// ============================================

function handleInputDetection() {
    const input = document.getElementById('targetInput');
    const badge = document.getElementById('detectionBadge');
    const value = input.value.trim();
    
    badge.classList.remove('ip-address', 'email', 'domain', 'username', 'hidden');
    badge.textContent = '';
    
    if (!value) {
        badge.classList.add('hidden');
        return;
    }
    
    // IP Address detection (IPv4)
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(value)) {
        badge.textContent = '[IP ADDRESS]';
        badge.classList.add('ip-address');
        return;
    }
    
    // Email detection
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (emailRegex.test(value)) {
        badge.textContent = '[EMAIL]';
        badge.classList.add('email');
        return;
    }
    
    // Domain detection
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
    if (domainRegex.test(value)) {
        badge.textContent = '[DOMAIN]';
        badge.classList.add('domain');
        return;
    }
    
    // Username detection (alphanumeric and underscore, 3-50 chars)
    const usernameRegex = /^[a-zA-Z0-9_]{3,50}$/;
    if (usernameRegex.test(value)) {
        badge.textContent = '[USERNAME]';
        badge.classList.add('username');
        return;
    }
    
    // Default: hidden
    badge.classList.add('hidden');
}

// ============================================
// SCANNING FLOW
// ============================================

async function initiateScanning() {
    const targetInput = document.getElementById('targetInput');
    const target = targetInput.value.trim();
    
    if (!target) {
        showToast('Please enter a target to scan', 'error');
        return;
    }
    
    if (isScanning) {
        showToast('Scan already in progress', 'warning');
        return;
    }
    
    isScanning = true;
    
    // Hide hero and input section, show scanning section
    document.getElementById('heroSection').style.display = 'none';
    document.getElementById('scanSection').style.display = 'none';
    document.getElementById('resultsSection').classList.add('hidden');
    document.getElementById('scanningSection').classList.remove('hidden');
    
    // Disable scan button
    document.getElementById('scanButton').disabled = true;
    
    try {
        // Phase 1: Initialize
        await runPhase1();
        
        // Phase 2: Collect
        await runPhase2(target);
        
        // Phase 3: AI Analysis
        await runPhase3(target);
        
        // Phase 4: Complete
        await runPhase4();
        
        // Fetch actual results
        await fetchAndDisplayResults(target);
        
        // Increment scan counter
        scansToday++;
        updateScansToday();
        
        // Add to history
        addToScanHistory(target);
        
    } catch (error) {
        console.error('Scan error:', error);
        showToast(`Scan failed: ${error.message}`, 'error');
        resetToScan();
    } finally {
        isScanning = false;
        document.getElementById('scanButton').disabled = false;
    }
}

async function runPhase1() {
    const phase1 = document.getElementById('phase1');
    phase1.classList.remove('hidden');
    
    const progressFill = phase1.querySelector('.progress-fill');
    
    return new Promise(resolve => {
        let width = 5;
        const interval = setInterval(() => {
            width += Math.random() * 10;
            if (width >= 30) {
                width = 30;
                clearInterval(interval);
                resolve();
            }
            progressFill.style.width = width + '%';
        }, 100);
    });
}

async function runPhase2(target) {
    document.getElementById('phase1').classList.add('hidden');
    const phase2 = document.getElementById('phase2');
    phase2.classList.remove('hidden');
    
    const collectors = [
        { name: 'SHODAN', icon: '🔍', description: 'Scanning open ports and services...' },
        { name: 'WHOIS', icon: '📋', description: 'Fetching domain registration data...' },
        { name: 'HIBP', icon: '⚠️', description: 'Checking breach databases...' },
        { name: 'GITHUB', icon: '👨‍💻', description: 'Analyzing public repositories...' },
        { name: 'GOOGLE', icon: '🔎', description: 'Running dork queries...' },
        { name: 'SOCIAL', icon: '🌐', description: 'Mapping digital footprint...' }
    ];
    
    const collectorsGrid = document.getElementById('collectorsGrid');
    collectorsGrid.innerHTML = '';
    
    // Add collector cards
    collectors.forEach((collector, index) => {
        const card = createCollectorCard(collector);
        collectorsGrid.appendChild(card);
    });
    
    // Stagger collector animations
    const cards = document.querySelectorAll('.collector-card');
    return new Promise(resolve => {
        let completedCount = 0;
        
        cards.forEach((card, index) => {
            setTimeout(() => {
                animateCollectorCard(card, () => {
                    completedCount++;
                    if (completedCount === cards.length) {
                        resolve();
                    }
                });
            }, (index + 1) * 1000);
        });
    });
}

function createCollectorCard(collector) {
    const card = document.createElement('div');
    card.className = 'collector-card';
    card.innerHTML = `
        <div class="collector-header">
            <span class="collector-name">${collector.name}</span>
            <span class="collector-icon">${collector.icon}</span>
        </div>
        <div class="collector-description">● ${collector.description}</div>
        <div class="collector-progress">
            <span class="collector-status">RUNNING</span>
            <div class="collector-bar">
                <div class="collector-bar-fill"></div>
            </div>
        </div>
    `;
    return card;
}

function animateCollectorCard(card, callback) {
    const barFill = card.querySelector('.collector-bar-fill');
    let width = 0;
    
    const interval = setInterval(() => {
        width += Math.random() * 30;
        if (width >= 100) {
            width = 100;
            clearInterval(interval);
            
            // Mark as complete
            card.classList.add('complete');
            card.querySelector('.collector-status').textContent = 'COMPLETE';
            
            setTimeout(callback, 300);
        }
        barFill.style.width = width + '%';
    }, 150);
    
    // Update main progress bar
    updateProgressBar(phase2, 40 + Math.random() * 40);
}

function updateProgressBar(phaseElement, targetWidth) {
    const progressFill = phaseElement.querySelector('.progress-fill');
    const currentWidth = parseFloat(progressFill.style.width) || 0;
    const newWidth = Math.max(currentWidth, targetWidth);
    progressFill.style.width = newWidth + '%';
}

async function runPhase3(target) {
    document.getElementById('phase2').classList.add('hidden');
    const phase3 = document.getElementById('phase3');
    phase3.classList.remove('hidden');
    
    const progressFill = phase3.querySelector('.progress-fill');
    
    // Streaming text effect
    const streamingTexts = [
        'Correlating 6 data sources...',
        'Identifying attack vectors...',
        'Analyzing threat patterns...',
        'Calculating risk scores...',
        'Generating recommendations...'
    ];
    
    return new Promise(resolve => {
        let currentText = 0;
        
        const cycleText = () => {
            if (currentText < streamingTexts.length) {
                typeStreamingText(streamingTexts[currentText], () => {
                    currentText++;
                    setTimeout(cycleText, 400);
                });
                
                // Incrementally fill progress
                const increment = 95 / streamingTexts.length;
                progressFill.style.width = (40 + currentText * increment) + '%';
            } else {
                progressFill.style.width = '95%';
                resolve();
            }
        };
        
        cycleText();
    });
}

function typeStreamingText(text, callback) {
    const element = document.getElementById('streamingText');
    let charIndex = 0;
    
    // Clear previous text
    element.textContent = '';
    
    const type = () => {
        if (charIndex < text.length) {
            element.textContent += text[charIndex];
            charIndex++;
            setTimeout(type, 30);
        } else {
            setTimeout(callback, 300);
        }
    };
    
    type();
}

async function runPhase4() {
    document.getElementById('phase3').classList.add('hidden');
    const phase4 = document.getElementById('phase4');
    phase4.classList.remove('hidden');
    
    return new Promise(resolve => {
        setTimeout(() => {
            const progressFill = phase4.querySelector('.progress-fill');
            progressFill.style.width = '100%';
            resolve();
        }, 800);
    });
}

async function fetchAndDisplayResults(target) {
    // Hide scanning section
    document.getElementById('scanningSection').classList.add('hidden');
    
    try {
        // Make API call to /scan endpoint
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target })
        });
        
        if (!response.ok) {
            throw new Error(`API error: ${response.statusText}`);
        }
        
        const data = await response.json();
        currentScanResult = data;
        
        // Display results
        displayResults(data);
        
        // Show results section
        document.getElementById('resultsSection').classList.remove('hidden');
        
    } catch (error) {
        console.error('Error fetching results:', error);
        showToast('Error fetching results from API', 'error');
        
        // Show demo results for offline testing
        displayDemoResults(target);
        document.getElementById('resultsSection').classList.remove('hidden');
    }
    
    // Scroll to results
    setTimeout(() => {
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
    }, 300);
}

// ============================================
// RESULTS DISPLAY
// ============================================

function displayResults(data) {
    const { report, osint_data } = data;
    
    // Threat Score
    displayThreatScore(report.risk_score, report.risk_level);
    
    // Summary
    displaySummary(report.summary);
    
    // Findings
    displayFindings(report.findings || []);
    
    // Threats
    displayThreats(report.threats || []);
    
    // Recommendations
    displayRecommendations(report.recommendations || []);
    
    // OSINT Data
    displayOsintData(osint_data);
    
    // Check if critical
    if (report.risk_level === 'CRITICAL') {
        showCriticalBanner();
    }
}

function displayThreatScore(score, riskLevel) {
    const gaugeScore = document.getElementById('gaugeScore');
    const threatBadge = document.getElementById('threatBadge');
    const threatDescription = document.getElementById('threatDescription');
    const gaugeProgress = document.getElementById('gaugeProgress');
    
    // Animate score from 0 to final
    animateValue(0, score, 2000, (value) => {
        gaugeScore.textContent = Math.round(value);
    });
    
    // Update badge and description based on risk level
    const riskConfig = {
        'LOW': { badge: 'LOW', desc: 'No significant threats detected', color: 'low' },
        'MEDIUM': { badge: 'MEDIUM', desc: 'Some vulnerabilities present', color: 'medium' },
        'HIGH': { badge: 'HIGH', desc: 'Multiple threats identified', color: 'high' },
        'CRITICAL': { badge: 'CRITICAL', desc: 'Immediate action required', color: 'critical' }
    };
    
    const config = riskConfig[riskLevel] || riskConfig['LOW'];
    threatBadge.textContent = config.badge;
    threatBadge.className = `threat-badge ${config.color}`;
    threatDescription.textContent = config.desc;
    
    // Animate gauge circle
    const circumference = 2 * Math.PI * 90; // radius = 90
    const offset = circumference - (score / 100) * circumference;
    
    // Set gradient color based on score
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
    gradient.setAttribute('id', 'gaugeGradient');
    
    let color1, color2;
    if (score <= 34) {
        color1 = '#10b981';
        color2 = '#06d6a0';
    } else if (score <= 59) {
        color1 = '#f59e0b';
        color2 = '#fbbf24';
    } else if (score <= 79) {
        color1 = '#ef4444';
        color2 = '#f87171';
    } else {
        color1 = '#ef4444';
        color2 = '#dc2626';
    }
    
    const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
    stop1.setAttribute('offset', '0%');
    stop1.setAttribute('stop-color', color1);
    
    const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
    stop2.setAttribute('offset', '100%');
    stop2.setAttribute('stop-color', color2);
    
    gradient.appendChild(stop1);
    gradient.appendChild(stop2);
    
    // Remove existing defs
    const svg = document.querySelector('.threat-gauge');
    const existingDefs = svg.querySelector('defs');
    if (existingDefs) existingDefs.remove();
    svg.insertBefore(defs, svg.firstChild);
    defs.appendChild(gradient);
    
    // Animate stroke offset
    setTimeout(() => {
        gaugeProgress.style.strokeDashoffset = offset + 'px';
    }, 500);
}

function displaySummary(summary) {
    document.getElementById('summaryText').textContent = summary || 'No summary available';
}

function displayFindings(findings) {
    const grid = document.getElementById('findingsGrid');
    grid.innerHTML = '';
    
    findings.forEach((finding, index) => {
        const card = document.createElement('div');
        card.className = 'finding-item';
        card.innerHTML = `
            <div class="finding-icon">⚠</div>
            <div class="finding-content">
                <div class="finding-number">[${String(index + 1).padStart(2, '0')}]</div>
                <div class="finding-text">${finding}</div>
                <div class="finding-actions">
                    <button class="copy-button" onclick="copyToClipboard('${finding}')">Copy</button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function displayThreats(threats) {
    const grid = document.getElementById('threatsGrid');
    grid.innerHTML = '';
    
    threats.forEach((threat, index) => {
        const card = document.createElement('div');
        card.className = 'threat-item';
        card.innerHTML = `
            <div class="threat-icon">☠</div>
            <div class="threat-content">
                <div class="threat-text">${threat}</div>
                <div class="finding-actions">
                    <button class="copy-button" onclick="copyToClipboard('${threat}')">Copy</button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function displayRecommendations(recommendations) {
    const grid = document.getElementById('recommendationsGrid');
    grid.innerHTML = '';
    
    recommendations.forEach((rec, index) => {
        const card = document.createElement('div');
        card.className = 'recommendation-item';
        card.innerHTML = `
            <div class="recommendation-icon">✓</div>
            <div class="recommendation-content">
                <div class="recommendation-number">[${String(index + 1).padStart(2, '0')}]</div>
                <div class="recommendation-text">${rec}</div>
                <div class="finding-actions">
                    <button class="copy-button" onclick="copyToClipboard('${rec}')">Copy</button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function displayOsintData(osintData) {
    const grid = document.getElementById('osintCardsGrid');
    grid.innerHTML = '';
    
    const collectors = [
        { key: 'shodan', name: 'SHODAN DATA', icon: '🔍' },
        { key: 'whois', name: 'WHOIS DATA', icon: '📋' },
        { key: 'hibp', name: 'HIBP DATA', icon: '⚠️' },
        { key: 'github', name: 'GITHUB DATA', icon: '👨‍💻' },
        { key: 'google', name: 'GOOGLE DATA', icon: '🔎' },
        { key: 'social_scan', name: 'SOCIAL SCAN DATA', icon: '🌐' }
    ];
    
    collectors.forEach(collector => {
        if (osintData[collector.key]) {
            const card = createOsintCard(collector, osintData[collector.key]);
            grid.appendChild(card);
        }
    });
}

function createOsintCard(collector, data) {
    const card = document.createElement('div');
    card.className = 'osint-card';
    
    const dataStr = JSON.stringify(data, null, 2);
    const dataLines = dataStr.split('\n').slice(0, 10).join('\n');
    
    card.innerHTML = `
        <div class="osint-card-header" onclick="toggleOsintCard(this)">
            <span class="osint-card-title">${collector.icon} ${collector.name}</span>
            <span class="osint-toggle">▼</span>
        </div>
        <div class="osint-card-content">
            <div class="osint-data">
                <pre>${escapeHtml(dataStr)}</pre>
            </div>
        </div>
    `;
    
    return card;
}

function toggleOsintCard(header) {
    header.classList.toggle('expanded');
    const content = header.nextElementSibling;
    
    if (header.classList.contains('expanded')) {
        content.style.maxHeight = content.scrollHeight + 'px';
    } else {
        content.style.maxHeight = '0';
    }
}

// ============================================
// DEMO RESULTS (for offline testing)
// ============================================

function displayDemoResults(target) {
    const demoReport = {
        risk_score: Math.floor(Math.random() * 100),
        risk_level: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)],
        summary: `Target "${target}" has been analyzed against multiple OSINT sources. Analysis reveals ${Math.random() > 0.5 ? 'moderate online presence with some security concerns' : 'limited public exposure with standard security profile'}. Further investigation may be warranted for sensitive operations.`,
        findings: [
            'Public exposure detected on major search engines',
            'Associated with multiple online platforms',
            'Historical data found in breach databases',
            'DNS records publicly accessible'
        ],
        threats: [
            'Potential phishing vectors identified',
            'Weak password patterns detected',
            'Social engineering risk present'
        ],
        recommendations: [
            'Enable two-factor authentication on all accounts',
            'Monitor credit reports regularly',
            'Use unique, strong passwords',
            'Configure privacy settings on social media'
        ]
    };
    
    const demoOsint = {
        shodan: { ports: [80, 443, 22], services: ['nginx', 'OpenSSH'] },
        whois: { registrar: 'Example Registrar', created: '2020-01-15' },
        hibp: { breaches: ['Example Breach 1', 'Example Breach 2'] },
        github: { repositories: 2, followers: 45 },
        google: { results: 'Multiple results found' },
        social_scan: { platforms: ['LinkedIn', 'Twitter'] }
    };
    
    displayResults({ report: demoReport, osint_data: demoOsint });
    currentScanResult = { report: demoReport, osint_data: demoOsint };
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function animateValue(start, end, duration, callback) {
    const startTime = Date.now();
    
    const animate = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function
        const easeProgress = progress < 0.5 
            ? 2 * progress * progress 
            : -1 + (4 - 2 * progress) * progress;
        
        const value = start + (end - start) * easeProgress;
        callback(value);
        
        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    };
    
    animate();
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'info');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function showCriticalBanner() {
    const banner = document.getElementById('criticalBanner');
    banner.classList.remove('hidden');
}

function hideCriticalBanner() {
    const banner = document.getElementById('criticalBanner');
    banner.classList.add('hidden');
}

// ============================================
// SCAN HISTORY
// ============================================

function addToScanHistory(target) {
    const historyItem = {
        target,
        riskLevel: currentScanResult?.report?.risk_level || 'UNKNOWN',
        riskScore: currentScanResult?.report?.risk_score || 0,
        timestamp: new Date().toLocaleTimeString()
    };
    
    scanHistory.unshift(historyItem);
    
    // Keep only last 5
    if (scanHistory.length > 5) {
        scanHistory.pop();
    }
    
    updateScanHistoryDisplay();
}

function loadScanHistory() {
    // Load from memory (cleared on refresh)
    updateScanHistoryDisplay();
}

function updateScanHistoryDisplay() {
    const grid = document.getElementById('scanHistoryGrid');
    grid.innerHTML = '';
    
    scanHistory.forEach((item, index) => {
        const card = document.createElement('div');
        card.className = 'history-item';
        
        const riskColor = getRiskColor(item.riskLevel);
        
        card.innerHTML = `
            <div class="history-target">${item.target}</div>
            <div class="history-risk">
                <span style="color: ${riskColor};">● ${item.riskLevel}</span>
                <span>${item.riskScore}/100</span>
            </div>
            <div class="history-date">${item.timestamp}</div>
        `;
        
        card.addEventListener('click', () => {
            document.getElementById('targetInput').value = item.target;
            handleInputDetection();
        });
        
        grid.appendChild(card);
    });
}

function getRiskColor(riskLevel) {
    switch(riskLevel) {
        case 'LOW': return '#10b981';
        case 'MEDIUM': return '#f59e0b';
        case 'HIGH': return '#ef4444';
        case 'CRITICAL': return '#dc2626';
        default: return '#999';
    }
}

// ============================================
// SCAN COUNTER
// ============================================

function loadScansToday() {
    // Load from sessionStorage to persist during the session
    const stored = sessionStorage.getItem('scansToday');
    scansToday = stored ? parseInt(stored) : 0;
    updateScansToday();
}

function updateScansToday() {
    document.getElementById('scansToday').textContent = scansToday;
    sessionStorage.setItem('scansToday', scansToday);
}

// ============================================
// NAVIGATION
// ============================================

function resetToScan() {
    hideCriticalBanner();
    document.getElementById('heroSection').style.display = 'flex';
    document.getElementById('scanSection').style.display = 'block';
    document.getElementById('scanningSection').classList.add('hidden');
    document.getElementById('resultsSection').classList.add('hidden');
    document.getElementById('targetInput').value = '';
    handleInputDetection();
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ============================================
// DOWNLOADS
// ============================================

async function downloadPdfReport() {
    if (!currentScanResult) {
        showToast('No scan results to download', 'warning');
        return;
    }
    
    try {
        const target = document.getElementById('targetInput').value;
        const response = await fetch(`${API_BASE}/scan/pdf`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target })
        });
        
        if (!response.ok) {
            throw new Error('PDF generation failed');
        }
        
        const blob = await response.blob();
        downloadFile(blob, `reconmind-report-${Date.now()}.pdf`, 'application/pdf');
        showToast('PDF report downloaded', 'success');
        
    } catch (error) {
        console.error('PDF download error:', error);
        showToast('Failed to download PDF', 'error');
    }
}

function downloadJsonReport() {
    if (!currentScanResult) {
        showToast('No scan results to download', 'warning');
        return;
    }
    
    const json = JSON.stringify(currentScanResult, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    downloadFile(blob, `reconmind-report-${Date.now()}.json`, 'application/json');
    showToast('JSON report downloaded', 'success');
}

function downloadFile(blob, filename, type) {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.type = type;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
}

// ============================================
// RESPONSIVE BEHAVIOR
// ============================================

window.addEventListener('resize', () => {
    const canvas = document.getElementById('particleCanvas');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

// Prevent zooming on mobile
document.addEventListener('touchmove', (e) => {
    if (e.scale !== 1) {
        e.preventDefault();
    }
}, { passive: false });
