const API_BASE = "http://localhost:5000";

const targetInput = document.getElementById("targetInput");
const targetBadge = document.getElementById("targetBadge");
const scanBtn = document.getElementById("scanBtn");

const scanExperience = document.getElementById("scanExperience");
const results = document.getElementById("results");

const progressFill = document.getElementById("progressFill");

const phaseTitle = document.getElementById("phaseTitle");
const phaseSubtitle = document.getElementById("phaseSubtitle");

const collectorsGrid = document.getElementById("collectorsGrid");

const aiAnalysis = document.getElementById("aiAnalysis");
const aiStreaming = document.getElementById("aiStreaming");

const scanCounter = document.getElementById("scanCounter");

let scansToday = 0;
let currentResponse = null;
let scanHistory = [];

const phrases = [
  "Scanning the digital footprint of any target...",
  "6 collectors. 1 AI. Complete threat intelligence.",
  "Know what the internet knows about you.",
  "Real-time OSINT analysis powered by Groq AI"
];

let phraseIndex = 0;
let charIndex = 0;

const typewriterText = document.getElementById("typewriterText");

function typeWriter(){

  const current = phrases[phraseIndex];

  typewriterText.textContent =
    current.slice(0, charIndex++);

  if(charIndex <= current.length){

    setTimeout(typeWriter, 40);

  }else{

    setTimeout(() => {

      charIndex = 0;
      phraseIndex =
        (phraseIndex + 1) % phrases.length;

      typeWriter();

    }, 2000);

  }

}

typeWriter();

function detectTargetType(value){

  const ipRegex =
    /^(?:\d{1,3}\.){3}\d{1,3}$/;

  const emailRegex =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const domainRegex =
    /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

  if(ipRegex.test(value)){

    targetBadge.textContent = "IP ADDRESS";
    targetBadge.style.borderColor = "#00f5ff";

  }else if(emailRegex.test(value)){

    targetBadge.textContent = "EMAIL";
    targetBadge.style.borderColor = "#7c3aed";

  }else if(domainRegex.test(value)){

    targetBadge.textContent = "DOMAIN";
    targetBadge.style.borderColor = "#f59e0b";

  }else{

    targetBadge.textContent = "USERNAME";
    targetBadge.style.borderColor = "#10b981";

  }

}

targetInput.addEventListener("input", (e) => {
  detectTargetType(e.target.value);
});

const collectors = [
  ["SHODAN","Scanning open ports and services..."],
  ["WHOIS","Fetching domain registration data..."],
  ["HIBP","Checking breach databases..."],
  ["GITHUB","Analyzing public repositories..."],
  ["GOOGLE","Running dork queries..."],
  ["SOCIAL SCAN","Mapping digital footprint..."]
];

function renderCollectors(){

  collectorsGrid.innerHTML = "";

  collectors.forEach((collector, index) => {

    const card = document.createElement("div");

    card.className = "collector-card";

    card.id = `collector-${index}`;

    card.innerHTML = `
      <div class="collector-top">
        <div class="collector-name">
          ${collector[0]}
        </div>

        <div class="collector-status">
          PENDING
        </div>
      </div>

      <div>
        ${collector[1]}
      </div>
    `;

    collectorsGrid.appendChild(card);

  });

}

async function startScan(){

  const target = targetInput.value.trim();

  if(!target) return;

  scansToday++;
  scanCounter.textContent = scansToday;

  results.classList.add("hidden");
  scanExperience.classList.remove("hidden");

  renderCollectors();

  phaseTitle.textContent = "INITIALIZING";
  phaseSubtitle.textContent =
    "ReconMind engine initializing...";

  progressFill.style.width = "5%";

  setTimeout(() => {

    phaseTitle.textContent = "COLLECTING";
    phaseSubtitle.textContent =
      "Running OSINT collectors...";

  }, 500);

  const fakeCollectors = collectors.map(
    (_, index) => {

      return new Promise(resolve => {

        setTimeout(() => {

          const card =
            document.getElementById(
              `collector-${index}`
            );

          card.classList.add("running");

          card.querySelector(
            ".collector-status"
          ).textContent = "RUNNING";

          setTimeout(() => {

            card.classList.remove("running");

            card.classList.add("complete");

            card.querySelector(
              ".collector-status"
            ).textContent =
              "COMPLETE ✓";

            progressFill.style.width =
              `${20 + ((index + 1) * 10)}%`;

            resolve();

          }, 1200 + (index * 250));

        }, index * 450);

      });

    }
  );

  const responsePromise = fetch(
    `${API_BASE}/scan`,
    {
      method:"POST",

      headers:{
        "Content-Type":"application/json"
      },

      body:JSON.stringify({
        target
      })
    }
  )
  .then(res => {
    if (!res.ok) {
      throw new Error(`Backend error: HTTP ${res.status}`);
    }
    return res.json();
  })
  .catch(err => {
    console.error('❌ Scan failed:', err.message);
    console.error('Backend URL:', API_BASE);
    alert(`Scan failed!\n\nError: ${err.message}\n\nMake sure backend is running at: ${API_BASE}\n\nRun: python Backend/app.py`);
    scanBtn.disabled = false;
    scanExperience.classList.add("hidden");
    throw err;
  });

  const response = await responsePromise;

  currentResponse = response;

  await Promise.all(fakeCollectors);

  aiAnalysis.classList.remove("hidden");

  phaseTitle.textContent = "AI ANALYSIS";

  phaseSubtitle.textContent =
    "Groq Llama 3.3 70B analyzing threat vectors...";

  const aiLines = [
    "Correlating 6 data sources...",
    "Identifying attack vectors...",
    "Calculating risk score...",
    "Generating recommendations..."
  ];

  for(let i = 0; i < aiLines.length; i++){

    aiStreaming.textContent = aiLines[i];

    progressFill.style.width =
      `${75 + (i * 5)}%`;

    await new Promise(r => setTimeout(r, 900));

  }

  progressFill.style.width = "100%";

  phaseTitle.textContent = "COMPLETE";

  phaseSubtitle.textContent =
    "ANALYSIS COMPLETE";

  setTimeout(() => {
    renderResults(response);
  }, 800);

}

scanBtn.addEventListener("click", startScan);

function animateGauge(score){

  const gauge =
    document.getElementById("gaugeProgress");

  const scoreNumber =
    document.getElementById("scoreNumber");

  const scoreLabel =
    document.getElementById("scoreLabel");

  const radius = 90;

  const circumference =
    2 * Math.PI * radius;

  const offset =
    circumference -
    ((score / 100) * circumference);

  gauge.style.strokeDashoffset = offset;

  let current = 0;

  const interval = setInterval(() => {

    current++;

    scoreNumber.textContent = current;

    if(current >= score){

      clearInterval(interval);

    }

  }, 20);

  if(score < 35){

    gauge.style.stroke = "#10b981";
    scoreLabel.textContent = "LOW";

  }else if(score < 60){

    gauge.style.stroke = "#f59e0b";
    scoreLabel.textContent = "MEDIUM";

  }else if(score < 80){

    gauge.style.stroke = "#ef4444";
    scoreLabel.textContent = "HIGH";

  }else{

    gauge.style.stroke = "#ff1f1f";
    scoreLabel.textContent = "CRITICAL";

  }

}

function createItem(
  container,
  text,
  icon,
  index
){

  const item =
    document.createElement("div");

  item.className = "result-item";

  item.innerHTML = `
    <div class="result-left">

      <div>
        ${icon}
      </div>

      <div>
        [${String(index + 1).padStart(2,"0")}]
        ${text}
      </div>

    </div>

    <button class="copy-btn">
      ⧉
    </button>
  `;

  item.querySelector(".copy-btn")
    .onclick = () => {

      navigator.clipboard.writeText(text);

    };

  container.appendChild(item);

}

function renderResults(response){

  scanExperience.classList.add("hidden");

  results.classList.remove("hidden");

  const {
    report,
    osint_data
  } = response;

  animateGauge(report.risk_score || 0);

  document.getElementById(
    "summaryText"
  ).textContent =
    report.summary ||
    "No summary available.";

  document.getElementById(
    "riskSummary"
  ).textContent =
    report.risk_level;

  if(report.risk_score >= 80){

    document.getElementById(
      "criticalBanner"
    ).classList.remove("hidden");

  }

  const findingsContainer =
    document.getElementById(
      "findingsContainer"
    );

  findingsContainer.innerHTML = "";

  (report.findings || []).forEach(
    (finding, index) => {

      createItem(
        findingsContainer,
        finding,
        "⚠",
        index
      );

    }
  );

  const threatsContainer =
    document.getElementById(
      "threatsContainer"
    );

  threatsContainer.innerHTML = "";

  (report.threats || []).forEach(
    (threat, index) => {

      createItem(
        threatsContainer,
        threat,
        "☠",
        index
      );

    }
  );

  const recommendationsContainer =
    document.getElementById(
      "recommendationsContainer"
    );

  recommendationsContainer.innerHTML = "";

  (report.recommendations || []).forEach(
    (recommendation, index) => {

      createItem(
        recommendationsContainer,
        recommendation,
        "✓",
        index
      );

    }
  );

  const osintContainer =
    document.getElementById(
      "osintContainer"
    );

  osintContainer.innerHTML = "";

  Object.entries(osint_data || {})
    .forEach(([key, value]) => {

      const wrapper =
        document.createElement("div");

      wrapper.className = "collapsible";

      wrapper.innerHTML = `
        <div class="collapsible-header">
          ${key.toUpperCase()} DATA ▼
        </div>

        <div class="collapsible-content">
${JSON.stringify(value, null, 2)}
        </div>
      `;

      wrapper.querySelector(
        ".collapsible-header"
      ).onclick = () => {

        const content =
          wrapper.querySelector(
            ".collapsible-content"
          );

        content.style.display =
          content.style.display === "block"
          ? "none"
          : "block";

      };

      osintContainer.appendChild(wrapper);

    });

  scanHistory.unshift({
    target:targetInput.value,
    response,
    date:new Date().toLocaleString(),
    level:report.risk_level
  });

  scanHistory = scanHistory.slice(0,5);

  renderHistory();

}

function renderHistory(){

  const historyGrid =
    document.getElementById("historyGrid");

  historyGrid.innerHTML = "";

  scanHistory.forEach(item => {

    const card =
      document.createElement("div");

    card.className = "history-card";

    card.innerHTML = `
      <div class="collector-name">
        ${item.target}
      </div>

      <div style="margin-top:10px;">
        ${item.level}
      </div>

      <div style="
        margin-top:10px;
        font-family:'JetBrains Mono',monospace;
        font-size:.85rem;
      ">
        ${item.date}
      </div>
    `;

    card.onclick = () => {
      renderResults(item.response);
    };

    historyGrid.appendChild(card);

  });

}

document.getElementById(
  "downloadJsonBtn"
).onclick = () => {

  if(!currentResponse) return;

  const blob = new Blob(
    [
      JSON.stringify(
        currentResponse,
        null,
        2
      )
    ],
    {
      type:"application/json"
    }
  );

  const url =
    URL.createObjectURL(blob);

  const a =
    document.createElement("a");

  a.href = url;

  a.download =
    "reconmind-report.json";

  a.click();

};

document.getElementById(
  "downloadPdfBtn"
).onclick = async () => {

  const target =
    targetInput.value.trim();

  const response = await fetch(
    `${API_BASE}/scan/pdf`,
    {
      method:"POST",

      headers:{
        "Content-Type":"application/json"
      },

      body:JSON.stringify({
        target
      })
    }
  );

  const blob =
    await response.blob();

  const url =
    URL.createObjectURL(blob);

  const a =
    document.createElement("a");

  a.href = url;

  a.download =
    "reconmind-report.pdf";

  a.click();

};

document.getElementById(
  "shareBtn"
).onclick = () => {

  if(!currentResponse) return;

  const r =
    currentResponse.report;

  const shareText = `
RECONMIND REPORT

Risk Score:
${r.risk_score}

Risk Level:
${r.risk_level}

Summary:
${r.summary}
  `;

  navigator.clipboard.writeText(
    shareText
  );

  alert(
    "Share report copied to clipboard."
  );

};

document.getElementById(
  "newScanBtn"
).onclick = () => {

  results.classList.add("hidden");

  window.scrollTo({
    top:0,
    behavior:"smooth"
  });

};

const canvas =
  document.getElementById("particles");

const ctx =
  canvas.getContext("2d");

let particles = [];

function resizeCanvas(){

  canvas.width =
    window.innerWidth;

  canvas.height =
    window.innerHeight;

}

resizeCanvas();

window.addEventListener(
  "resize",
  resizeCanvas
);

for(let i = 0; i < 70; i++){

  particles.push({

    x:Math.random() * canvas.width,
    y:Math.random() * canvas.height,

    vx:(Math.random() - .5) * .3,
    vy:(Math.random() - .5) * .3

  });

}

function animateParticles(){

  ctx.clearRect(
    0,
    0,
    canvas.width,
    canvas.height
  );

  particles.forEach(p => {

    p.x += p.vx;
    p.y += p.vy;

    if(
      p.x < 0 ||
      p.x > canvas.width
    ) p.vx *= -1;

    if(
      p.y < 0 ||
      p.y > canvas.height
    ) p.vy *= -1;

    ctx.beginPath();

    ctx.arc(
      p.x,
      p.y,
      1.5,
      0,
      Math.PI * 2
    );

    ctx.fillStyle = "#00f5ff";

    ctx.fill();

    particles.forEach(p2 => {

      const dist = Math.hypot(
        p.x - p2.x,
        p.y - p2.y
      );

      if(dist < 120){

        ctx.beginPath();

        ctx.moveTo(p.x,p.y);

        ctx.lineTo(p2.x,p2.y);

        ctx.strokeStyle =
          `rgba(0,245,255,${
            0.08 - dist/1600
          })`;

        ctx.stroke();

      }

    });

  });

  requestAnimationFrame(
    animateParticles
  );

}

animateParticles();
