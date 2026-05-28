# script.js

```javascript
// TYPING EFFECT

const typedText = document.getElementById("typed-text");

const texts = [
  "Scanning threat intelligence vectors...",
  "Correlating digital attack surfaces...",
  "Initializing AI threat analysis...",
  "Enumerating exposed infrastructure...",
];

let textIndex = 0;
let charIndex = 0;

function typeEffect() {

  if (charIndex < texts[textIndex].length) {

    typedText.innerHTML += texts[textIndex].charAt(charIndex);

    charIndex++;

    setTimeout(typeEffect, 50);

  } else {

    setTimeout(eraseEffect, 2000);

  }

}

function eraseEffect() {

  if (charIndex > 0) {

    typedText.innerHTML = texts[textIndex].substring(0, charIndex - 1);

    charIndex--;

    setTimeout(eraseEffect, 30);

  } else {

    textIndex++;

    if (textIndex >= texts.length) {
      textIndex = 0;
    }

    setTimeout(typeEffect, 500);

  }

}

typeEffect();

// TERMINAL LOGS

const terminal = document.getElementById("terminal");

const logs = [
  "[INFO] Connecting to Shodan collectors...",
  "[INFO] Running WHOIS intelligence...",
  "[INFO] Enumerating usernames...",
  "[INFO] AI threat correlation active...",
  "[SUCCESS] Threat intelligence generated.",
];

let logIndex = 0;

function addLog() {

  if (logIndex < logs.length) {

    const p = document.createElement("p");

    p.textContent = logs[logIndex];

    terminal.appendChild(p);

    terminal.scrollTop = terminal.scrollHeight;

    logIndex++;

  }

}

setInterval(addLog, 2500);

// SEARCH BUTTON

const scanBtn = document.getElementById("scanBtn");

scanBtn.addEventListener("click", () => {

  scanBtn.innerHTML = "SCANNING...";

  scanBtn.style.background = "#FF3B3B";

  setTimeout(() => {

    scanBtn.innerHTML = "SCAN COMPLETE";

    scanBtn.style.background = "#00FF9D";

  }, 3000);

});

// THREAT CHART

const ctx = document.getElementById('riskChart');

new Chart(ctx, {

  type: 'doughnut',

  data: {

    labels: [
      'Critical',
      'High',
      'Medium',
      'Low'
    ],

    datasets: [{

      data: [12, 19, 8, 4],

      backgroundColor: [
        '#FF3B3B',
        '#8B5CF6',
        '#00F5FF',
        '#00FF9D'
      ],

      borderWidth: 0

    }]

  },

  options: {

    plugins: {

      legend: {
        labels: {
          color: '#E2E8F0'
        }
      }

    }

  }

});

// MOUSE GLOW EFFECT

document.addEventListener("mousemove", (e) => {

  const glow = document.querySelector(".grid-bg");

  glow.style.backgroundPosition =
    `${e.clientX / 20}px ${e.clientY / 20}px`;

});
```

