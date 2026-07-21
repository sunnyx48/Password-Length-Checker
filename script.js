const MIN_LENGTH = 12;
const HISTORY_KEY = "vaultcheck_password_hashes";
const MAX_HISTORY = 50;

const COMMON_PASSWORDS = new Set(
  [
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "admin123",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "login",
    "princess",
    "football",
    "baseball",
    "sunshine",
    "trustno1",
    "passw0rd",
    "shadow",
    "superman",
    "michael",
    "jennifer",
    "hunter2",
    "changeme",
    "secret",
    "default",
  ].map((p) => p.toLowerCase())
);

const WORDS = [
  "amber", "basin", "cedar", "delta", "ember", "fjord", "grove", "haven",
  "ivory", "jade", "kite", "lunar", "maple", "north", "olive", "pine",
  "quartz", "river", "sage", "tide", "umbra", "vale", "willow", "xenon",
  "bloom", "coral", "drift", "echo", "flint", "glade", "harbor", "orbit",
];

const passwordInput = document.getElementById("password");
const togglePasswordBtn = document.getElementById("togglePassword");
const analyzerForm = document.getElementById("analyzerForm");
const saveBtn = document.getElementById("saveBtn");
const regenBtn = document.getElementById("regenBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

const meterFill = document.getElementById("meterFill");
const strengthLabel = document.getElementById("strengthLabel");
const scoreLabel = document.getElementById("scoreLabel");
const checklist = document.getElementById("checklist");
const feedback = document.getElementById("feedback");
const summary = document.getElementById("summary");
const tips = document.getElementById("tips");
const suggestions = document.getElementById("suggestions");
const altList = document.getElementById("altList");
const historyCount = document.getElementById("historyCount");

let lastAnalyzed = "";
let lastAlternatives = [];

function getHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function setHistory(hashes) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(hashes.slice(0, MAX_HISTORY)));
  updateHistoryCount();
}

function updateHistoryCount() {
  const n = getHistory().length;
  historyCount.textContent = `${n} saved hash${n === 1 ? "" : "es"}`;
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hasSequentialChars(password) {
  const lower = password.toLowerCase();
  const sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - 3; i++) {
      const chunk = seq.slice(i, i + 3);
      const reverse = chunk.split("").reverse().join("");
      if (lower.includes(chunk) || lower.includes(reverse)) return true;
    }
  }
  return false;
}

function hasRepeatedChars(password) {
  return /(.)\1{2,}/.test(password);
}

function analyzePassword(password, historyHashes, currentHash) {
  const length = password.length;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const lengthOk = length >= MIN_LENGTH;

  const isCommon =
    password.length > 0 && COMMON_PASSWORDS.has(password.toLowerCase());
  const isReused =
    Boolean(currentHash) && historyHashes.includes(currentHash);
  const uniqueOk = password.length > 0 && !isCommon && !isReused;

  const rules = {
    length: lengthOk,
    upper: hasUpper,
    lower: hasLower,
    number: hasNumber,
    special: hasSpecial,
    unique: uniqueOk,
  };

  let score = 0;
  if (length >= 8) score += 10;
  if (length >= 12) score += 15;
  if (length >= 16) score += 10;
  if (length >= 20) score += 5;
  if (hasUpper) score += 12;
  if (hasLower) score += 12;
  if (hasNumber) score += 12;
  if (hasSpecial) score += 14;
  if (uniqueOk) score += 10;

  const tipList = [];
  if (!lengthOk) tipList.push(`Use at least ${MIN_LENGTH} characters.`);
  if (!hasUpper) tipList.push("Add an uppercase letter.");
  if (!hasLower) tipList.push("Add a lowercase letter.");
  if (!hasNumber) tipList.push("Include at least one number.");
  if (!hasSpecial) tipList.push("Include a special character (!@#$…).");
  if (isCommon) tipList.push("Avoid common passwords found in breach lists.");
  if (isReused) tipList.push("This password matches one in your local history.");
  if (hasSequentialChars(password)) {
    tipList.push("Avoid sequential patterns like abc or 123.");
    score = Math.max(0, score - 8);
  }
  if (hasRepeatedChars(password)) {
    tipList.push("Avoid repeating the same character three or more times.");
    score = Math.max(0, score - 6);
  }

  score = Math.min(100, Math.max(0, score));

  let level = "weak";
  if (score >= 90) level = "excellent";
  else if (score >= 75) level = "strong";
  else if (score >= 55) level = "good";
  else if (score >= 35) level = "fair";

  const allPassed = Object.values(rules).every(Boolean);
  let summaryText = "Enter a password to begin analysis.";
  if (password.length === 0) {
    summaryText = "Enter a password to begin analysis.";
  } else if (allPassed && score >= 75) {
    summaryText = "Solid password. Complexity and uniqueness look good.";
  } else if (allPassed) {
    summaryText = "Requirements met, but a longer or less patterned password would score higher.";
  } else {
    summaryText = "Needs work — fix the items below to raise strength.";
  }

  return { length, rules, score, level, tipList, summaryText, isReused, isCommon };
}

function randomInt(max) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % max;
}

function pick(arr) {
  return arr[randomInt(arr.length)];
}

function generateAlternatives(count = 3) {
  const specials = "!@#$%&*?+-=";
  const alts = [];

  for (let i = 0; i < count; i++) {
    const w1 = pick(WORDS);
    const w2 = pick(WORDS.filter((w) => w !== w1));
    const num = 10 + randomInt(90);
    const special = specials[randomInt(specials.length)];
    const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
    const styles = [
      `${cap(w1)}${special}${w2}${num}`,
      `${w1}${num}${cap(w2)}${special}`,
      `${cap(w1)}${cap(w2)}${special}${num}${pick(WORDS).slice(0, 2)}`,
    ];
    alts.push(styles[i % styles.length]);
  }
  return alts;
}

function setRuleState(key, ok, empty) {
  const li = checklist.querySelector(`[data-rule="${key}"]`);
  if (!li) return;
  li.classList.remove("ok", "bad");
  if (empty) return;
  li.classList.add(ok ? "ok" : "bad");
}

function renderMeter(score, level, empty) {
  meterFill.style.width = empty ? "0%" : `${score}%`;
  meterFill.className = `meter-fill${empty ? "" : ` ${level}`}`;
  strengthLabel.textContent = empty ? "Waiting" : level;
  strengthLabel.className = `strength-label${empty ? "" : ` ${level}`}`;
  scoreLabel.textContent = `${empty ? 0 : score} / 100`;
}

function renderAlternatives(list) {
  lastAlternatives = list;
  altList.innerHTML = "";
  list.forEach((pwd) => {
    const li = document.createElement("li");
    const text = document.createElement("span");
    text.textContent = pwd;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pwd);
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = "Copy";
        }, 1200);
      } catch {
        btn.textContent = "Failed";
        setTimeout(() => {
          btn.textContent = "Copy";
        }, 1200);
      }
    });
    li.append(text, btn);
    altList.appendChild(li);
  });
  suggestions.classList.remove("hidden");
}

async function runAnalysis() {
  const password = passwordInput.value;
  lastAnalyzed = password;

  const history = getHistory();
  const hash = password ? await sha256(password) : "";
  const result = analyzePassword(password, history, hash);

  const empty = password.length === 0;
  Object.entries(result.rules).forEach(([key, ok]) => {
    setRuleState(key, ok, empty);
  });

  renderMeter(result.score, result.level, empty);

  if (empty) {
    feedback.classList.add("hidden");
    suggestions.classList.add("hidden");
    saveBtn.disabled = true;
    return result;
  }

  summary.textContent = result.summaryText;
  tips.innerHTML = "";
  result.tipList.forEach((tip) => {
    const li = document.createElement("li");
    li.textContent = tip;
    tips.appendChild(li);
  });
  feedback.classList.remove("hidden");

  saveBtn.disabled = result.isReused || result.isCommon || password.length < MIN_LENGTH;

  if (result.score < 75 || result.tipList.length > 0) {
    renderAlternatives(generateAlternatives(3));
  } else {
    suggestions.classList.add("hidden");
  }

  return result;
}

const eyeOpen = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const eyeClosed = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

togglePasswordBtn.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  togglePasswordBtn.innerHTML = showing ? eyeOpen : eyeClosed;
  togglePasswordBtn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  togglePasswordBtn.setAttribute("title", showing ? "Show password" : "Hide password");
});

let debounceTimer;
passwordInput.addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runAnalysis, 120);
});

analyzerForm.addEventListener("submit", (e) => {
  e.preventDefault();
  runAnalysis();
});

saveBtn.addEventListener("click", async () => {
  const password = passwordInput.value;
  if (!password) return;

  const hash = await sha256(password);
  const history = getHistory();
  if (history.includes(hash)) {
    summary.textContent = "Already in history — reuse blocked.";
    feedback.classList.remove("hidden");
    await runAnalysis();
    return;
  }

  history.unshift(hash);
  setHistory(history);
  saveBtn.disabled = true;
  summary.textContent = "Hash saved. This password cannot be reused here.";
  feedback.classList.remove("hidden");
  await runAnalysis();
});

regenBtn.addEventListener("click", () => {
  renderAlternatives(generateAlternatives(3));
});

clearHistoryBtn.addEventListener("click", () => {
  localStorage.removeItem(HISTORY_KEY);
  updateHistoryCount();
  runAnalysis();
});

updateHistoryCount();
runAnalysis();
