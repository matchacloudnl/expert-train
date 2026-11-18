// --- Helpers: veilige random getallen ---
function randInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

function pickRandom(list) {
  return list[randInt(list.length)];
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function randDigitsString(n) {
  let s = "";
  for (let i = 0; i < n; i++) s += randInt(10);
  return s;
}

// --- Tabs ---
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
  });
});

// --- Toast ---
let toastEl;
function toast(msg) {
  if (!toastEl) {
    toastEl = document.createElement("div");
    toastEl.className = "toast";
    document.body.appendChild(toastEl);
  }
  toastEl.textContent = msg;
  toastEl.classList.add("show");
  clearTimeout(toastEl._t);
  toastEl._t = setTimeout(() => toastEl.classList.remove("show"), 1500);
}

async function copyText(tekst) {
  if (!tekst) return;
  try {
    await navigator.clipboard.writeText(tekst);
  } catch (e) {
    const tmp = document.createElement("textarea");
    tmp.value = tekst;
    tmp.style.position = "fixed";
    tmp.style.opacity = "0";
    document.body.appendChild(tmp);
    tmp.select();
    document.execCommand("copy");
    document.body.removeChild(tmp);
  }
  toast("Copied!");
}

// --- Kopiëren (statische velden) ---
document.querySelectorAll(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.copy);
    copyText(input.value);
  });
});

// --- Render helpers voor lijsten/chips ---
function renderLijst(containerId, waarden) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  waarden.forEach((waarde) => {
    const item = document.createElement("div");
    item.className = "lijst-item";
    const tekst = document.createElement("span");
    tekst.textContent = waarde;
    const icoon = document.createElement("span");
    icoon.className = "lijst-item-icoon";
    icoon.textContent = "📋";
    item.appendChild(tekst);
    item.appendChild(icoon);
    item.addEventListener("click", () => copyText(waarde));
    container.appendChild(item);
  });
}

function renderChips(containerId, waarden) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  waarden.forEach((waarde) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = waarde;
    chip.addEventListener("click", () => copyText(waarde));
    container.appendChild(chip);
  });
}

// --- Wachtwoord: kern-generator (herbruikbaar) ---
const LEESBAAR_UITSLUITEN = "0Ool1I";

const SETS = {
  hoofdletters: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  kleine: "abcdefghijklmnopqrstuvwxyz",
  cijfers: "0123456789",
  symbolen: "!@#$%^&*()-_=+[]{}?",
};

function genereerWachtwoordWaarde(lengte, opties) {
  const actieveSets = [];
  if (opties.hoofdletters) actieveSets.push(SETS.hoofdletters);
  if (opties.kleine) actieveSets.push(SETS.kleine);
  if (opties.cijfers) actieveSets.push(SETS.cijfers);
  if (opties.symbolen) actieveSets.push(SETS.symbolen);
  if (actieveSets.length === 0) return "";

  const filter = (set) =>
    opties.leesbaar ? set.split("").filter((c) => !LEESBAAR_UITSLUITEN.includes(c)).join("") : set;

  const gefilterdeSets = actieveSets.map(filter).filter((s) => s.length > 0);
  const allChars = gefilterdeSets.join("");

  const wachtwoord = [];
  gefilterdeSets.forEach((set) => {
    if (wachtwoord.length < lengte) wachtwoord.push(pickRandom(set.split("")));
  });
  while (wachtwoord.length < lengte) {
    wachtwoord.push(pickRandom(allChars.split("")));
  }
  return shuffle(wachtwoord).join("");
}

function berekenEntropieWachtwoord(lengte, aantalTekens) {
  if (aantalTekens <= 1) return 0;
  return lengte * Math.log2(aantalTekens);
}

// --- Onthoudbare wachtwoorden: uitspreekbare brabbeltaal (reset.nl-stijl) ---
const KLINKERS = ["a", "e", "i", "o", "u", "aa", "ee", "oo", "uu", "ie", "oe", "eu", "ui", "ei", "au", "ou"];
const MEDEKLINKERS = ["b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "z"];
const RESET_SYMBOLEN = ["?", "@", "+", "#", ";", "-", "*", "!", "%"];

function genereerLettergreep() {
  let s = "";
  if (randInt(4) !== 0) s += pickRandom(MEDEKLINKERS);
  s += pickRandom(KLINKERS);
  if (randInt(3) === 0) s += pickRandom(MEDEKLINKERS);
  return s;
}

function genereerOnthoudbaarResetWaarde(minLengte) {
  let gebrabbel = "";
  while (gebrabbel.length < minLengte) {
    gebrabbel += genereerLettergreep();
  }

  let woord = gebrabbel.charAt(0).toUpperCase() + gebrabbel.slice(1);
  const symboolPos = Math.max(1, Math.min(woord.length - 1, Math.floor(woord.length / 2) + randInt(3) - 1));
  woord = woord.slice(0, symboolPos) + pickRandom(RESET_SYMBOLEN) + woord.slice(symboolPos);

  const huidigJaar = new Date().getFullYear();
  const jaar = huidigJaar - 75 + randInt(101);
  return woord + jaar;
}

// --- Wachtwoordzin: kern-generator (herbruikbaar) ---
const SYMBOLEN_ZIN = ["!", "@", "#", "$", "%", "&", "*", "?"];

function genereerWachtwoordzinWaarde(aantal, metStreepjes) {
  const gekozenWoorden = [];
  const beschikbaar = [...WOORDEN];
  for (let i = 0; i < aantal; i++) {
    const idx = randInt(beschikbaar.length);
    gekozenWoorden.push(beschikbaar.splice(idx, 1)[0]);
  }

  const hoofdletterIdx = randInt(gekozenWoorden.length);
  gekozenWoorden[hoofdletterIdx] =
    gekozenWoorden[hoofdletterIdx].charAt(0).toUpperCase() + gekozenWoorden[hoofdletterIdx].slice(1);

  const cijferIdx = randInt(gekozenWoorden.length);
  const cijfer = randInt(90) + 10; // 10-99
  gekozenWoorden[cijferIdx] = gekozenWoorden[cijferIdx] + cijfer;

  const symboolIdx = randInt(gekozenWoorden.length);
  const symbool = pickRandom(SYMBOLEN_ZIN);
  gekozenWoorden[symboolIdx] = gekozenWoorden[symboolIdx] + symbool;

  return gekozenWoorden.join(metStreepjes ? "-" : "");
}

// --- Aangepast wachtwoord (UI) ---
function genereerWachtwoord() {
  const lengte = parseInt(document.getElementById("lengte").value, 10);
  const opties = {
    hoofdletters: document.getElementById("opt-hoofdletters").checked,
    kleine: document.getElementById("opt-kleine").checked,
    cijfers: document.getElementById("opt-cijfers").checked,
    symbolen: document.getElementById("opt-symbolen").checked,
    leesbaar: document.getElementById("opt-leesbaar").checked,
  };
  const output = document.getElementById("wachtwoord-output");
  const waarde = genereerWachtwoordWaarde(lengte, opties);

  if (!waarde) {
    output.value = "Select at least one character type";
    updateStrength("wachtwoord-strength", 0);
    return;
  }

  output.value = waarde;
  const aantalSets =
    (opties.hoofdletters ? 26 : 0) + (opties.kleine ? 26 : 0) + (opties.cijfers ? 10 : 0) + (opties.symbolen ? SETS.symbolen.length : 0);
  updateStrength("wachtwoord-strength", berekenEntropieWachtwoord(lengte, aantalSets));
}

document.getElementById("lengte").addEventListener("input", (e) => {
  document.getElementById("lengte-label").textContent = e.target.value;
  genereerWachtwoord();
});
["opt-hoofdletters", "opt-kleine", "opt-cijfers", "opt-symbolen", "opt-leesbaar"].forEach((id) => {
  document.getElementById(id).addEventListener("change", genereerWachtwoord);
});
document.getElementById("wachtwoord-refresh").addEventListener("click", genereerWachtwoord);

// --- Aangepaste wachtwoordzin (UI) ---
function genereerWachtwoordzin() {
  const aantal = parseInt(document.getElementById("aantal-woorden").value, 10);
  const metStreepjes = document.getElementById("zin-scheidingsteken").checked;
  const waarde = genereerWachtwoordzinWaarde(aantal, metStreepjes);
  document.getElementById("zin-output").value = waarde;

  const bits =
    aantal * Math.log2(WOORDEN.length) +
    Math.log2(aantal) +
    Math.log2(aantal * 90) +
    Math.log2(aantal * SYMBOLEN_ZIN.length);
  updateStrength("zin-strength", bits);
}

document.getElementById("aantal-woorden").addEventListener("input", (e) => {
  document.getElementById("aantal-woorden-label").textContent = e.target.value;
  genereerWachtwoordzin();
});
document.getElementById("zin-scheidingsteken").addEventListener("change", genereerWachtwoordzin);
document.getElementById("zin-refresh").addEventListener("click", genereerWachtwoordzin);

// --- Sterkte-indicator ---
function updateStrength(id, bits) {
  const bar = document.querySelector("#" + id + " .strength-bar");
  const pct = Math.min(100, (bits / 100) * 100);
  bar.style.width = pct + "%";
  let kleur = "var(--weak)";
  if (bits >= 70) kleur = "var(--strong)";
  else if (bits >= 40) kleur = "var(--medium)";
  bar.style.backgroundColor = kleur;
}

// --- Overzicht (Wachtwoorden-tab, reset.nl-stijl: altijd 10 stuks) ---
function genereerOverzicht() {
  renderChips("pin4-lijst", Array.from({ length: 10 }, () => randDigitsString(4)));
  renderChips("pin6-lijst", Array.from({ length: 10 }, () => randDigitsString(6)));

  renderLijst(
    "onthoudbaar-lijst",
    Array.from({ length: 10 }, (_, i) => genereerOnthoudbaarResetWaarde(8 + i))
  );

  renderLijst(
    "onthoudbaarzin-lijst",
    Array.from({ length: 10 }, () => genereerWachtwoordzinWaarde(randInt(2) + 3, true))
  );

  renderLijst(
    "moeilijk-lijst",
    Array.from({ length: 10 }, (_, i) =>
      genereerWachtwoordWaarde(12 + i, { hoofdletters: true, kleine: true, cijfers: true, symbolen: false })
    )
  );

  renderLijst(
    "zwaar-lijst",
    Array.from({ length: 10 }, (_, i) =>
      genereerWachtwoordWaarde(14 + i * 2, { hoofdletters: true, kleine: true, cijfers: true, symbolen: true })
    )
  );
}

document.getElementById("overzicht-refresh").addEventListener("click", genereerOverzicht);

// --- IPSec PSK ---
function genereerPsk() {
  const lengte = parseInt(document.getElementById("psk-lengte").value, 10);
  const metSymbolen = document.getElementById("psk-symbolen").checked;
  const opties = { hoofdletters: true, kleine: true, cijfers: true, symbolen: metSymbolen };
  renderLijst("psk-lijst", Array.from({ length: 5 }, () => genereerWachtwoordWaarde(lengte, opties)));
}

document.getElementById("psk-lengte").addEventListener("input", (e) => {
  document.getElementById("psk-lengte-label").textContent = e.target.value;
  genereerPsk();
});
document.getElementById("psk-symbolen").addEventListener("change", genereerPsk);
document.getElementById("psk-refresh").addEventListener("click", genereerPsk);

// --- WiFi & SSID ---
// SSID's en wachtwoorden kunnen tekens buiten ASCII bevatten
qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];

function wifiEscape(str) {
  return str.replace(/([\\;,:"])/g, "\\$1");
}

function bijwerkenWifiQr() {
  const ssid = document.getElementById("wifi-ssid").value;
  const wachtwoord = document.getElementById("wifi-wachtwoord").value;

  const qrContainer = document.getElementById("wifi-qr");
  qrContainer.innerHTML = "";
  if (!ssid) return;

  const wifiUri = `WIFI:T:WPA;S:${wifiEscape(ssid)};P:${wifiEscape(wachtwoord)};H:false;;`;
  const qr = qrcode(0, "H");
  qr.addData(wifiUri);
  qr.make();

  // Hele pixels per module houden de QR-code scherp
  const cellSize = Math.max(1, Math.floor(200 / qr.getModuleCount()));
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = qr.getModuleCount() * cellSize;
  qr.renderTo2dContext(canvas.getContext("2d"), cellSize);
  qrContainer.appendChild(canvas);
}

function genereerWifi() {
  const ssid = `${pickRandom(ADJECTIEVEN)} ${pickRandom(WOORDEN).replace(/^./, (c) => c.toUpperCase())} ${randInt(90) + 10}`;
  const wachtwoord = genereerWachtwoordWaarde(20, {
    hoofdletters: true,
    kleine: true,
    cijfers: true,
    symbolen: false,
    leesbaar: true,
  });

  document.getElementById("wifi-ssid").value = ssid;
  document.getElementById("wifi-wachtwoord").value = wachtwoord;
  bijwerkenWifiQr();
}

// --- Username + memorable password ---
function genereerUsername() {
  const woord = pickRandom(WOORDEN).replace(/^./, (c) => c.toUpperCase());
  return `${pickRandom(ADJECTIEVEN)}${woord}${randInt(90) + 10}`.replace(/\s+/g, "");
}

function genereerUsernames() {
  const container = document.getElementById("username-lijst");
  container.innerHTML = "";
  for (let i = 0; i < 10; i++) {
    const rij = document.createElement("div");
    rij.className = "lijst-item username-rij";
    [genereerUsername(), genereerOnthoudbaarResetWaarde(8 + i)].forEach((waarde) => {
      const cel = document.createElement("span");
      cel.className = "username-cel";
      cel.textContent = waarde;
      cel.addEventListener("click", () => copyText(waarde));
      rij.appendChild(cel);
    });
    container.appendChild(rij);
  }
}

document.getElementById("username-refresh").addEventListener("click", genereerUsernames);
genereerUsernames();

document.getElementById("wifi-refresh").addEventListener("click", genereerWifi);
document.getElementById("wifi-ssid").addEventListener("input", bijwerkenWifiQr);
document.getElementById("wifi-wachtwoord").addEventListener("input", bijwerkenWifiQr);

document.getElementById("wifi-print").addEventListener("click", () => {
  window.print();
});

document.getElementById("wifi-download-png").addEventListener("click", () => {
  const qrCanvas = document.querySelector("#wifi-qr canvas");
  const ssid = document.getElementById("wifi-ssid").value;
  const wachtwoord = document.getElementById("wifi-wachtwoord").value;

  const canvas = document.createElement("canvas");
  const width = 480;
  const qrSize = qrCanvas ? qrCanvas.width : 200;
  const height = 220 + qrSize;
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");

  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width, height);

  ctx.fillStyle = "#0f172a";
  ctx.font = "bold 22px sans-serif";
  ctx.fillText("WiFi details", 24, 44);

  ctx.font = "13px sans-serif";
  ctx.fillStyle = "#64748b";
  ctx.fillText("NETWORK NAME (SSID)", 24, 80);
  ctx.font = "bold 18px monospace";
  ctx.fillStyle = "#0f172a";
  ctx.fillText(ssid, 24, 104);

  ctx.font = "13px sans-serif";
  ctx.fillStyle = "#64748b";
  ctx.fillText("PASSWORD", 24, 138);
  ctx.font = "bold 18px monospace";
  ctx.fillStyle = "#0f172a";
  ctx.fillText(wachtwoord, 24, 162);

  if (qrCanvas) {
    const qrX = (width - qrSize) / 2;
    ctx.drawImage(qrCanvas, qrX, 190);
  }

  canvas.toBlob((blob) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `wifi-${ssid.replace(/\s+/g, "-").toLowerCase()}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
});

// --- Init ---
genereerWachtwoord();
genereerWachtwoordzin();
genereerOverzicht();
genereerPsk();
genereerWifi();
