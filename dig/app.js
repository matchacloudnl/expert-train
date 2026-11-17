const DOH = 'https://cloudflare-dns.com/dns-query';
const TYPE_NUM = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k]));
const CONCURRENCY = 8;
const MAX_NAMES = 1000;

const WORDS = ('www mail webmail smtp imap pop pop3 mx mx1 mx2 ns ns1 ns2 ns3 ftp sftp vpn remote rdp portal login sso auth ' +
  'autodiscover autoconfig owa exchange api app apps dev test staging stage uat qa demo beta admin cpanel panel dashboard ' +
  'blog shop store cdn static assets media img images files download support help docs wiki status monitor grafana git gitlab ' +
  'github jenkins ci intranet extranet crm erp db sql mysql backup cloud office lyncdiscover sip meet teams mobile m web ' +
  'secure proxy gateway gw fw firewall relay mailer newsletter lists dns time ntp radius ldap ad dc citrix rds terminal').split(' ');

const $ = (id) => document.getElementById(id);
let results = []; // { name, type, value, source }
let lastDomain = '';

function setStatus(msg, isError) {
  const el = $('status');
  el.textContent = msg;
  el.classList.toggle('error', !!isError);
}

function cleanName(n) {
  return n.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
}

function validDomain(d) {
  return /^(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/.test(d);
}

async function dohQuery(name, type, retries = 2) {
  for (let i = 0; ; i++) {
    try {
      const res = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { accept: 'application/dns-json' },
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const json = await res.json();
      if (json.Status !== 0) return [];
      return (json.Answer || []).filter((a) => TYPE_NAME[a.type]);
    } catch (e) {
      if (i >= retries) return [];
      await new Promise((r) => setTimeout(r, 300 * (i + 1)));
    }
  }
}

function fetchTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { signal: ctrl.signal }).finally(() => clearTimeout(t));
}

async function fromCrtSh(domain) {
  const res = await fetchTimeout(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, 20000);
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const rows = await res.json();
  return rows.flatMap((r) => String(r.name_value).split('\n'));
}

async function fromCertSpotter(domain) {
  const res = await fetchTimeout(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`, 20000);
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const rows = await res.json();
  return rows.flatMap((r) => r.dns_names || []);
}

async function ctNames(domain) {
  for (const [label, fn] of [['crt.sh', fromCrtSh], ['Cert Spotter', fromCertSpotter]]) {
    try {
      return { label, names: await fn(domain) };
    } catch (e) { /* try the next source */ }
  }
  return { label: null, names: [] };
}

async function pool(items, worker) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
    while (i < items.length) await worker(items[i++]);
  }));
}

function render() {
  const rows = $('rows');
  rows.textContent = '';
  const frag = document.createDocumentFragment();
  for (const r of results) {
    const tr = document.createElement('tr');
    for (const v of [r.name, r.type, r.value, r.source]) {
      const td = document.createElement('td');
      td.textContent = v;
      tr.appendChild(td);
    }
    frag.appendChild(tr);
  }
  rows.appendChild(frag);
  $('n-names').textContent = new Set(results.filter((r) => r.type !== '-').map((r) => r.name)).size;
  $('n-records').textContent = results.filter((r) => r.type !== '-').length;
  $('table-wrap').hidden = $('csv').hidden = results.length === 0;
}

function csvCell(v) {
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // avoid spreadsheet formula injection
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function downloadCsv() {
  const lines = [['subdomain', 'type', 'value', 'source'].join(',')];
  for (const r of results) lines.push([r.name, r.type, r.value, r.source].map(csvCell).join(','));
  const blob = new Blob(['﻿' + lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `subdomains-${lastDomain}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function run(e) {
  e.preventDefault();
  const domain = cleanName($('domain').value.replace(/^https?:\/\//i, '').split('/')[0]);
  const types = [...document.querySelectorAll('#types input:checked')].map((c) => c.value);
  const useCt = $('use-ct').checked;
  const useWords = $('use-words').checked;

  if (!validDomain(domain)) return setStatus('Enter a valid domain name, e.g. example.com', true);
  if (!types.length) return setStatus('Select at least one record type.', true);
  if (!useCt && !useWords) return setStatus('Select at least one search method.', true);

  const btn = $('go');
  btn.disabled = true;
  results = [];
  lastDomain = domain;
  $('stats').hidden = false;
  $('n-checked').textContent = 0;
  render();

  try {
    const sources = new Map(); // name -> set of sources
    const addName = (n, src) => {
      n = cleanName(n);
      if (n !== domain && !n.endsWith('.' + domain)) return;
      if (!/^[a-z0-9._-]+$/.test(n)) return;
      if (!sources.has(n)) sources.set(n, new Set());
      sources.get(n).add(src);
    };
    addName(domain, 'apex');

    if (useCt) {
      setStatus('Searching certificate transparency logs…');
      const ct = await ctNames(domain);
      ct.names.forEach((n) => addName(n, 'ct-logs'));
      if (!ct.label) setStatus('Certificate logs could not be reached; continuing without them.');
    }

    // Wildcard detection: if random names resolve, wordlist guesses are meaningless
    let wildcard = false;
    if (useWords) {
      const probe = `zz-${Math.random().toString(36).slice(2, 10)}.${domain}`;
      wildcard = (await dohQuery(probe, 'A')).length > 0;
      if (!wildcard) WORDS.forEach((w) => addName(`${w}.${domain}`, 'wordlist'));
    }

    let names = [...sources.keys()];
    if (names.length > MAX_NAMES) names = names.slice(0, MAX_NAMES);
    let checked = 0;
    setStatus(`Resolving ${names.length} names…`);

    await pool(names, async (name) => {
      const seen = new Set();
      const found = [];
      for (const t of types) {
        for (const a of await dohQuery(name, TYPE_NUM[t])) {
          const type = TYPE_NAME[a.type];
          const value = type === 'TXT'
            ? [...a.data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]).join('') || a.data
            : a.data.replace(/\.$/, '');
          const key = type + '|' + value;
          if (seen.has(key)) continue;
          seen.add(key);
          found.push({ name, type, value, source: [...sources.get(name)].join('+') });
        }
      }
      // keep only records for names that exist; names without a record are dropped unless they came from CT logs
      if (found.length) results.push(...found);
      else if (sources.get(name).has('ct-logs')) results.push({ name, type: '-', value: '(no record found)', source: [...sources.get(name)].join('+') });
      $('n-checked').textContent = ++checked;
      if (checked % 10 === 0 || checked === names.length) {
        results.sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type));
        render();
      }
    });

    results.sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type));
    render();
    const count = new Set(results.filter((r) => r.type !== '-').map((r) => r.name)).size;
    setStatus(
      `Done: ${count} subdomain${count === 1 ? '' : 's'} with records found.` +
      (wildcard ? ' This domain uses a wildcard DNS record, so the wordlist was skipped.' : '') +
      (sources.size > MAX_NAMES ? ` Only the first ${MAX_NAMES} names were checked.` : ''));
  } catch (err) {
    setStatus('Something went wrong: ' + err.message, true);
  } finally {
    btn.disabled = false;
  }
}

$('dig-form').addEventListener('submit', run);
$('csv').addEventListener('click', downloadCsv);
