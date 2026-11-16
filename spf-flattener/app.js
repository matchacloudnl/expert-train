const DOH = 'https://cloudflare-dns.com/dns-query';
const TYPES = { A: 1, MX: 15, TXT: 16, AAAA: 28 };
const MAX_DEPTH = 10;
const cache = new Map();

async function query(name, type) {
  const key = type + ' ' + name;
  if (cache.has(key)) return cache.get(key);
  const res = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: 'application/dns-json' },
  });
  if (!res.ok) throw new Error(`DNS query for ${name} failed (HTTP ${res.status})`);
  const json = await res.json();
  let answers = [];
  if (json.Status === 0) {
    answers = (json.Answer || []).filter((a) => a.type === TYPES[type]).map((a) => a.data);
  } else if (json.Status !== 3) {
    throw new Error(`DNS query for ${name} failed (status ${json.Status})`);
  }
  cache.set(key, answers);
  return answers;
}

function txtValue(data) {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  return parts.length ? parts.join('') : data;
}

async function getSpf(domain) {
  const txts = (await query(domain, 'TXT')).map(txtValue);
  const spf = txts.filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (spf.length === 0) throw new Error(`No SPF record found for ${domain}`);
  if (spf.length > 1) throw new Error(`${domain} has multiple SPF records, which is invalid`);
  return spf[0];
}

function cleanHost(h) {
  return h.replace(/\.$/, '').toLowerCase();
}

async function flatten(domain, ctx, depth, allowAll) {
  if (depth > MAX_DEPTH) {
    ctx.warnings.push(`Stopped at ${domain}: nesting is too deep.`);
    return;
  }
  if (ctx.visited.has(domain)) {
    ctx.warnings.push(`Loop detected at ${domain}; skipped.`);
    return;
  }
  ctx.visited.add(domain);

  const record = await getSpf(domain);
  const terms = record.trim().split(/\s+/).slice(1);
  const found = (ctx.sources[domain] = ctx.sources[domain] || []);

  const add = (entry) => {
    if (!ctx.seen.has(entry)) {
      ctx.seen.add(entry);
      ctx.entries.push(entry);
    }
    found.push(entry);
  };

  for (const term of terms) {
    const m = term.match(/^([+\-~?])?(.*)$/);
    const q = m[1] || '+';
    const body = m[2];
    const lower = body.toLowerCase();

    if (lower.startsWith('redirect=')) {
      ctx.lookups++;
      await flatten(cleanHost(body.slice(9)), ctx, depth + 1, allowAll);
      continue;
    }
    if (lower.startsWith('exp=')) continue;

    if (lower === 'all') {
      if (allowAll && !ctx.all) ctx.all = q === '+' ? 'all' : q + 'all';
      continue;
    }

    if (q !== '+' && !lower.startsWith('ip')) {
      ctx.warnings.push(`Skipped "${term}" in ${domain}: only "pass" mechanisms can be flattened.`);
      if (/^(include|a|mx|exists|ptr)\b/.test(lower)) ctx.lookups++;
      continue;
    }
    if (q !== '+') {
      ctx.warnings.push(`Skipped "${term}" in ${domain}: only "pass" mechanisms can be flattened.`);
      continue;
    }

    if (lower.startsWith('ip4:') || lower.startsWith('ip6:')) {
      add(lower);
    } else if (lower.startsWith('include:')) {
      ctx.lookups++;
      await flatten(cleanHost(body.slice(8)), ctx, depth + 1, false);
    } else if (/^a(:|\/|$)/.test(lower)) {
      ctx.lookups++;
      const mm = lower.match(/^a(?::([^/]+))?(?:\/(\d+))?(?:\/\/(\d+))?$/);
      if (!mm) { ctx.warnings.push(`Could not read "${term}" in ${domain}.`); continue; }
      await addHost(cleanHost(mm[1] || domain), mm[2], mm[3], add);
    } else if (/^mx(:|\/|$)/.test(lower)) {
      ctx.lookups++;
      const mm = lower.match(/^mx(?::([^/]+))?(?:\/(\d+))?(?:\/\/(\d+))?$/);
      if (!mm) { ctx.warnings.push(`Could not read "${term}" in ${domain}.`); continue; }
      const mxs = await query(cleanHost(mm[1] || domain), 'MX');
      for (const mx of mxs.slice(0, 10)) {
        const host = cleanHost(mx.split(/\s+/)[1] || '');
        if (host) await addHost(host, mm[2], mm[3], add);
      }
    } else if (lower.startsWith('exists:') || lower.startsWith('ptr')) {
      ctx.lookups++;
      ctx.kept.push(term);
      ctx.warnings.push(`"${term}" in ${domain} cannot be flattened and was kept as is (it still counts as a DNS lookup).`);
    } else {
      ctx.warnings.push(`Unknown term "${term}" in ${domain} was ignored.`);
    }
  }
}

async function addHost(host, cidr4, cidr6, add) {
  const [v4, v6] = await Promise.all([query(host, 'A'), query(host, 'AAAA')]);
  v4.forEach((ip) => add('ip4:' + ip + (cidr4 && cidr4 !== '32' ? '/' + cidr4 : '')));
  v6.forEach((ip) => add('ip6:' + ip + (cidr6 && cidr6 !== '128' ? '/' + cidr6 : '')));
}

function normalizeDomain(input) {
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').split(/[/?#]/)[0].replace(/\.$/, '');
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d) ? d : null;
}

const $ = (id) => document.getElementById(id);

$('spf-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = normalizeDomain($('domain').value);
  const status = $('status');
  status.classList.remove('error');
  $('result').hidden = true;
  if (!domain) {
    status.textContent = 'Enter a valid domain, for example example.com';
    status.classList.add('error');
    return;
  }

  $('go').disabled = true;
  status.textContent = `Looking up SPF for ${domain}…`;
  const ctx = { entries: [], seen: new Set(), kept: [], warnings: [], visited: new Set(), sources: {}, lookups: 0, all: '' };
  try {
    await flatten(domain, ctx, 0, true);
  } catch (err) {
    status.textContent = err.message;
    status.classList.add('error');
    $('go').disabled = false;
    return;
  }

  if (!ctx.all) ctx.warnings.push('The record has no "all" mechanism; none was added. Add ~all or -all yourself.');
  const record = ['v=spf1', ...ctx.entries, ...ctx.kept, ctx.all].filter(Boolean).join(' ');

  $('out').value = record;
  $('st-before').textContent = ctx.lookups;
  $('st-after').textContent = ctx.kept.length;
  $('st-len').textContent = record.length;
  if (record.length > 255) {
    ctx.warnings.push('The record is longer than 255 characters. It must be stored as multiple quoted strings in one TXT record (most DNS providers split it automatically).');
  }
  if (record.length > 450) {
    ctx.warnings.push('The record is longer than about 450 characters, which can exceed the size of a UDP DNS response. Consider moving some senders to a subdomain.');
  }
  if (ctx.lookups <= 10) {
    ctx.warnings.unshift(`The original record used ${ctx.lookups} lookups, which is already within the limit of 10.`);
  }

  const w = $('warnings');
  w.innerHTML = '';
  ctx.warnings.forEach((t) => { const li = document.createElement('li'); li.textContent = t; w.appendChild(li); });
  w.hidden = ctx.warnings.length === 0;

  const src = $('sources');
  src.innerHTML = '<h3>Where the addresses came from</h3>';
  Object.entries(ctx.sources).forEach(([d, list]) => {
    if (!list.length) return;
    const det = document.createElement('details');
    const sum = document.createElement('summary');
    sum.textContent = `${d} (${list.length})`;
    const code = document.createElement('code');
    code.textContent = list.join(' ');
    det.append(sum, code);
    src.appendChild(det);
  });

  status.textContent = `Done: ${ctx.entries.length} addresses collected from ${ctx.visited.size} record(s).`;
  $('result').hidden = false;
  $('go').disabled = false;
});

$('copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('out').value);
    $('copy').textContent = '✅ Copied';
  } catch (e) {
    $('out').select();
    document.execCommand('copy');
    $('copy').textContent = '✅ Copied';
  }
  setTimeout(() => { $('copy').textContent = '📋 Copy'; }, 1500);
});
