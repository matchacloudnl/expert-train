async function getIp(url) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return (await res.json()).ip;
}

async function loadIp() {
  const main = document.getElementById('ip-main');
  const v4Wrap = document.getElementById('ip4-wrap');
  main.textContent = 'Loading…';
  v4Wrap.hidden = true;

  document.getElementById('meta-ua').textContent = navigator.userAgent;
  document.getElementById('meta-lang').textContent = navigator.language;
  document.getElementById('meta-tz').textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;

  try {
    const ip = await getIp('https://api64.ipify.org?format=json');
    main.textContent = ip;
    // If the preferred address is IPv6, also show the IPv4 address when there is one
    if (ip.includes(':')) {
      try {
        document.getElementById('ip-v4').textContent = await getIp('https://api.ipify.org?format=json');
        v4Wrap.hidden = false;
      } catch (e) { /* no IPv4 available */ }
    }
  } catch (e) {
    main.textContent = 'Could not look up your IP';
  }
}

document.getElementById('ip-main').addEventListener('click', function (e) {
  if (navigator.clipboard && /^[0-9a-f.:]+$/i.test(e.target.textContent)) navigator.clipboard.writeText(e.target.textContent);
});
document.getElementById('ip-refresh').addEventListener('click', loadIp);
loadIp();
