(function () {
  var year = document.getElementById('year');
  if (year) year.textContent = new Date().getFullYear();

  // Build the mailto link in JS so the address is not in the HTML (spam protection)
  var addr = ['info', 'matchacloud.nl'].join('@');
  document.querySelectorAll('[data-mail]').forEach(function (a) {
    a.href = 'mailto:' + addr;
  });
})();
