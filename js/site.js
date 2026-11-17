(function () {
  var year = document.getElementById('year');
  if (year) year.textContent = new Date().getFullYear();

  // Build the mailto link in JS so the address is not in the HTML (spam protection)
  var addr = ['info', 'matchacloud.nl'].join('@');
  document.querySelectorAll('[data-mail]').forEach(function (a) {
    a.href = 'mailto:' + addr;
  });

  // Recipe window
  var recipe = document.getElementById('recipe');
  if (recipe && recipe.showModal) {
    document.querySelectorAll('[data-open-recipe]').forEach(function (b) {
      b.addEventListener('click', function () { recipe.showModal(); });
    });
    recipe.querySelectorAll('[data-close-recipe]').forEach(function (b) {
      b.addEventListener('click', function () { recipe.close(); });
    });
    // click on the backdrop closes it
    recipe.addEventListener('click', function (e) { if (e.target === recipe) recipe.close(); });
  }

  // Hero image: tilts, drifts and shrinks slightly while scrolling
  var img = document.querySelector('.hero-img');
  if (img && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    var ticking = false;
    var update = function () {
      var p = Math.min(Math.max(window.scrollY / 650, 0), 1);
      img.style.setProperty('--ty', (p * 90).toFixed(1) + 'px');
      img.style.setProperty('--rot', (p * 14).toFixed(1) + 'deg');
      img.style.setProperty('--ds', (p * 0.2).toFixed(3));
      ticking = false;
    };
    window.addEventListener('scroll', function () {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    update();
  }
})();
