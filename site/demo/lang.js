// Test page language: same as chosen in the Routelark tab (its settings live at this same origin)
(function () {
  var key = 'rl:settings', saved = {};
  try { saved = JSON.parse(localStorage.getItem(key)) || {}; } catch (e) { /* storage unavailable */ }
  var texts = document.querySelectorAll('[data-ru]');
  for (var i = 0; i < texts.length; i++) texts[i].setAttribute('data-en', texts[i].textContent);
  function apply(lang) {
    document.documentElement.lang = lang;
    for (var i = 0; i < texts.length; i++) texts[i].textContent = texts[i].getAttribute('data-' + lang);
    // Both language versions of a block share one grid cell: height follows the larger, the inactive one is just invisible
    var blocks = document.querySelectorAll('section[lang]');
    for (var j = 0; j < blocks.length; j++) { blocks[j].hidden = false; blocks[j].style.visibility = blocks[j].getAttribute('lang') === lang ? '' : 'hidden'; blocks[j].setAttribute('aria-hidden', blocks[j].getAttribute('lang') === lang ? 'false' : 'true'); }
    document.getElementById('lang').textContent = lang === 'ru' ? 'EN' : 'RU';
    document.title = lang === 'ru' ? 'Routelark: тестовая страница' : 'Routelark: test page';
  }
  // Each translatable text reserves room for the longer version so blocks do not shift on language change
  function lock() {
    var lang = document.documentElement.lang || 'en';
    for (var i = 0; i < texts.length; i++) {
      var el = texts[i], h = 0, w = 0, d;
      el.style.minHeight = ''; el.style.minWidth = '';
      d = getComputedStyle(el).display;
      if (d === 'inline') continue;
      ['en', 'ru'].forEach(function (l) { el.textContent = el.getAttribute('data-' + l); var r = el.getBoundingClientRect(); h = Math.max(h, r.height); w = Math.max(w, r.width); });
      el.textContent = el.getAttribute('data-' + lang);
      el.style.minHeight = h + 'px';
      if (/^(?:BUTTON|A)$/.test(el.tagName)) { el.style.minWidth = w + 'px'; el.style.justifyContent = 'center'; el.style.textAlign = 'center'; } // buttons and links: width follows the longer label
    }
  }
  apply(saved.lang === 'ru' ? 'ru' : 'en');
  lock();
  var t = null;
  window.addEventListener('resize', function () { clearTimeout(t); t = setTimeout(lock, 100); });
  document.getElementById('lang').addEventListener('click', function () {
    var lang = document.documentElement.lang === 'ru' ? 'en' : 'ru';
    // Settings are re-read before writing: the tab may have changed them while this page was open
    try { var cur = JSON.parse(localStorage.getItem(key)) || {}; cur.lang = lang; localStorage.setItem(key, JSON.stringify(cur)); } catch (e) { /* storage unavailable */ }
    apply(lang);
  });
})();
