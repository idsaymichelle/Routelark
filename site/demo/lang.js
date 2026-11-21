// Язык тестовой страницы: тот же, что выбран во вкладке Routelark (её настройки лежат на этом же адресе)
(function () {
  var key = 'rl:settings', saved = {};
  try { saved = JSON.parse(localStorage.getItem(key)) || {}; } catch (e) { /* хранилище недоступно */ }
  var texts = document.querySelectorAll('[data-ru]');
  for (var i = 0; i < texts.length; i++) texts[i].setAttribute('data-en', texts[i].textContent);
  function apply(lang) {
    document.documentElement.lang = lang;
    for (var i = 0; i < texts.length; i++) texts[i].textContent = texts[i].getAttribute('data-' + lang);
    // Обе языковые версии блока лежат в одной ячейке сетки: высота берётся по большей, неактивная просто невидима
    var blocks = document.querySelectorAll('section[lang]');
    for (var j = 0; j < blocks.length; j++) { blocks[j].hidden = false; blocks[j].style.visibility = blocks[j].getAttribute('lang') === lang ? '' : 'hidden'; blocks[j].setAttribute('aria-hidden', blocks[j].getAttribute('lang') === lang ? 'false' : 'true'); }
    document.getElementById('lang').textContent = lang === 'ru' ? 'EN' : 'RU';
    document.title = lang === 'ru' ? 'Routelark: тестовая страница' : 'Routelark: test page';
  }
  // Каждый переводимый текст держит место под более длинную версию: при смене языка блоки не сдвигаются
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
      if (/^(?:BUTTON|A)$/.test(el.tagName)) { el.style.minWidth = w + 'px'; el.style.justifyContent = 'center'; el.style.textAlign = 'center'; } // кнопки и ссылки: ширина по длинной подписи
    }
  }
  apply(saved.lang === 'ru' ? 'ru' : 'en');
  lock();
  var t = null;
  window.addEventListener('resize', function () { clearTimeout(t); t = setTimeout(lock, 100); });
  document.getElementById('lang').addEventListener('click', function () {
    var lang = document.documentElement.lang === 'ru' ? 'en' : 'ru';
    // Настройки перечитываются перед записью: вкладка могла их изменить, пока открыта эта страница
    try { var cur = JSON.parse(localStorage.getItem(key)) || {}; cur.lang = lang; localStorage.setItem(key, JSON.stringify(cur)); } catch (e) { /* хранилище недоступно */ }
    apply(lang);
  });
})();
