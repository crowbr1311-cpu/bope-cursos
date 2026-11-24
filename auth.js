/* B.O.P.E - cliente da API (AWS). Senhas, sessões e dados ficam no servidor (Lambda + DynamoDB).
   Mantém a interface "Auth.*" que as páginas já usavam. As leituras continuam síncronas (vêm de um cache carregado
   em Auth.ready); cada alteração é enviada à API e o cache é recarregado antes de a Promise resolver. */
(function (global) {
  'use strict';

  var K_SESS = 'bope_session_v1';
  var API = String((global.BOPE_CONFIG && global.BOPE_CONFIG.apiUrl) || '').replace(/\/+$/, '');
  /* sem apiUrl, mas aberto em localhost: usa o servidor local (cd aws && npm run local) */
  if (!API && global.location && /^(localhost|127\.0\.0\.1)$/.test(global.location.hostname || '')) API = global.location.origin + '/prod';
  var doc = global.document || null;
  var state = empty();

  function empty() { return { user: null, cargos: [], courses: [], myCerts: [], users: [], certs: [], notes: [], punicoes: [] }; }
  function fail(m) { return { ok: false, error: m }; }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function today() { var d = new Date(); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function fmtDate(s) { var p = String(s || '').split('-'); return p.length === 3 ? p[2] + '/' + p[1] + '/' + p[0] : '—'; }

  /* ---------- sessão (token JWT emitido pela API; some ao fechar a aba) ---------- */
  function token() {
    try {
      var s = JSON.parse(global.sessionStorage.getItem(K_SESS) || 'null');
      return s && s.exp > Date.now() ? s.token : null;
    } catch (e) { return null; }
  }
  function startSession(tok, exp) { try { global.sessionStorage.setItem(K_SESS, JSON.stringify({ token: tok, exp: exp })); } catch (e) {} }
  function endSession() { try { global.sessionStorage.removeItem(K_SESS); } catch (e) {} state = empty(); }
  function logout() { endSession(); global.location.replace('login.html'); }

  /* ---------- chamadas à API ---------- */
  function request(method, path, body) {
    if (!API) return Promise.resolve({ ok: false, status: 0, error: 'API não configurada. Para testar no computador, rode "npm run local" na pasta aws e abra http://localhost:3000. Em produção, preencha apiUrl em config.js.' });
    var headers = {}, t = token();
    if (t) headers.Authorization = 'Bearer ' + t;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return global.fetch(API + path, { method: method, headers: headers, body: body === undefined ? undefined : JSON.stringify(body) })
      .then(function (res) {
        return res.json().then(function (j) { j.status = res.status; return j; },
          function () {
            return { ok: false, status: res.status, error: 'A API (' + (API || '/') + ') respondeu HTTP ' + res.status + ' sem ser JSON: a requisição não chegou ao servidor. ' +
              'Abra o site pelo endereço do CloudFront (SiteUrl do deploy) ou, se ele estiver em outro domínio, coloque a ApiUrl completa em config.js.' };
          });
      })
      .catch(function () { return { ok: false, status: 0, error: 'Não foi possível conectar ao servidor.' }; });
  }
  /* recarrega o cache; resolve true se há sessão válida */
  function refresh() {
    if (!token()) { state = empty(); return Promise.resolve(false); }
    return request('GET', '/bootstrap').then(function (r) {
      if (r.ok) {
        state = { user: r.user, cargos: r.cargos || [], courses: r.courses || [], myCerts: r.myCerts || [], users: r.users || [], certs: r.certs || [], notes: r.notes || [], punicoes: r.punicoes || [] };
        return true;
      }
      if (r.status === 401) endSession();   /* token vencido ou usuário removido */
      return false;
    });
  }
  /* envia uma alteração e só resolve depois de o cache refletir o novo estado */
  function mutate(method, path, body) {
    return request(method, path, body).then(function (r) {
      if (r.status === 401) { endSession(); return fail('Sessão expirada. Entre novamente.'); }
      if (!r.ok) return { ok: false, error: r.error || 'Não foi possível concluir a operação.' };
      return refresh().then(function () { return r; });
    });
  }
  function enc(s) { return encodeURIComponent(String(s)); }

  function login(nome, senha) {
    return request('POST', '/login', { nome: nome, senha: senha }).then(function (r) {
      if (r.ok && r.token) { startSession(r.token, r.expiresAt); return refresh().then(function () { return { ok: true }; }); }
      return { ok: false, code: r.code, error: r.error || 'Não foi possível entrar.' };
    });
  }

  /* ---------- leituras (cache) ---------- */
  function current() { return state.user; }
  function isAdmin() { return !!state.user && state.user.role === 'admin'; }
  function cargos() { return state.cargos.slice(); }
  function listUsers() { return isAdmin() ? state.users : []; }
  function listCerts() { return isAdmin() ? state.certs : []; }
  function myCerts() { return state.myCerts; }
  function listCourses() { return state.user ? state.courses : []; }
  function getCourse(id) { return state.user ? (state.courses.filter(function (c) { return c.id === id; })[0] || null) : null; }
  function listNotes() { return isAdmin() ? state.notes : []; }
  function listPunicoes() { return isAdmin() ? state.punicoes : []; }
  function getCert(id) {
    var u = state.user; if (!u) return null;
    var c = (u.role === 'admin' ? state.certs : state.myCerts).filter(function (x) { return x.id === id; })[0];
    if (!c) return null;
    var owner = u.role === 'admin' ? (state.users.filter(function (x) { return String(x.id).toLowerCase() === String(c.userId).toLowerCase(); })[0] || null) : u;
    return { cert: c, user: owner };
  }

  /* ---------- alterações (a API valida tudo e só aceita administrador) ---------- */
  function addUser(d) { return mutate('POST', '/users', d); }
  function updateUser(id, d) { return mutate('PUT', '/users/' + enc(id), d); }
  function resetPassword(id, senha) { return mutate('POST', '/users/' + enc(id) + '/password', { senha: senha }); }
  function deleteUser(id) { return mutate('DELETE', '/users/' + enc(id)); }
  function addCargo(nome) { return mutate('POST', '/cargos', { nome: nome }); }
  function removeCargo(nome) { return mutate('DELETE', '/cargos/' + enc(nome)); }
  function addCourse(d) { return mutate('POST', '/courses', d); }
  function updateCourse(id, d) { return mutate('PUT', '/courses/' + enc(id), d); }
  function removeCourse(id) { return mutate('DELETE', '/courses/' + enc(id)); }
  function addCert(d) { return mutate('POST', '/certs', d); }
  function removeCert(id) { return mutate('DELETE', '/certs/' + enc(id)); }
  function addNote(d) { return mutate('POST', '/notes', d); }
  function updateNote(id, d) { return mutate('PUT', '/notes/' + enc(id), d); }
  function removeNote(id) { return mutate('DELETE', '/notes/' + enc(id)); }
  function addPunicao(d) { return mutate('POST', '/punicoes', d); }
  function updatePunicao(id, d) { return mutate('PUT', '/punicoes/' + enc(id), d); }
  function removePunicao(id) { return mutate('DELETE', '/punicoes/' + enc(id)); }

  /* ---------- backup ---------- */
  /* resolve com o texto JSON do backup, ou '' se falhar */
  function exportBackup() {
    return request('GET', '/backup').then(function (r) { return r.ok && r.backup ? JSON.stringify(r.backup, null, 2) : ''; });
  }
  function importBackup(text) {
    var o; try { o = JSON.parse(text); } catch (e) { return Promise.resolve(fail('Arquivo inválido.')); }
    return mutate('POST', '/backup', { backup: o });
  }

  /* ---------- DOM ---------- */
  function h(tag, attrs) {
    var el = doc.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { if (k === 'text') el.textContent = attrs[k]; else el.setAttribute(k, attrs[k]); });
    for (var i = 2; i < arguments.length; i++) { var c = arguments[i]; if (c != null) el.appendChild(typeof c === 'string' ? doc.createTextNode(c) : c); }
    return el;
  }
  function onDom(fn) { if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', fn); else fn(); }
  function guard(role) {
    var u = current();
    if (!u) {
      var p = (global.location.pathname.split('/').pop() || 'index.html');
      if (!/\.html$/i.test(p)) p += '.html';
      global.location.replace('login.html?next=' + encodeURIComponent(p) + (global.location.search && /certificado/.test(p) ? '&q=' + encodeURIComponent(global.location.search.slice(1)) : ''));
      return null;
    }
    if (role === 'admin' && u.role !== 'admin') { global.location.replace('index.html'); return null; }
    return u;
  }
  function mountUserbar() {
    var el = doc.getElementById('userbar'), u = current();
    if (!el || !u) return;
    el.textContent = '';
    if (u.role === 'admin') el.appendChild(h('a', { href: 'admin.html', 'class': 'navlink', text: 'Painel' }));
    el.appendChild(h('span', { 'class': 'who', text: u.nome + ' (' + u.id + ')' }));
    var b = h('button', { type: 'button', 'class': 'btn small', text: 'Sair' });
    b.addEventListener('click', logout);
    el.appendChild(b);
  }
  /* abas do painel administrativo: <nav id="tabs" data-active="admin|dashboard|anotacoes|punicoes"> */
  function mountTabs() {
    var el = doc.getElementById('tabs'), u = current();
    if (!el || !u || u.role !== 'admin') return;
    var active = el.getAttribute('data-active');
    el.textContent = '';
    [['admin', 'Governança', 'admin.html'], ['dashboard', 'Dashboard', 'dashboard.html'], ['anotacoes', 'Anotações', 'anotacoes.html'], ['punicoes', 'Punições', 'punicoes.html']].forEach(function (t) {
      var a = h('a', { href: t[2], 'class': 'tab' + (t[0] === active ? ' active' : ''), text: t[1] });
      if (t[0] === active) a.setAttribute('aria-current', 'page');
      el.appendChild(a);
    });
  }
  function fmtDateTime(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? '—' : d.toLocaleDateString('pt-BR') + ' ' + d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  }

  var api = {
    user: null, ready: null,
    listCourses: listCourses, getCourse: getCourse, addCourse: addCourse, updateCourse: updateCourse, removeCourse: removeCourse,
    current: current, login: login, logout: logout, guard: guard,
    listUsers: listUsers, listCerts: listCerts, myCerts: myCerts, getCert: getCert, cargos: cargos,
    addUser: addUser, updateUser: updateUser, resetPassword: resetPassword, deleteUser: deleteUser,
    addCargo: addCargo, removeCargo: removeCargo, addCert: addCert, removeCert: removeCert,
    exportBackup: exportBackup, importBackup: importBackup,
    listNotes: listNotes, addNote: addNote, updateNote: updateNote, removeNote: removeNote,
    listPunicoes: listPunicoes, addPunicao: addPunicao, updatePunicao: updatePunicao, removePunicao: removePunicao,
    h: h, fmtDate: fmtDate, fmtDateTime: fmtDateTime, today: today, mountUserbar: mountUserbar, mountTabs: mountTabs
  };
  global.Auth = api;

  /* proteção automática: <script src="auth.js" data-guard="user|admin">. Os scripts das páginas rodam dentro de Auth.ready.then(...) */
  var me = doc && doc.currentScript;
  var mode = me && me.getAttribute('data-guard');
  if (mode) doc.documentElement.style.visibility = 'hidden';
  api.ready = refresh().then(function () {
    if (!mode) return;
    api.user = guard(mode);
    if (api.user) onDom(function () { mountUserbar(); mountTabs(); doc.documentElement.style.visibility = ''; });
  });
})(typeof window !== 'undefined' ? window : globalThis);
