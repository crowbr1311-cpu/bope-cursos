'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');

const pbkdf2 = promisify(crypto.pbkdf2);
const ITER = 150000;
const SESSION_S = 8 * 3600;
const ID_RE = /^[A-Za-z0-9._-]{3,20}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const SEED = { id: 'CEO', nome: 'Albino', salt: '7fdcswkfPX/g5Qt7pZia4w==', hash: 'MsIlEd1Q9CzgElVxjwpmNJjg80AkWelQD6JailyMMTo=' };
const DEFAULT_CARGOS = ['Diretor', 'Instrutor', 'Membro'];
const DEFAULT_COURSES = [
  { id: 'c1', icone: '🎯', titulo: 'Curso Fuzil/Sub', descricao: 'Domínio total dos armamentos', conteudo: '', link: '' },
  { id: 'c2', icone: '⚡', titulo: 'Manual Operacional', descricao: 'Protocolo de negociação', conteudo: '', link: '' },
  { id: 'c3', icone: '🔥', titulo: 'Curso Acougue', descricao: 'Curso Progressão acougue', conteudo: '', link: '' },
  { id: 'c4', icone: '💥', titulo: 'Curso N/A', descricao: 'Curso N/A', conteudo: '', link: '' },
  { id: 'c5', icone: '⭐', titulo: 'Curso N/A', descricao: 'Curso N/A', conteudo: '', link: '' },
  { id: 'c6', icone: '🚀', titulo: 'Curso N/A', descricao: 'Curso N/A', conteudo: '', link: '' }
];

/* ---------- Banco de Dados (Memória + data.json) ---------- */
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.json');
const store = new Map();
const key = (pk, sk) => pk + '\u0000' + sk;

if (DB_FILE && fs.existsSync(DB_FILE)) {
  try {
    JSON.parse(fs.readFileSync(DB_FILE, 'utf8')).forEach((v) => store.set(key(v.pk, v.sk), v));
  } catch (e) {}
}
const saveDb = () => {
  if (DB_FILE) {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify([...store.values()]));
    } catch (e) {}
  }
};
const clone = (x) => JSON.parse(JSON.stringify(x));

const db = {
  async get(pk, sk) { const v = store.get(key(pk, sk)); return v ? clone(v) : null; },
  async put(item) { store.set(key(item.pk, item.sk), clone(item)); saveDb(); },
  async putNew(item) { if (store.has(key(item.pk, item.sk))) return false; store.set(key(item.pk, item.sk), clone(item)); saveDb(); return true; },
  async del(pk, sk) { store.delete(key(pk, sk)); saveDb(); },
  async query(pk) { return [...store.values()].filter((v) => v.pk === pk).sort((a, b) => (a.sk < b.sk ? -1 : 1)).map(clone); },
  async replaceAll(pk, items) {
    for (const [k, v] of [...store]) if (v.pk === pk) store.delete(k);
    items.forEach((i) => store.set(key(i.pk, i.sk), clone(i)));
    saveDb();
  }
};

/* ---------- Utilidades ---------- */
const rid = () => crypto.randomBytes(8).toString('hex');
const today = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
const lc = (s) => String(s || '').toLowerCase();
const normNome = (n) => String(n || '').trim().replace(/\s+/g, ' ').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const strip = (it) => { if (!it) return it; const o = Object.assign({}, it); delete o.pk; delete o.sk; delete o.ordem; delete o.ttl; return o; };
const pub = (u) => ({ id: u.id, nome: u.nome, cargo: u.cargo, instrutor: !!u.instrutor, role: u.role, fixo: !!u.fixo, criadoEm: u.criadoEm });

async function derive(pass, saltB64) {
  return (await pbkdf2(Buffer.from(String(pass), 'utf8'), Buffer.from(saltB64, 'base64'), ITER, 32, 'sha256')).toString('base64');
}
async function newCreds(pass) {
  const salt = crypto.randomBytes(16).toString('base64');
  return { salt, hash: await derive(pass, salt) };
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

const JWT_SECRET = process.env.JWT_SECRET || 'bope-cursos-jwt-secret-key-prod-2026';
const hmac = (data) => crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');

function signToken(sub) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_S;
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ sub, exp })).toString('base64url');
  return { token: head + '.' + body + '.' + hmac(head + '.' + body), expiresAt: exp * 1000 };
}
function verifyToken(tok) {
  const p = String(tok || '').split('.');
  if (p.length !== 3 || !safeEq(p[2], hmac(p[0] + '.' + p[1]))) return null;
  try {
    const h = JSON.parse(Buffer.from(p[0], 'base64url').toString());
    const b = JSON.parse(Buffer.from(p[1], 'base64url').toString());
    if (h.alg !== 'HS256' || typeof b.sub !== 'string' || !(b.exp * 1000 > Date.now())) return null;
    return b;
  } catch (e) { return null; }
}

let seeded = false;
async function ensureSeed() {
  if (seeded) return;
  await db.putNew({ pk: 'USER', sk: lc(SEED.id), id: SEED.id, nome: SEED.nome, cargo: 'CEO', instrutor: false, role: 'admin', fixo: true, salt: SEED.salt, hash: SEED.hash, criadoEm: '2026-11-23' });
  if (await db.putNew({ pk: 'META', sk: 'seeded', at: new Date().toISOString() })) {
    for (let i = 0; i < DEFAULT_CARGOS.length; i++) await db.put({ pk: 'CARGO', sk: DEFAULT_CARGOS[i], nome: DEFAULT_CARGOS[i], ordem: i });
    for (let i = 0; i < DEFAULT_COURSES.length; i++) await db.put(Object.assign({ pk: 'COURSE', sk: DEFAULT_COURSES[i].id, ordem: i }, DEFAULT_COURSES[i]));
  }
  seeded = true;
}

const byOrdem = (a, b) => (a.ordem || 0) - (b.ordem || 0);
const listUsers = async () => (await db.query('USER')).map(strip);
const listCargos = async () => (await db.query('CARGO')).sort(byOrdem).map((c) => c.nome);
const listCourses = async () => (await db.query('COURSE')).sort(byOrdem).map(strip);
const listCerts = async () => (await db.query('CERT')).map(strip);
const listRecs = async (pk) => (await db.query(pk)).map(strip).sort((a, b) => String(b.criadoEm).localeCompare(String(a.criadoEm)));

const vNome = (n) => { n = String(n || '').trim(); return n.length >= 2 && n.length <= 80 ? '' : 'Informe o nome (2 a 80 caracteres).'; };
const vId = (id) => ID_RE.test(String(id || '')) ? '' : 'ID deve ter 3 a 20 caracteres: letras, números, ponto, hífen ou sublinhado.';
const vSenha = (s) => { s = String(s || ''); return s.length >= 8 && s.length <= 128 ? '' : 'A senha deve ter de 8 a 128 caracteres.'; };

function vCourse(d) {
  d = d || {};
  const t = String(d.titulo || '').trim().replace(/\s+/g, ' '), ds = String(d.descricao || '').trim(),
    ct = String(d.conteudo || '').replace(/\r\n/g, '\n').trim(), ic = String(d.icone || '').trim() || '📘', lk = String(d.link || '').trim();
  if (t.length < 2 || t.length > 80) return { error: 'Informe o título do curso (2 a 80 caracteres).' };
  if (ds.length > 200) return { error: 'A descrição deve ter até 200 caracteres.' };
  if (ct.length > 8000) return { error: 'O conteúdo deve ter até 8000 caracteres.' };
  if (ic.length > 8) return { error: 'Use apenas um emoji como ícone.' };
  if (lk && (lk.length > 300 || !/^https?:\/\/[^\s]+$/i.test(lk))) return { error: 'O link deve começar com http:// ou https://.' };
  return { value: { icone: ic, titulo: t, descricao: ds, conteudo: ct, link: lk } };
}
function vText(s, min, max, label) {
  s = String(s == null ? '' : s).replace(/\r\n/g, '\n').trim();
  return (s.length < min || s.length > max) ? { error: 'Preencha ' + label + ' (' + min + ' a ' + max + ' caracteres).' } : { value: s };
}
function vNote(d) {
  d = d || {};
  const n = vText(d.nome, 2, 80, 'o nome'); if (n.error) return n;
  const t = vText(d.texto, 1, 4000, 'as observações/relatos'); if (t.error) return t;
  return { value: { nome: n.value.replace(/\s+/g, ' '), texto: t.value } };
}
function vPun(d) {
  d = d || {};
  const a = vText(d.autor, 2, 80, 'o autor da punição'); if (a.error) return a;
  const p = vText(d.punido, 2, 80, 'o militar punido'); if (p.error) return p;
  const m = vText(d.motivo, 3, 2000, 'o motivo'); if (m.error) return m;
  return { value: { autor: a.value.replace(/\s+/g, ' '), punido: p.value.replace(/\s+/g, ' '), motivo: m.value } };
}

const json = (status, body) => ({
  statusCode: status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  body: JSON.stringify(body)
});
const ok = (extra) => json(200, Object.assign({ ok: true }, extra));
const fail = (error, status, code) => json(status || 400, { ok: false, error, code });

/* ---------- Handlers da API ---------- */
const DUP_NOME = 'Já existe um usuário com esse nome. O nome é usado no login e precisa ser único.';
const nameTaken = (list, nome, exceptId) => list.some((u) => normNome(u.nome) === normNome(nome) && lc(u.id) !== lc(exceptId));

/* Níveis de acesso: CEO (Total), Instrutor (Cursos, Dashboard, Anotações, Punições), Membro (Início apenas) */
const isCEO = (u) => !!u && (u.role === 'admin' || String(u.id).toUpperCase() === 'CEO');
const isInstrutor = (u) => !!u && !isCEO(u) && (!!u.instrutor || u.cargo === 'Instrutor' || String(u.cargo || '').toLowerCase() === 'instrutor');
const isPrivileged = (u) => isCEO(u) || isInstrutor(u);
const isMembro = (u) => !isPrivileged(u);

const handlers = {
  // auth.login
  async login({ body }) {
    const nome = String(body.nome || ''), senha = String(body.senha || '');
    const k = normNome(nome);
    if (!k || !senha || senha.length > 256) return fail('Informe nome e senha.', 400);

    const lock = (await db.get('LOCK', k)) || { n: 0, until: 0 };
    if (lock.until > Date.now()) {
      return fail('Muitas tentativas. Aguarde ' + Math.ceil((lock.until - Date.now()) / 1000) + ' s.', 429, 'locked');
    }
    const cands = (await listUsers()).filter((u) => normNome(u.nome) === k);
    if (!cands.length) return fail('Usuário não encontrado. Abra um ticket no Discord para solicitar seu acesso.', 401, 'nouser');

    const res = await Promise.all(cands.map(async (u) => (safeEq(await derive(senha, u.salt), u.hash) ? u : null)));
    const u = res.find(Boolean);
    if (!u) {
      lock.n = (lock.n || 0) + 1;
      if (lock.n >= 5) { lock.until = Date.now() + 30000; lock.n = 0; }
      await db.put({ pk: 'LOCK', sk: k, n: lock.n, until: lock.until, ttl: Math.floor(Date.now() / 1000) + 3600 });
      return fail('Senha incorreta.', 401, 'badpass');
    }
    if (lock.n || lock.until) await db.del('LOCK', k);
    const s = signToken(u.id);
    return ok({ token: s.token, expiresAt: s.expiresAt, user: pub(u) });
  },

  // auth.me
  async me({ me }) {
    return ok({ user: pub(me) });
  },

  // data.bootstrap
  async bootstrap({ me }) {
    const admin = isPrivileged(me);
    const [cargos, courses, certs] = await Promise.all([listCargos(), listCourses(), listCerts()]);
    const out = {
      user: pub(me), cargos, courses,
      myCerts: certs.filter((x) => lc(x.userId) === lc(me.id)),
      users: [], certs: [], notes: [], punicoes: []
    };
    if (admin) {
      const [users, notes, puns] = await Promise.all([listUsers(), listRecs('NOTE'), listRecs('PUN')]);
      out.users = users.map(pub); out.certs = certs; out.notes = notes; out.punicoes = puns;
    }
    return ok(out);
  },

  // users.create
  async userCreate({ body: d }) {
    const e = vNome(d.nome) || vId(d.id) || vSenha(d.senha);
    if (e) return fail(e);
    if (!(await listCargos()).includes(d.cargo)) return fail('Selecione um cargo válido.');
    const list = await listUsers();
    if (list.some((u) => lc(u.id) === lc(d.id))) return fail('Já existe um usuário com esse ID.');
    if (nameTaken(list, d.nome)) return fail(DUP_NOME);
    const cr = await newCreds(String(d.senha));
    const done = await db.putNew({
      pk: 'USER', sk: lc(d.id), id: String(d.id), nome: String(d.nome).trim().replace(/\s+/g, ' '), cargo: d.cargo,
      instrutor: !!d.instrutor, role: 'user', salt: cr.salt, hash: cr.hash, criadoEm: today()
    });
    return done ? ok() : fail('Já existe um usuário com esse ID.');
  },

  // users.update
  async userUpdate({ params, body: d }) {
    const u = await db.get('USER', lc(params.id));
    if (!u) return fail('Usuário não encontrado.', 404);
    if (u.role !== 'admin') {
      const e = vNome(d.nome); if (e) return fail(e);
      if (nameTaken(await listUsers(), d.nome, u.id)) return fail(DUP_NOME);
      if (!(await listCargos()).includes(d.cargo)) return fail('Selecione um cargo válido.');
      u.cargo = d.cargo;
      u.nome = String(d.nome).trim().replace(/\s+/g, ' ');
    }
    u.instrutor = !!d.instrutor;
    await db.put(u);
    return ok();
  },

  // users.resetPassword
  async userPassword({ params, body: d }) {
    const e = vSenha(d.senha); if (e) return fail(e);
    const u = await db.get('USER', lc(params.id));
    if (!u) return fail('Usuário não encontrado.', 404);
    const cr = await newCreds(String(d.senha));
    u.salt = cr.salt; u.hash = cr.hash;
    await db.put(u);
    return ok();
  },

  // users.remove
  async userDelete({ me, params }) {
    const u = await db.get('USER', lc(params.id));
    if (!u) return fail('Usuário não encontrado.', 404);
    if (u.role === 'admin' || lc(u.id) === lc(me.id)) return fail('O administrador não pode ser excluído.');
    for (const ct of await db.query('CERT')) if (lc(ct.userId) === lc(u.id)) await db.del('CERT', ct.sk);
    await db.del('USER', u.sk);
    return ok();
  },

  // cargos.create
  async cargoCreate({ body }) {
    const nome = String(body.nome || '').trim();
    if (nome.length < 2 || nome.length > 40) return fail('O cargo deve ter de 2 a 40 caracteres.');
    const list = await listCargos();
    if (nome.toLowerCase() === 'ceo' || list.some((x) => x.toLowerCase() === nome.toLowerCase())) return fail('Esse cargo já existe.');
    await db.put({ pk: 'CARGO', sk: nome, nome, ordem: Date.now() });
    return ok();
  },

  // cargos.remove
  async cargoDelete({ params }) {
    let nome = params.nome || '';
    try { nome = decodeURIComponent(nome); } catch (e) {}
    if ((await listUsers()).some((u) => u.cargo === nome)) return fail('Há usuários com esse cargo. Altere o cargo deles antes de remover.');
    await db.del('CARGO', nome);
    return ok();
  },

  // courses.create
  async courseCreate({ body }) {
    const v = vCourse(body); if (v.error) return fail(v.error);
    const id = 'c' + rid();
    await db.put(Object.assign({ pk: 'COURSE', sk: id, id, ordem: Date.now() }, v.value));
    return ok({ id });
  },

  // courses.update
  async courseUpdate({ params, body }) {
    const v = vCourse(body); if (v.error) return fail(v.error);
    const old = await db.get('COURSE', params.id);
    if (!old) return fail('Curso não encontrado.', 404);
    await db.put(Object.assign({ pk: 'COURSE', sk: old.sk, id: old.id, ordem: old.ordem }, v.value));
    return ok();
  },

  // courses.remove
  async courseDelete({ params }) {
    if (!(await db.get('COURSE', params.id))) return fail('Curso não encontrado.', 404);
    await db.del('COURSE', params.id);
    return ok();
  },

  // certs.create
  async certCreate({ me, body: d }) {
    const user = await db.get('USER', lc(d.userId));
    if (!user) return fail('Selecione um usuário.');
    const course = await db.get('COURSE', String(d.cursoId || ''));
    if (!course) return fail('Selecione um curso.');
    if (!DATE_RE.test(String(d.data || ''))) return fail('Informe a data de conclusão.');
    const certs = await db.query('CERT');
    if (certs.some((x) => lc(x.userId) === lc(user.id) && (x.cursoId ? x.cursoId === course.id : x.curso === course.titulo))) {
      return fail('Esse usuário já tem certificado desse curso.');
    }
    let instr = null;
    if (d.instrutorId) {
      instr = await db.get('USER', lc(d.instrutorId));
      if (!instr || !instr.instrutor) return fail('O instrutor selecionado precisa estar com "Instrutor ativo" = Sim.');
    }
    const id = rid();
    await db.put({
      pk: 'CERT', sk: id, id, userId: user.id, cursoId: course.id, curso: course.titulo, data: d.data, emitidoPor: me.nome,
      instrutorId: instr ? instr.id : '', instrutorNome: instr ? instr.nome : '', emitidoEm: today()
    });
    return ok({ id });
  },

  // certs.remove
  async certDelete({ params }) {
    await db.del('CERT', params.id);
    return ok();
  },

  // notes
  async noteCreate({ me, body }) {
    const v = vNote(body); if (v.error) return fail(v.error);
    const id = rid();
    await db.put(Object.assign({ pk: 'NOTE', sk: id, id, criadoEm: new Date().toISOString(), registradoPor: me.nome }, v.value));
    return ok({ id });
  },
  async noteUpdate({ me, params, body }) {
    const v = vNote(body); if (v.error) return fail(v.error);
    const r = await db.get('NOTE', params.id);
    if (!r) return fail('Registro não encontrado.', 404);
    await db.put(Object.assign(r, v.value, { editadoEm: new Date().toISOString(), editadoPor: me.nome }));
    return ok();
  },
  async noteDelete({ params }) {
    if (!(await db.get('NOTE', params.id))) return fail('Registro não encontrado.', 404);
    await db.del('NOTE', params.id);
    return ok();
  },

  // punicoes
  async punCreate({ me, body }) {
    const v = vPun(body); if (v.error) return fail(v.error);
    const id = rid();
    await db.put(Object.assign({ pk: 'PUN', sk: id, id, criadoEm: new Date().toISOString(), registradoPor: me.nome }, v.value));
    return ok({ id });
  },
  async punUpdate({ me, params, body }) {
    const v = vPun(body); if (v.error) return fail(v.error);
    const r = await db.get('PUN', params.id);
    if (!r) return fail('Registro não encontrado.', 404);
    await db.put(Object.assign(r, v.value, { editadoEm: new Date().toISOString(), editadoPor: me.nome }));
    return ok();
  },
  async punDelete({ params }) {
    if (!(await db.get('PUN', params.id))) return fail('Registro não encontrado.', 404);
    await db.del('PUN', params.id);
    return ok();
  },

  // backup.export
  async backupExport() {
    const [users, cargos, certs, courses, notes, punicoes] = await Promise.all([
      listUsers(), listCargos(), listCerts(), listCourses(), listRecs('NOTE'), listRecs('PUN')
    ]);
    return ok({ backup: { v: 1, users, cargos, certs, courses, notes, punicoes } });
  },

  // backup.import
  async backupImport({ body }) {
    const o = body.backup;
    if (!o || !Array.isArray(o.users) || !Array.isArray(o.cargos) || !Array.isArray(o.certs)) return fail('Arquivo inválido.');
    const good = o.users.every((u) => u && ID_RE.test(String(u.id)) && typeof u.nome === 'string' && typeof u.salt === 'string' && typeof u.hash === 'string' && (u.role === 'admin' || u.role === 'user'));
    if (!good || !o.users.some((u) => u.role === 'admin')) return fail('O backup precisa ter usuários válidos e um administrador.');

    const cargos = o.cargos.filter((x) => typeof x === 'string' && x.length >= 1 && x.length <= 40);
    const certs = o.certs.filter((x) => x && typeof x.id === 'string' && typeof x.userId === 'string' && typeof x.curso === 'string' && x.curso.length <= 80 && DATE_RE.test(String(x.data)))
      .map((x) => ({
        id: x.id.slice(0, 40), userId: x.userId, cursoId: typeof x.cursoId === 'string' ? x.cursoId : '', curso: x.curso, data: x.data,
        emitidoPor: String(x.emitidoPor || '').slice(0, 80), instrutorId: String(x.instrutorId || '').slice(0, 20), instrutorNome: String(x.instrutorNome || '').slice(0, 80),
        emitidoEm: DATE_RE.test(String(x.emitidoEm || '')) ? x.emitidoEm : ''
      }));
    
    function cleanRecs(list, fields) {
      if (!Array.isArray(list)) return null;
      return list.filter((r) => r && typeof r.id === 'string' && fields.every((f) => typeof r[f[0]] === 'string')).map((r) => {
        const x = { id: r.id.slice(0, 40), criadoEm: String(r.criadoEm || '').slice(0, 40), registradoPor: String(r.registradoPor || '').slice(0, 80) };
        fields.forEach((f) => { x[f[0]] = r[f[0]].slice(0, f[1]); });
        if (r.editadoEm) { x.editadoEm = String(r.editadoEm).slice(0, 40); x.editadoPor = String(r.editadoPor || '').slice(0, 80); }
        return x;
      });
    }

    const notes = cleanRecs(o.notes, [['nome', 80], ['texto', 4000]]);
    const puns = cleanRecs(o.punicoes, [['autor', 80], ['punido', 80], ['motivo', 2000]]);

    let courses = null;
    if (Array.isArray(o.courses)) {
      courses = [];
      for (const x of o.courses) {
        const v = vCourse(x || {});
        if (v.error || typeof (x || {}).id !== 'string' || !/^c[a-z0-9]{1,20}$/.test(x.id)) return fail('O backup tem um curso inválido.');
        courses.push(Object.assign({ id: x.id }, v.value));
      }
    }
    const users = o.users.map((u) => ({
      id: String(u.id), nome: String(u.nome).slice(0, 80), cargo: u.role === 'admin' ? 'CEO' : String(u.cargo || ''), instrutor: !!u.instrutor,
      role: u.role, fixo: String(u.id) === SEED.id, salt: u.salt, hash: u.hash, criadoEm: String(u.criadoEm || '')
    }));

    await db.replaceAll('USER', users.map((u) => Object.assign({ pk: 'USER', sk: lc(u.id) }, u)));
    await db.replaceAll('CARGO', cargos.map((n, i) => ({ pk: 'CARGO', sk: n, nome: n, ordem: i })));
    await db.replaceAll('CERT', certs.map((x) => Object.assign({ pk: 'CERT', sk: x.id }, x)));
    if (courses) await db.replaceAll('COURSE', courses.map((x, i) => Object.assign({ pk: 'COURSE', sk: x.id, ordem: i }, x)));
    if (notes) await db.replaceAll('NOTE', notes.map((x) => Object.assign({ pk: 'NOTE', sk: x.id }, x)));
    if (puns) await db.replaceAll('PUN', puns.map((x) => Object.assign({ pk: 'PUN', sk: x.id }, x)));
    seeded = false;
    await ensureSeed();
    return ok();
  }
};

/* ---------- Roteamento das 22 rotas ---------- */
const ROUTES = [
  { method: 'POST',   re: /^\/login$/,                  role: 'none',      fn: handlers.login },
  { method: 'GET',    re: /^\/me$/,                     role: 'user',      fn: handlers.me },
  { method: 'GET',    re: /^\/bootstrap$/,              role: 'user',      fn: handlers.bootstrap },
  { method: 'POST',   re: /^\/users$/,                  role: 'ceo',       fn: handlers.userCreate },
  { method: 'PUT',    re: /^\/users\/(?<id>[^/]+)$/,    role: 'ceo',       fn: handlers.userUpdate },
  { method: 'POST',   re: /^\/users\/(?<id>[^/]+)\/password$/, role: 'ceo', fn: handlers.userPassword },
  { method: 'DELETE', re: /^\/users\/(?<id>[^/]+)$/,    role: 'ceo',       fn: handlers.userDelete },
  { method: 'POST',   re: /^\/cargos$/,                 role: 'ceo',       fn: handlers.cargoCreate },
  { method: 'DELETE', re: /^\/cargos\/(?<nome>[^/]+)$/, role: 'ceo',       fn: handlers.cargoDelete },
  { method: 'POST',   re: /^\/courses$/,                role: 'instrutor', fn: handlers.courseCreate },
  { method: 'PUT',    re: /^\/courses\/(?<id>[^/]+)$/,  role: 'instrutor', fn: handlers.courseUpdate },
  { method: 'DELETE', re: /^\/courses\/(?<id>[^/]+)$/,  role: 'instrutor', fn: handlers.courseDelete },
  { method: 'POST',   re: /^\/certs$/,                  role: 'instrutor', fn: handlers.certCreate },
  { method: 'DELETE', re: /^\/certs\/(?<id>[^/]+)$/,    role: 'instrutor', fn: handlers.certDelete },
  { method: 'POST',   re: /^\/notes$/,                  role: 'instrutor', fn: handlers.noteCreate },
  { method: 'PUT',    re: /^\/notes\/(?<id>[^/]+)$/,    role: 'instrutor', fn: handlers.noteUpdate },
  { method: 'DELETE', re: /^\/notes\/(?<id>[^/]+)$/,    role: 'instrutor', fn: handlers.noteDelete },
  { method: 'POST',   re: /^\/punicoes$/,               role: 'instrutor', fn: handlers.punCreate },
  { method: 'PUT',    re: /^\/punicoes\/(?<id>[^/]+)$/, role: 'instrutor', fn: handlers.punUpdate },
  { method: 'DELETE', re: /^\/punicoes\/(?<id>[^/]+)$/, role: 'instrutor', fn: handlers.punDelete },
  { method: 'GET',    re: /^\/backup$/,                 role: 'ceo',       fn: handlers.backupExport },
  { method: 'POST',   re: /^\/backup$/,                 role: 'ceo',       fn: handlers.backupImport }
];

async function authenticate(req) {
  const h = req.headers.authorization || req.headers.Authorization || '';
  const m = /^Bearer (.+)$/.exec(h);
  const claims = m && verifyToken(m[1]);
  if (!claims) return null;
  return await db.get('USER', lc(claims.sub));
}

const SITE = __dirname;
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const port = process.env.PORT || 3000;

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));

  // Healthcheck para Render
  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('OK');
  }

  // Rotas de API (/prod/*)
  if (url.pathname.startsWith('/prod/')) {
    const p = url.pathname.slice(5);
    const match = ROUTES.find((r) => r.method === req.method && r.re.test(p));
    if (!match) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end('{"ok":false,"error":"Rota não encontrada."}');
    }

    const chunks = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', async () => {
      try {
        await ensureSeed();
        let me = null;
        if (match.role !== 'none') {
          me = await authenticate(req);
          if (!me) {
            const out = fail('Sessão expirada. Entre novamente.', 401, 'unauth');
            res.writeHead(out.statusCode, out.headers);
            return res.end(out.body);
          }
          if (match.role === 'ceo' && !isCEO(me)) {
            const out = fail('Apenas o CEO tem acesso a esta funcionalidade (usuários, cargos e backup).', 403, 'forbidden');
            res.writeHead(out.statusCode, out.headers);
            return res.end(out.body);
          }
          if (match.role === 'instrutor' && !isPrivileged(me)) {
            const out = fail('Acesso permitido apenas para Instrutores e CEO.', 403, 'forbidden');
            res.writeHead(out.statusCode, out.headers);
            return res.end(out.body);
          }
        }

        let body = {};
        const raw = Buffer.concat(chunks).toString('utf8');
        if (raw) {
          try { body = JSON.parse(raw); } catch (e) {
            const out = fail('Corpo da requisição inválido.', 400);
            res.writeHead(out.statusCode, out.headers);
            return res.end(out.body);
          }
        }

        const m = match.re.exec(p);
        const params = m && m.groups ? Object.assign({}, m.groups) : {};
        const out = await match.fn({ req, me, body, params });
        res.writeHead(out.statusCode, out.headers);
        res.end(out.body);
      } catch (err) {
        console.error('Erro na requisição:', err);
        const out = fail('Não foi possível concluir a operação.', 500);
        res.writeHead(out.statusCode, out.headers);
        res.end(out.body);
      }
    });
    return;
  }

  // Serve auth.js com os níveis de acesso (CEO, Instrutor, Membro)
  if (url.pathname === '/auth.js') {
    const authPath = path.join(SITE, 'auth.js');
    let code = fs.existsSync(authPath) ? fs.readFileSync(authPath, 'utf8') : '';
    if (!code.includes('isCEO')) {
      // 1. Injeta as funções de nível de acesso (substitui isAdmin existente)
      code = code.replace(
        "function isAdmin() { return !!state.user && state.user.role === 'admin'; }",
        "function isCEO() { var u = state.user; return !!u && (u.role === 'admin' || String(u.id).toUpperCase() === 'CEO'); }\n  function isInstrutor(u) { u = u || state.user; return !!u && !isCEO() && (u.instrutor === true || u.cargo === 'Instrutor' || String(u.cargo || '').toLowerCase() === 'instrutor'); }\n  function isPrivileged() { return isCEO() || isInstrutor(); }\n  function isMembro() { var u = state.user; return !!u && !isPrivileged(); }\n  function isAdmin() { return isPrivileged(); }"
      )
      // 2. Ajusta guard para usar isPrivileged ao invés de checar role diretamente
      .replace("if (role === 'admin' && u.role !== 'admin')", "if (role === 'admin' && !isPrivileged())")
      // 3. Mostra link "Painel" para CEO e Instrutor
      .replace("if (u.role === 'admin') el.appendChild(h('a', { href: 'admin.html', 'class': 'navlink', text: 'Painel' }));", "if (isPrivileged()) el.appendChild(h('a', { href: 'admin.html', 'class': 'navlink', text: 'Painel' }));")
      // 4. mountTabs: exige isPrivileged
      .replace("if (!el || !u || u.role !== 'admin') return;", "if (!el || !u || !isPrivileged()) return;")
      // 5. listCerts usa isAdmin() 
      .replace("var c = (u.role === 'admin' ? state.certs : state.myCerts)", "var c = (isAdmin() ? state.certs : state.myCerts)")
      .replace("var owner = u.role === 'admin' ?", "var owner = isAdmin() ?")
      // 6. Tabs: CEO vê "Governança", Instrutor vê "Cursos & Certificados"
      .replace(
        "[['admin', 'Governança', 'admin.html'], ['dashboard', 'Dashboard', 'dashboard.html'], ['anotacoes', 'Anotações', 'anotacoes.html'], ['punicoes', 'Punições', 'punicoes.html']]",
        "[[isCEO() ? ['admin', 'Governança', 'admin.html'] : ['admin', 'Cursos & Certificados', 'admin.html']], ['dashboard', 'Dashboard', 'dashboard.html'], ['anotacoes', 'Anotações', 'anotacoes.html'], ['punicoes', 'Punições', 'punicoes.html']].flat()"
      )
      // 7. Exporta isCEO/isInstrutor/isPrivileged/isMembro no objeto api
      //    IMPORTANTE: o api original usa "user: null, ready: null," como primeira linha - adicionamos as funções após
      .replace(
        "user: null, ready: null,",
        "user: null, ready: null,\n    isCEO: isCEO, isInstrutor: isInstrutor, isPrivileged: isPrivileged, isMembro: isMembro, isAdmin: isAdmin,"
      );
    }
    res.writeHead(200, {
      'Content-Type': 'text/javascript; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    return res.end(code);
  }

  // Serve admin.html ajustando interface para CEO vs Instrutor
  if (url.pathname === '/admin.html') {
    const adminPath = path.join(SITE, 'admin.html');
    let html = fs.existsSync(adminPath) ? fs.readFileSync(adminPath, 'utf8') : '';
    if (!html.includes('isCEO')) {
      const patch = `<script>
Auth.ready.then(function () {
  if (!Auth.user) return;
  var isCEO = Auth.isCEO && Auth.isCEO();
  if (!isCEO) {
    var h1 = document.querySelector('h1');
    if (h1) h1.textContent = 'CURSOS & CERTIFICADOS';
    var lead = document.querySelector('.lead');
    if (lead) lead.textContent = 'Área do Instrutor: gerenciamento de cursos e emissão de certificados.';
    var bU = document.getElementById('btnUser'); if (bU) bU.style.display = 'none';
    var bC = document.getElementById('btnCargo'); if (bC) bC.style.display = 'none';
    var bE = document.getElementById('btnExport'); if (bE) bE.style.display = 'none';
    var bI = document.getElementById('btnImport'); if (bI) bI.style.display = 'none';
    var sU = document.getElementById('h-users'); if (sU && sU.closest('section')) sU.closest('section').style.display = 'none';
    var sC = document.getElementById('h-cargos'); if (sC && sC.closest('section')) sC.closest('section').style.display = 'none';
  }
});
</script>`;
      html = html.replace('</body>', patch + '\n</body>');
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    return res.end(html);
  }

  // Serve curso.html com o botão de editar para Instrutores
  if (url.pathname === '/curso.html') {
    const cursoPath = path.join(SITE, 'curso.html');
    let html = fs.existsSync(cursoPath) ? fs.readFileSync(cursoPath, 'utf8') : '';
    html = html.replace("Auth.user.role === 'admin'", "(Auth.isPrivileged && Auth.isPrivileged())");
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    return res.end(html);
  }

  // Arquivos estáticos
  let name = url.pathname === '/' ? 'login.html' : decodeURIComponent(url.pathname.slice(1));
  let file = path.join(SITE, name);

  if (!fs.existsSync(file) && fs.existsSync(file + '.html')) {
    name += '.html';
    file += '.html';
  }

  if (!/^[\w.-]+\.(html|js|css|json|png|jpg|jpeg|svg|ico)$/i.test(name) || !file.startsWith(SITE + path.sep) || !fs.existsSync(file)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Página não encontrada');
  }

  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, {
    'Content-Type': TYPES[ext] || 'application/octet-stream',
    'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400'
  });
  res.end(fs.readFileSync(file));
}).listen(port, () => console.log('B.O.P.E Cursos rodando na porta ' + port));
