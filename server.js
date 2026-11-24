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
