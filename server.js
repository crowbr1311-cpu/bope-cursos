'use strict';
const path = require('path'), fs = require('fs'), http = require('http');

process.env.DB_DRIVER = 'memory';
process.env.DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.json');
process.env.JWT_SECRET = process.env.JWT_SECRET || 'bope-cursos-jwt-secret-key-prod-2026';

const SITE = __dirname;
const tpl = fs.readFileSync(path.join(__dirname, 'aws', 'template.yaml'), 'utf8');
const routes = [...tpl.matchAll(/Handler: handlers\/(\S+)[\s\S]*?Method: (\w+), Path: "([^"]+)"/g)].map((m) => {
  let fn = require('./aws/src/handlers/' + m[1].split('.')[0]);
  m[1].split('.').slice(1).forEach((k) => { fn = fn[k]; });
  return { fn, method: m[2], re: new RegExp('^' + m[3].replace(/\{(\w+)\}/g, '(?<$1>[^/]+)') + '$') };
});

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

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  
  // Rota de API (/prod/*)
  if (url.pathname.startsWith('/prod/')) {
    const p = url.pathname.slice(5);
    const hit = routes.map((r) => ({ r, m: r.re.exec(p) })).find((x) => x.m && x.r.method === req.method);
    if (!hit) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end('{"ok":false,"error":"Rota não encontrada."}');
    }
    const chunks = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', async () => {
      try {
        const out = await hit.r.fn({
          headers: req.headers,
          body: Buffer.concat(chunks).toString() || undefined,
          pathParameters: Object.assign({}, hit.m.groups)
        });
        res.writeHead(out.statusCode, out.headers);
        res.end(out.body);
      } catch (err) {
        console.error('Erro na rota:', err);
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end('{"ok":false,"error":"Erro interno do servidor."}');
      }
    });
    return;
  }

  // Healthcheck para o Render
  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('OK');
  }

  // Arquivos estáticos do site
  let name = url.pathname === '/' ? 'login.html' : decodeURIComponent(url.pathname.slice(1));
  let file = path.join(SITE, name);

  // Permite abrir /admin ao invés de /admin.html
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
}).listen(port, () => console.log('B.O.P.E Cursos rodando em http://localhost:' + port));
