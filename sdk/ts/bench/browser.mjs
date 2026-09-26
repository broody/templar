// Proof time and linear memory in headless Chrome (spec §12.4): serves sdk/ts and sdk/vectors,
// runs bench/web/index.html, writes the results. `node bench/browser.mjs OUT_JSON [RUNS] [v4|v5]`.
import http from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = path.dirname(fileURLToPath(import.meta.url));
const ts = path.resolve(here, '..');
const repo = path.resolve(ts, '../..');
const require = createRequire(path.join(repo, 'target/wasm-membership/browser-tools/package.json'));
const { chromium } = require('playwright');
const [out, runs = '3', mode = 'v4'] = process.argv.slice(2);
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json' };
let result;
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'POST' && url.pathname === '/result') {
    let body = '';
    for await (const c of req) body += c;
    result = JSON.parse(body);
    return res.end('ok');
  }
  const file = url.pathname.startsWith('/vectors/') ? path.join(repo, 'sdk', url.pathname) : path.join(ts, url.pathname === '/' ? 'bench/web/index.html' : url.pathname);
  if (!file.startsWith(path.join(repo, 'sdk'))) return res.writeHead(403).end();
  try {
    res.setHeader('Content-Type', mime[path.extname(file)] ?? 'application/octet-stream');
    res.end(await readFile(file));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ executablePath: process.env.CHROME ?? '/usr/bin/google-chrome', args: ['--headless=new'] });
const page = await browser.newPage();
await page.goto(`http://127.0.0.1:${server.address().port}/?runs=${runs}&mode=${mode}`);
await page.waitForFunction(() => document.title === 'done', null, { timeout: 30 * 60_000 });
const doc = { browser: `chromium ${browser.version()}`, date: new Date().toISOString(), runs: result };
await browser.close();
server.close();
await writeFile(out, JSON.stringify(doc, null, 1));
console.log(JSON.stringify(doc, null, 1));
