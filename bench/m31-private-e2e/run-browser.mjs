// Local integration test and measurement, using the previously installed browser tools.
import http from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const require = createRequire(path.join(repo, 'target/wasm-membership/browser-tools/package.json'));
const { chromium } = require('playwright');
const [pkgArg, publicArg, privateArg, nativeArg, outArg, repeatArg = '3'] = process.argv.slice(2);
if (!outArg) throw new Error('usage: PKG PUBLIC PRIVATE NATIVE_PROOF OUTPUT [REPEAT]');
const [pkg, publicPath, privatePath, nativePath, output] = [pkgArg, publicArg, privateArg, nativeArg, outArg].map(p => path.resolve(p));
const repeat = Number(repeatArg);
if (!Number.isInteger(repeat) || repeat < 1 || repeat > 3) throw new Error('Repeat must be 1–3');
await mkdir(output, { recursive: false });
const routes = {
  '/': path.join(here, 'web/index.html'), '/worker.js': path.join(here, 'web/worker.js'),
  '/public.json': publicPath, '/private.json': privatePath, '/native.bin': nativePath,
  '/pkg/membership.js': path.join(pkg, 'membership.js'),
  '/pkg/membership_bg.wasm': path.join(pkg, 'membership_bg.wasm'),
};
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json', '.bin': 'application/octet-stream' };
let serverError;
const server = http.createServer(async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    const match = /^\/proof\/([1-3])$/.exec(req.url);
    if (req.method === 'POST' && match && Number(match[1]) <= repeat) {
      const chunks = []; let bytes = 0;
      for await (const c of req) { bytes += c.length; if (bytes > 16 * 1024 * 1024) throw new Error('Proof size cap'); chunks.push(c); }
      await writeFile(path.join(output, `proof-${match[1]}.bin`), Buffer.concat(chunks), { flag: 'wx' });
      res.end('saved'); return;
    }
    const file = routes[req.url];
    if (req.method !== 'GET' || !file) { res.writeHead(404); res.end(); return; }
    res.setHeader('Content-Type', mime[path.extname(file)]);
    res.end(await readFile(file));
  } catch (e) { serverError = String(e); res.writeHead(500); res.end('Local harness error'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const result = { started_utc: new Date().toISOString(), repeat, scope: 'Private membership research; synthetic witness; no payment or PROOF1 qualification' };
let browser, stop = false, sampling;
const samples = [];
try {
  browser = await chromium.launch({ executablePath: '/usr/bin/google-chrome', headless: true });
  result.browser_version = browser.version();
  const cdp = await browser.newBrowserCDPSession();
  sampling = (async () => {
    while (!stop) {
      try {
        const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
        const processes = await Promise.all(processInfo.map(async ({ id, type }) => {
          try {
            const s = await readFile(`/proc/${id}/status`, 'utf8');
            const p = await readFile(`/proc/${id}/smaps_rollup`, 'utf8');
            return { id, type, rss_bytes: Number(s.match(/^VmRSS:\s+(\d+)/m)[1]) * 1024,
              pss_bytes: Number(p.match(/^Pss:\s+(\d+)/m)[1]) * 1024 };
          } catch { return { id, type, unavailable: true }; }
        }));
        const complete = processes.length && processes.every(p => !p.unavailable);
        samples.push({ unix_ms: Date.now(), processes, complete: Boolean(complete),
          rss_bytes: complete ? processes.reduce((s, p) => s + p.rss_bytes, 0) : null,
          pss_bytes: complete ? processes.reduce((s, p) => s + p.pss_bytes, 0) : null });
      } catch (e) { samples.push({ error: String(e) }); }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  })();
  const page = await browser.newPage();
  page.setDefaultTimeout(180000);
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.waitForFunction(() => typeof window.runExperiment === 'function');
  const run = page.evaluate(n => window.runExperiment(n), repeat);
  let timer;
  try { result.report = await Promise.race([run, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Browser experiment timeout')), 180000); })]); }
  finally { clearTimeout(timer); }
  result.status = 'passed';
  await page.screenshot({ path: path.join(output, 'browser.png'), fullPage: true });
} catch (e) { result.status = 'failed'; result.error = String(e); }
finally {
  stop = true; await sampling;
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
  result.server_error = serverError ?? null;
  result.completed_utc = new Date().toISOString();
  for (const metric of ['rss_bytes', 'pss_bytes']) {
    const values = samples.map(s => s[metric]).filter(Number.isFinite);
    result[`sampled_peak_browser_${metric}`] = values.length ? Math.max(...values) : null;
  }
  await writeFile(path.join(output, 'memory-samples.json'), JSON.stringify(samples, null, 2));
  await writeFile(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
}
console.log(JSON.stringify(result));
if (result.status !== 'passed' || serverError) process.exitCode = 1;
