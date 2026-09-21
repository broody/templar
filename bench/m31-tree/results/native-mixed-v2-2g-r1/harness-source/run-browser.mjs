// Isolated local benchmark. All fixture, module and proof traffic stays on loopback.
import http from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const require = createRequire(path.join(repo, 'target/wasm-membership/browser-tools/package.json'));
const { chromium } = require('playwright');
const args = process.argv.slice(2);
const output = path.resolve(args[0] || path.join(here, 'results/browser-probe'));
const repeat = Number(args[1] || 3);
const pkg = path.resolve(args[2] || path.join(repo, 'target/m31-tree/pkg'));
if (args.length < 5) throw new Error('Usage: node run-browser.mjs OUTPUT REPEATS PKG FIXTURE REFERENCE');
if (!Number.isInteger(repeat) || repeat < 1 || repeat > 10) throw new Error('Repeat must be 1–10');
await mkdir(output, { recursive: true });
if (existsSync(path.join(output, 'browser-result.json'))) throw new Error('Refusing to overwrite a completed run');
const fixture = path.resolve(args[3]);
const reference = path.resolve(args[4]);
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json', '.bin': 'application/octet-stream' };
let serverError;
const server = http.createServer(async (req, res) => {
  try {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cache-Control', 'no-store');
    const url = new URL(req.url, 'http://127.0.0.1');
    const match = /^\/proof\/(\d+)$/.exec(url.pathname);
    if (req.method === 'POST' && match) {
      const n = Number(match[1]);
      if (n < 1 || n > repeat) throw new Error('Invalid proof index');
      const chunks = [];
      let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > 10 * 1024 * 1024) throw new Error('Artifact too large'); chunks.push(chunk); }
      const bytes = Buffer.concat(chunks);
      await writeFile(path.join(output, `proof-${n}.bin`), bytes, { flag: 'wx' });
      res.end(JSON.stringify({ bytes: size, sha256: createHash('sha256').update(bytes).digest('hex') }));
      return;
    }
    const routes = { '/': path.join(here, 'web/index.html'), '/app.js': path.join(here, 'web/app.js'), '/worker.js': path.join(here, 'web/worker.js'), '/fixture.json': fixture, '/reference.bin': reference };
    let file = routes[url.pathname];
    if (url.pathname.startsWith('/pkg/')) {
      const relative = decodeURIComponent(url.pathname.slice(5));
      const candidate = path.resolve(pkg, relative);
      if (candidate.startsWith(pkg + path.sep)) file = candidate;
    }
    if (!file || req.method !== 'GET') { res.writeHead(404); res.end(); return; }
    res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
    res.end(await readFile(file));
  } catch (e) {
    serverError = String(e);
    res.writeHead(500); res.end(String(e));
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}/`;
const logs = [];
const samples = [];
let browser;
let sampling = false;
let stopSampling = false;
let samplePromise;
const result = { started_utc: new Date().toISOString(), scope: 'Public synthetic M31 tree or mixed hash workload in one browser worker; no payment/privacy qualification', repeat, pkg, url, host_is_consumer_desktop: false, status: 'running' };
const save = (name, value) => writeFile(path.join(output, name), JSON.stringify(value, null, 2) + '\n');
try {
  browser = await chromium.launch({ executablePath: '/usr/bin/google-chrome', headless: true });
  result.browser_version = browser.version();
  const cdp = await browser.newBrowserCDPSession();
  try { result.browser_command = await cdp.send('Browser.getBrowserCommandLine'); }
  catch (e) {
    result.browser_command_protocol_note = String(e);
    const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
    const browserProcess = processInfo.find(p => p.type === 'browser');
    if (browserProcess) result.browser_command = { arguments: (await readFile(`/proc/${browserProcess.id}/cmdline`, 'utf8')).split('\0').filter(Boolean) };
  }
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on('console', msg => {
    logs.push({ time: Date.now(), type: msg.type(), text: msg.text() });
    if (msg.text().startsWith('MEMBERSHIP_EVENT ')) {
      const event = JSON.parse(msg.text().slice(17));
      if (event.type === 'phase' || event.type === 'ready' || event.type === 'failure') console.log(JSON.stringify(event));
      if (event.type === 'run') console.log(JSON.stringify({ type: 'run', run: event.run, elapsed_ms: event.elapsed_ms, memory_after_bytes: event.memory_after_bytes, matches_native: event.matches_native }));
    }
  });
  page.on('pageerror', e => logs.push({ time: Date.now(), type: 'pageerror', text: String(e) }));
  page.on('crash', () => { result.page_crashed = true; });
  samplePromise = (async () => {
    while (!stopSampling) {
      if (!sampling) {
        sampling = true;
        try {
          const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
          const processes = await Promise.all(processInfo.map(async p => {
            const out = { pid: p.id, type: p.type, cpu_seconds: p.cpuTime };
            try {
              const status = await readFile(`/proc/${p.id}/status`, 'utf8');
              for (const key of ['VmRSS', 'VmHWM', 'VmSwap']) {
                const found = status.split('\n').find(line => line.startsWith(key + ':'))?.match(/\d+/);
                if (found) out[key + '_bytes'] = Number(found[0]) * 1024;
              }
              const rollup = await readFile(`/proc/${p.id}/smaps_rollup`, 'utf8');
              const pss = rollup.match(/^Pss:\s+(\d+)/m);
              if (pss) out.pss_bytes = Number(pss[1]) * 1024;
            } catch (e) { out.read_error = String(e); }
            return out;
          }));
          const rssComplete = processes.length > 0 && processes.every(p => Number.isFinite(p.VmRSS_bytes));
          const pssComplete = processes.length > 0 && processes.every(p => Number.isFinite(p.pss_bytes));
          samples.push({ unix_ms: Date.now(), processes, rss_complete: rssComplete, pss_complete: pssComplete, summed_rss_bytes: rssComplete ? processes.reduce((n, p) => n + p.VmRSS_bytes, 0) : null, summed_pss_bytes: pssComplete ? processes.reduce((n, p) => n + p.pss_bytes, 0) : null });
        } catch (e) { samples.push({ unix_ms: Date.now(), error: String(e) }); }
        sampling = false;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  })();
  await page.goto(url);
  result.runtime = await page.evaluate(() => ({ user_agent: navigator.userAgent, hardware_concurrency: navigator.hardwareConcurrency, cross_origin_isolated: crossOriginIsolated }));
  const report = await page.evaluate(async options => {
    try { return { ok: true, result: await window.runExperiment(options) }; }
    catch (e) { return { ok: false, message: String(e), stack: e.stack, detail: e.detail, experiment: e.experiment }; }
  }, { repeat, negativeTests: true });
  Object.assign(result, report);
  result.status = report.ok ? 'passed' : 'failed';
  await page.screenshot({ path: path.join(output, 'browser.png'), fullPage: true });
} catch (e) {
  result.status = 'failed'; result.error = String(e); result.stack = e.stack;
} finally {
  stopSampling = true;
  await samplePromise;
  result.server_error = serverError ?? null;
  result.completed_utc = new Date().toISOString();
  const observedPeak = key => {
    const values = samples.map(s => s[key]).filter(Number.isFinite);
    return values.length ? Math.max(...values) : null;
  };
  result.sampled_browser_peak_summed_rss_bytes = observedPeak('summed_rss_bytes');
  result.sampled_browser_peak_summed_pss_bytes = observedPeak('summed_pss_bytes');
  result.memory_sample_coverage = { total: samples.length, rss_complete: samples.filter(s => s.rss_complete).length, pss_complete: samples.filter(s => s.pss_complete).length, cdp_errors: samples.filter(s => s.error).length };
  result.memory_metric_note = 'PSS/RSS cover processes reported by Chrome CDP; summed RSS double-counts shared pages. The outer cgroup includes browser plus Node harness/server. WASM linear memory is separate.';
  await save('browser-result.json', result);
  await save('browser-memory.json', samples);
  await save('browser-console.json', logs);
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
console.log(JSON.stringify({ status: result.status, output, browser_peak_pss_gib: result.sampled_browser_peak_summed_pss_bytes === null ? null : result.sampled_browser_peak_summed_pss_bytes / 2**30 }));
process.exitCode = result.status === 'passed' ? 0 : 1;
