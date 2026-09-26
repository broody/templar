// Proving in a worker (spec §7.3), one worker per proof.
import type { Proved } from './core.js';
import { TemplarError } from './errors.js';

export interface ProveOptions {
  /** The core's `.wasm` (bytes or URL) for the worker; defaults to the packaged one. */
  wasm?: BufferSource | string;
}

type Reply = { ok: true; proved: string } | { ok: false; code: string; message: string };

/**
 * Proves `plan` in a fresh worker with the wallet's key material. A V5 plan needs `now` (the
 * latest block and the pool's `E`, `Q`; JSON), `"null"` otherwise.
 */
export async function proveInWorker(keys: Uint8Array, plan: string, now: string, opts: ProveOptions = {}): Promise<Proved> {
  const url = new URL('./worker.js', import.meta.url);
  const job = { keys, plan, now, wasm: opts.wasm };
  let reply: Reply;
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { Worker } = await import('node:worker_threads');
    const w = new Worker(url);
    try {
      reply = await new Promise<Reply>((resolve, reject) => {
        w.once('message', resolve);
        w.once('error', reject);
        w.once('exit', (code) => reject(new TemplarError('proving', `the proving worker exited (${code})`)));
        w.postMessage(job);
      });
    } finally {
      await w.terminate();
    }
  } else {
    const w = new Worker(url, { type: 'module' });
    try {
      reply = await new Promise<Reply>((resolve, reject) => {
        w.onmessage = (e: MessageEvent<Reply>) => resolve(e.data);
        w.onerror = (e) => reject(new TemplarError('proving', `the proving worker failed: ${e.message}`));
        w.postMessage(job);
      });
    } finally {
      w.terminate();
    }
  }
  if (!reply.ok) throw new TemplarError(reply.code, reply.message);
  return JSON.parse(reply.proved) as Proved;
}
