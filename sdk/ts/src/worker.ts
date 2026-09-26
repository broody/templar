// The proving worker (spec §7.3): a fresh WASM instance per proof, terminated afterwards, so a
// crash in the prover is contained and linear memory holding key material is released. Runs as a
// browser module worker or a Node worker thread.
import { call, loadCore, wasm } from './core.js';
import { coreError } from './errors.js';

interface Job {
  /** The wallet's key material (a Templar seed, or a bound seed and its account). */
  keys: Uint8Array;
  plan: string;
  now: string;
  wasm?: BufferSource | string;
}

async function run(job: Job): Promise<{ ok: true; proved: string } | { ok: false; code: string; message: string }> {
  try {
    await loadCore(job.wasm);
    return { ok: true, proved: call(() => wasm.prove_spend(job.keys, job.plan, job.now)) };
  } catch (e) {
    const err = coreError(e);
    return { ok: false, code: err.code, message: err.message };
  }
}

const isNode = typeof process !== 'undefined' && !!process.versions?.node;
if (isNode) {
  const { parentPort } = await import('node:worker_threads');
  parentPort?.once('message', async (job: Job) => parentPort.postMessage(await run(job)));
} else if (typeof self !== 'undefined') {
  self.addEventListener('message', async (e: MessageEvent<Job>) => self.postMessage(await run(e.data)), { once: true });
}
