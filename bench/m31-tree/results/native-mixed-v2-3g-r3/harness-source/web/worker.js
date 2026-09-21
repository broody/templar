let memory;
let currentRun = 0;
let phases = [];
globalThis.onMembershipPhase = phase => {
  const event = { type: 'phase', run: currentRun, phase, worker_ms: performance.now(), linear_memory_bytes: memory?.buffer.byteLength ?? null };
  phases.push(event);
  self.postMessage(event);
};
const hash = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
self.onmessage = async ({ data: options }) => {
  try {
    const { default: init, prove_membership, test_membership_mutations } = await import('/pkg/templar_m31_tree.js');
    const loadStart = performance.now();
    const exports = await init();
    memory = exports.memory;
    const fixture = await (await fetch('/fixture.json')).text();
    const reference = await (await fetch('/reference.bin')).arrayBuffer();
    const referenceHash = await hash(reference);
    self.postMessage({ type: 'ready', initialization_and_fixture_ms: performance.now() - loadStart, initialization_timer_note: 'Includes WASM init and fixture/reference loading and reference hash; excludes JS module import.', linear_memory_bytes: memory.buffer.byteLength, fixture_sha256: await hash(new TextEncoder().encode(fixture)), reference_sha256: referenceHash, cross_origin_isolated: self.crossOriginIsolated });
    let lastProof;
    for (currentRun = 1; currentRun <= options.repeat; currentRun++) {
      phases = [];
      const before = memory.buffer.byteLength;
      const started = performance.now();
      const result = prove_membership(fixture);
      const elapsed = performance.now() - started;
      const after = memory.buffer.byteLength;
      const proof = result.proof_bytes;
      const summary = JSON.parse(result.summary_json);
      const shape = JSON.parse(result.shape_json);
      result.free();
      const proofHash = await hash(proof);
      const upload = await fetch(`/proof/${currentRun}`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: proof });
      if (!upload.ok) throw new Error(`Local artifact save failed: ${upload.status}`);
      const record = { type: 'run', run: currentRun, instance_state: currentRun === 1 ? 'first proof in fresh worker/module' : 'warm repeat in same worker/module', elapsed_ms: elapsed, memory_before_bytes: before, memory_after_bytes: after, memory_after_result_free_bytes: memory.buffer.byteLength, proof_bytes: proof.byteLength, proof_sha256: proofHash, matches_native: proofHash === referenceHash, summary, shape, phases };
      self.postMessage(record);
      if (!record.matches_native) throw new Error('Browser proof differs from archived native envelope');
      lastProof = proof;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const provingHighWater = memory.buffer.byteLength;
    let checks = null;
    if (options.negativeTests) {
      currentRun = 0;
      const started = performance.now();
      checks = { report: JSON.parse(test_membership_mutations(lastProof)), elapsed_ms: performance.now() - started, linear_memory_bytes: memory.buffer.byteLength };
      self.postMessage({ type: 'checks', ...checks });
    }
    self.postMessage({ type: 'complete', checks, proving_linear_memory_high_water_bytes: provingHighWater, linear_memory_high_water_after_checks_bytes: memory.buffer.byteLength });
  } catch (e) {
    self.postMessage({ type: 'failure', run: currentRun, message: String(e?.message ?? e), stack: e?.stack ?? null, linear_memory_bytes: memory?.buffer.byteLength ?? null, phases });
  }
};
