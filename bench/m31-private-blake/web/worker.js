// This loopback-only harness uses a synthetic fixture. No witness is uploaded.
self.onmessage = async ({ data: { repeat } }) => {
  let memory;
  try {
    const { default: init, prove_membership, verify_membership } = await import('/pkg/membership.js');
    const exports = await init();
    memory = exports.memory;
    const publicJson = await (await fetch('/public.json')).text();
    const privateJson = await (await fetch('/private.json')).text();
    const nativeProof = new Uint8Array(await (await fetch('/native.bin')).arrayBuffer());
    verify_membership(publicJson, nativeProof);
    self.postMessage({ type: 'ready', native_proof_verified: true, linear_memory_bytes: memory.buffer.byteLength });
    const hashes = new Set();
    for (let run = 1; run <= repeat; run++) {
      const before = memory.buffer.byteLength;
      const start = performance.now();
      const proof = prove_membership(publicJson, privateJson);
      const proveMs = performance.now() - start;
      const afterProve = memory.buffer.byteLength;
      const verifyStart = performance.now();
      verify_membership(publicJson, proof);
      const verifyMs = performance.now() - verifyStart;
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', proof)), b => b.toString(16).padStart(2, '0')).join('');
      if (hashes.has(hash)) throw new Error('Repeated proof randomness');
      hashes.add(hash);
      let rejections = 0;
      const reject = (pub, bytes) => {
        try { verify_membership(pub, bytes); } catch { rejections++; return; }
        throw new Error('Negative proof accepted');
      };
      const changed = JSON.parse(publicJson);
      changed.root[0] = (changed.root[0] + 1) % 2147483647;
      reject(JSON.stringify(changed), proof);
      const bad = proof.slice(); bad[Math.floor(bad.length / 2)] ^= 1;
      reject(publicJson, bad);
      reject(publicJson, proof.slice(0, -1));
      const trailing = new Uint8Array(proof.length + 1); trailing.set(proof);
      reject(publicJson, trailing);
      const saved = await fetch(`/proof/${run}`, { method: 'POST', body: proof });
      if (!saved.ok) throw new Error('Local proof save failed');
      self.postMessage({ type: 'run', run, prove_ms: proveMs, verify_ms: verifyMs,
        memory_before_bytes: before, memory_after_prove_bytes: afterProve,
        memory_after_checks_bytes: memory.buffer.byteLength, proof_bytes: proof.length,
        proof_sha256: hash, accepted: true, negative_rejections: rejections });
    }
    self.postMessage({ type: 'complete', linear_memory_high_water_bytes: memory.buffer.byteLength });
  } catch (e) {
    self.postMessage({ type: 'failure', message: String(e?.message ?? e), linear_memory_bytes: memory?.buffer.byteLength ?? null });
  }
};
