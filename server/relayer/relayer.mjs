#!/usr/bin/env node
// templar-relayer CONFIG_JSON: submits every R0 V5 spend the paired prover server proves, and
// answers each job with the transaction hash or a refusal (docs/account-bound-note-spec.md §7.3,
// §7.4). The logic is `@templar/sdk/relayer`; this file wires the configuration and signals.
import { readFileSync } from 'node:fs';

import { createRelayer } from '../../sdk/ts/dist/relayer.js';

const path = process.argv[2];
if (!path) {
  console.error('usage: relayer.mjs CONFIG_JSON');
  process.exit(2);
}
const config = JSON.parse(readFileSync(path, 'utf8'));
const log = (line) => console.log(`${new Date().toISOString()} ${line}`);
const relayer = await createRelayer(config, log);
const stop = new AbortController();
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => stop.abort());
log(`relaying for pool ${config.pool.pool} through ${config.handoff.url}`);
await relayer.run({ intervalMs: config.intervalMs ?? 2000, signal: stop.signal });
log('stopped');
