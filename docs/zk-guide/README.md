# ZK Fundamentals

A standalone Vocs site teaching zero-knowledge and STARK concepts from first
principles, grounded in Starknet's actual stack (M31 circle STARKs, S-two,
felt252 limbs, PROOF1) and ending on proof privacy — what a proof artifact
leaks, how hiding is built, and how a compact private client proof can be
wrapped by a server for Starknet compatibility.

Parallel to the product-oriented guide in `../guide` (architecture of the
payment system); this site is conceptual and self-contained.

## Run

```bash
cd docs/zk-guide
npm install        # (deps are shared with ../guide's package versions)
npm run dev        # http://localhost:5173
npm run build
```

## Structure

- `src/pages/` — MDX curriculum (foundations → proof systems → STARK anatomy →
  Starknet → privacy), with runnable Python checks on every page
- `vocs.config.ts` — sidebar and site config
