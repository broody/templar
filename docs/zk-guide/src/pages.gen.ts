// deno-fmt-ignore-file
// biome-ignore format: generated types do not need formatting
// prettier-ignore
import type { PathsForPages } from 'waku/router'

// prettier-ignore
type Page =
  | { path: '/foundations/circles'; render: 'static' }
  | { path: '/foundations/fields'; render: 'static' }
  | { path: '/foundations/polynomials'; render: 'static' }
  | { path: '/glossary'; render: 'static' }
  | { path: '/'; render: 'static' }
  | { path: '/privacy/blinding'; render: 'static' }
  | { path: '/privacy/what-zk-means'; render: 'static' }
  | { path: '/proofs/commitments'; render: 'static' }
  | { path: '/proofs/snark-vs-stark'; render: 'static' }
  | { path: '/proofs/what-is-a-proof-system'; render: 'static' }
  | { path: '/starknet/cairo-and-s-two'; render: 'static' }
  | { path: '/starknet/how-starknet-proves'; render: 'static' }
  | { path: '/starks/fri'; render: 'static' }
  | { path: '/starks/lookups'; render: 'static' }
  | { path: '/starks/openings'; render: 'static' }
  | { path: '/starks/trace-and-air'; render: 'static' }

// prettier-ignore
declare module 'waku/router' {
  interface RouteConfig {
    paths: PathsForPages<Page>
  }
  interface CreatePagesConfig {
    pages: Page
  }
}
