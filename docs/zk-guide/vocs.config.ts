import { defineConfig } from 'vocs/config'

export default defineConfig({
  title: 'ZK Fundamentals',
  description: 'Zero-knowledge and STARK concepts from first principles, in the context of Starknet.',
  titleTemplate: '%s · ZK Fundamentals',
  renderStrategy: 'full-static',
  accentColor: 'light-dark(#4338ca, #a5b4fc)',
  iconUrl: '/mark.svg',
  topNav: [{ text: 'Guide', link: '/' }],
  sidebar: [
    { text: 'Overview', link: '/' },
    {
      text: 'Foundations',
      items: [
        { text: 'Finite fields', link: '/foundations/fields' },
        { text: 'Polynomials', link: '/foundations/polynomials' },
        { text: 'The circle group', link: '/foundations/circles' },
      ],
    },
    {
      text: 'Proof systems',
      items: [
        { text: 'What a proof system is', link: '/proofs/what-is-a-proof-system' },
        { text: 'Commitments', link: '/proofs/commitments' },
        { text: 'SNARK vs STARK', link: '/proofs/snark-vs-stark' },
      ],
    },
    {
      text: 'STARK anatomy',
      items: [
        { text: 'Trace and AIR', link: '/starks/trace-and-air' },
        { text: 'FRI', link: '/starks/fri' },
        { text: 'What the verifier sees', link: '/starks/openings' },
        { text: 'Lookups (LogUp)', link: '/starks/lookups' },
      ],
    },
    {
      text: 'Starknet',
      items: [
        { text: 'How Starknet proves', link: '/starknet/how-starknet-proves' },
        { text: 'Cairo and S-two', link: '/starknet/cairo-and-s-two' },
      ],
    },
    {
      text: 'Privacy',
      items: [
        { text: 'What zero-knowledge really means', link: '/privacy/what-zk-means' },
        { text: 'Blinding in practice', link: '/privacy/blinding' },
      ],
    },
    {
      text: 'Reference',
      items: [{ text: 'Glossary', link: '/glossary' }],
    },
  ],
})
