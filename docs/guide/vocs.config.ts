import { defineConfig } from 'vocs/config'

export default defineConfig({
  title: 'Templar',
  description: 'The architecture of private, note-based transfers on Starknet.',
  titleTemplate: '%s · Templar',
  renderStrategy: 'full-static',
  accentColor: 'light-dark(#0f6555, #83d7bd)',
  iconUrl: '/mark.svg',
  mcp: {
    enabled: true,
  },
  topNav: [
    { text: 'Architecture', link: '/' },
    { text: 'Implementation status', link: '/status' },
  ],
  sidebar: [
    { text: 'Overview', link: '/' },
    { text: 'Starknet Privacy comparison', link: '/comparison' },
    {
      text: 'Architecture',
      items: [
        { text: 'System & boundaries', link: '/architecture/system' },
        { text: 'Notes & ownership', link: '/architecture/notes' },
        { text: 'Receiving & recovery', link: '/architecture/receiving' },
        { text: 'Pool state', link: '/architecture/state' },
        { text: 'Transaction lifecycle', link: '/architecture/lifecycle' },
        { text: 'Proofs & verification', link: '/architecture/proofs' },
        { text: 'Open notes', link: '/architecture/open-notes' },
        { text: 'Policy notes', link: '/architecture/policy-notes' },
        { text: 'Privacy & trust', link: '/architecture/privacy' },
      ],
    },
    {
      text: 'Reference',
      items: [
        { text: 'Implementation status', link: '/status' },
        { text: 'Code map', link: '/code-map' },
        { text: 'Glossary', link: '/glossary' },
      ],
    },
  ],
})
