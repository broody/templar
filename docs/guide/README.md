# Templar developer guide

A standalone Vocs 2 site explaining Templar's architecture. Published content is
in `src/pages/`; reusable presentation components are in `src/components/`.
The guide contains no design-decision history, how-to tutorials, or integration
instructions. Implementation maturity and benchmark qualifications live on the
status page rather than being mixed into the core narrative.

## Maintain the site

With Node.js 22.22.1 or a compatible newer runtime, from this directory:

```bash
npm ci
npm run dev
```

Validate configuration/components and generate the fully static site:

```bash
npm run typecheck
npm run build
npm run preview
```

Vocs checks internal links during the build and provides local search, an
outline, mobile navigation, and a theme toggle. The package lock pins the
dependency tree. No chain access, proving tools, or wallet configuration is
needed to build the documentation.

Two dependency overrides select patched `toml` and `undici` releases for
Vocs' transitive dependencies. Review these when upgrading Vocs.

Keep the guide focused on the accepted push-payment architecture. Describe
receiving as a native capability, without invoice history or alternate invoice
flows. Check keys, delivery, statement binding, and recovery against
`bench/controlled-push-e2e/` and `docs/push-payment-spec.md`; `packages/pool/` is not yet
integrated with this format. Resource
figures must retain their measurement scope and date. Do not copy private
witnesses, local account files, signed requests, or runtime directories into
the site's public assets.

No deployment URL is assumed. Set Vocs `baseUrl` (and `basePath` if needed)
when an actual hosting target is selected. Framework reference:
https://vocs.dev/reference/site-config
