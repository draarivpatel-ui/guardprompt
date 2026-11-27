# Contributing to guardprompt

Thank you for improving deterministic prompt-security engineering.

## Ground rules

- Keep runtime dependencies at zero.
- Keep development dependencies at zero unless a maintainer explicitly approves an exception.
- Support Node.js 18, 20, 22, and 24.
- Preserve ESM and CommonJS behavior from the same `src/index.mjs` source of truth.
- Update `types/index.d.ts` for every public API change.
- Add adversarial and benign regression tests for every scanner change.
- Use only synthetic credentials, tokens, canaries, and personal data in fixtures.
- Do not commit real credentials, real personal data, local home paths, or private hostnames.
- Keep rule IDs stable within a major version.

## Local verification

```sh
npm test
npm run check:cjs
npm run smoke
node scripts/cli-smoke.mjs
npm run check:repo
npm pack --dry-run
```

The test suite uses only `node --test`. Generated parameterized cases count as individual tests. A change that alters scanner behavior should add both positive and negative cases.

## Code review checklist

- Input, decoded payload, recursion, candidate, and finding limits remain bounded.
- New regular expressions are simple and cannot backtrack through nested quantifiers.
- Evidence is clipped and does not reproduce secret values.
- Redaction positions refer to the canonical string being redacted.
- Findings include stable IDs, severity, CWE, and OWASP metadata.
- CJS output is regenerated with `npm run build:cjs`.
- Type declarations match runtime behavior.

## Commit style

Use concise commits that explain why the change is needed. Do not add co-author trailers. Keep generated files reproducible.

## Security reports

Do not use the public issue tracker for sensitive vulnerability details. Follow [SECURITY.md](SECURITY.md).
