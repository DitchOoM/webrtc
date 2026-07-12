# docs/

Placeholder for the Docusaurus documentation site (wired up alongside W6/W7, mirroring the
buffer/socket setup). The `copyDokkaToDocusaurus` Gradle task generates per-module API docs from
Dokka into `docs/static/api/`; the site scaffolding (`package.json`, Docusaurus config, a `docs.yaml`
CI lane) lands when there is a public API worth documenting.

Until then, the canonical docs are the repo-root markdown: `README.md`, `RFC_KMP_WEBRTC.md`,
`EXECUTION_PLAN.md`, `DESIGN_PRINCIPLES.md`, `CLAUDE.md`.
