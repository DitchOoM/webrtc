# docs/

Design notes that are too long for a KDoc comment and too specific for the repo-root docs.

- [`DC_SEMANTICS_INTEROP_DESIGN.md`](./DC_SEMANTICS_INTEROP_DESIGN.md) — how the interop lanes prove
  data-channel *semantics* (fragmentation, unordered, PR-SCTP, multiplexing, per-channel close) against
  foreign peers, rather than only that a session establishes.

The canonical docs are at the repo root: [`README.md`](../README.md) (quickstart + support matrix),
[`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DESIGN_PRINCIPLES.md`](../DESIGN_PRINCIPLES.md),
[`TESTING.md`](../TESTING.md), [`PERFORMANCE.md`](../PERFORMANCE.md) and
[`CHANGELOG.md`](../CHANGELOG.md). Per-module API reference ships as a Dokka javadoc jar with each
published artifact.
