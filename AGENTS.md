# Agent instructions

Write comments and documentation in English. Keep this leaf within README Scope.
Use maintained dependencies; no own security primitives or identity verifier.
Key custody and signature verification belong to ckmg. Only authenticated current
capabilities authorize events. Preserve block/close monotonicity and checkpoint
before publication. Never store contacts on a server.

No workstation Cargo, including fmt or metadata. Crow (`ci-job`) runs
native tests and actual wasm vectors, Clippy, formatting, dependency policy,
and 100% reachable line and branch coverage. Keep first-party git dependencies
on main with one revision per crate in Cargo.lock. Document justified exclusions;
never lower gates for missing tests. Expensive load and churn use the CI scheduler.

Stage explicit paths, use small plain-English commits, pull --rebase before
pushing main. No force pushes, registry publication, AI attribution or secrets.
LGPL-3.0-only WITH LGPL-3.0-linking-exception; no GPL/AGPL-only dependencies.

Current working rules (2026-10-12): the live line is branch v01 and CI is Crow through `ci-job` (never GitHub Actions); first-party dependencies follow v01. Punishment and the public record belong to the MVP and the alpha (Julian 2026-10-02 and 2026-10-11); they gate release as the Waves proposal defines.
