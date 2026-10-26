# ctcs agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p ctcs` — lib `0`, `contacts` `12`
  passed, exit 0
- `~/agents/scratch/cbuild <lane> fmt -p ctcs -- --check` — must be clean
- Full gate (clippy `--locked`, native + actual wasm vectors, 100% reachable
  line and branch coverage, dependency policy) runs in CI: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Reopen needs an explicit authenticated fresh event; an old Answer never
  establishes the new conversation
  -> `tests/contacts.rs::lifecycle_requires_fresh_reopen_and_verified_answer`
- Concurrent stale reopen vs block converges to Blocked in both orders; a
  stale device never undoes a concurrent block
  -> `tests/contacts.rs::concurrent_stale_reopen_and_block_converge_to_blocked_in_both_orders`
- Tampered/wrong-scope/revoked/unavailable device or outcome proofs refuse
  -> `tests/contacts.rs::tamper_wrong_scope_revocation_and_unavailable_proofs_refuse`
- Competing writers fence on the exact prior record before any output
  -> `tests/contacts.rs::combined_checkpoint_fences_competing_writers_before_outputs`
- Bounded union refuses overload without dropping existing blocks
  -> `tests/contacts.rs::bounded_union_refuses_without_discarding_existing_blocks`
- Every publication rechecks current device and outcome authority
  -> `tests/contacts.rs::publication_rechecks_device_and_outcome_authority`
- Voucher admission establishes once and never undoes a block
  -> `tests/contacts.rs::voucher_admission_establishes_once_and_never_undoes_a_block`
- Never a server contact list; no own crypto — custody and signatures are ckmg's
  -> `tests/contacts.rs::empty_store_scope_and_changed_checkpoint_refuse`,
  `foreign_predecessors_and_reused_conversations_refuse`

Pointers: `src/lib.rs`, `docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; no GPL/AGPL-only deps.
