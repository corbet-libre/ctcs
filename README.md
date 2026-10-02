# ctcs — Contacts

Community-local relationship state for the member Inbox.

## Scope

### Purpose

ctcs keeps the member's relation to every other member of the community — contacts, closure, reopening and blocks — as a signed, synced private journal.

### Owns

- Relationship states and the signed control journal, merged conservatively so blocks are preserved.
- Blocks stored on the member's devices and supplied to Board as never-match rules while online.
- Transient peer reachability of contacts, kept off cfrm.

### Never

- No balances, MLS roster, or delivery acknowledgements.
- No contact graph on cfrm.
- No generic last-write-wins merge that could remove a block.

### States

Unknown → Pending → Established → Closed; any relation may become Blocked; reopening needs an explicit authenticated fresh event.

### Test obligations

- A block at once stops key release, waves and messages and appears in online never-match rules; the forum forgets the rules on departure and member storage keeps them.
- A concurrent stale unblock or reopen is refused; idempotent receipts do not reopen a closed contact; the same identity bytes in another community are a separate relation.
- Full line and branch coverage with real round trips and injected delay, duplication, loss, cancellation, clock regression, corruption and storage conflicts; atomic publication with reconciliation of unknown outcomes; per-community isolation; bounded inputs with errors omitting identifiers and secrets; maintained third-party cryptography only.

## Implementation and dependencies

The journal implements versioned signed controls, monotone synchronization,
block-preserving conflicts, fresh reopening and combined cwst checkpoint publication.
Production device authority and Waves accounting acceptance remain integration
dependencies. CI and review, rather than configuration, establish acceptance.
The contact rules derive from cmsg's directional journal; its legacy identity
and accounting ownership are not part of this library.

Use ckmg on main for purpose certificates and signatures, serde for bounded
versioned records, and the standard collections for deterministic journal union.
The standard append-only event set is sufficient for the domain merge.
[Generic last-write-wins registers](https://docs.rs/crdts/latest/crdts/) cannot
implement the block-preserving conflict rule. Keys supplies maintained crypto;
cwst supplies encrypted storage and atomic writes.

See [the contract](docs/CONTRACT.md) and [licensing](LICENSE.md).
