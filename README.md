# ctcs — Contacts

Community-local relationship state for the member Inbox.

## Scope

Own contacts, closure, explicit fresh reopening, blocks, and the private control
journal. Supply block rules to Board. Persist through Vault; replicate sealed
records through Records. Peer presence is transient and stays off the forum.

Contacts never owns balances, MLS membership, delivery acknowledgements, identity
issuance, cryptographic primitives, or a server contact list. A stale merge must
never remove a block or reopen a closed contact.

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
