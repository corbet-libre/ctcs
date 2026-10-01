# ctcs — Contacts

Community-local relationship state for the member Inbox.

## Scope

Own contacts, closure, explicit fresh reopening, blocks, and the private control
journal. Supply block rules to Board. Persist through Vault; replicate sealed
records through Records. Peer presence is transient and stays off the forum.

Contacts never owns balances, MLS membership, delivery acknowledgements, identity
issuance, cryptographic primitives, or a server contact list. A stale merge must
never remove a block or reopen a closed contact.

**States.** Unknown → Pending → Established → Closed; any relation may become
Blocked. Reopening requires an explicit authenticated fresh event. Concurrent
conflicting control history stays conservatively blocked.

**Ports.** Signed control preparation and journal merge, relation and blocking-rule
views, current device authority, verified Waves outcomes and encrypted Store.
Transient peer reachability remains a separate proposed mechanism; the current
journal does not manufacture presence from DHT persistence or forum rosters.

**Invariants and tests.** A block must stop key disclosure, waves and messages and
feed Board's online never-match rules. The forum forgets those transient rules on
departure; member storage keeps the block. Native and actual Wasm tests cover
cross-community isolation, stale/concurrent reopen, receipt replay, and atomic
publication with fresh device/outcome checks. Network restore and presence require
the real owner adapters. Journal record packing must compress and pad before
Records encrypts; a server never retains a contact graph.

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
