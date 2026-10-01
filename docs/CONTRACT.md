# Contacts contract

`Contacts` is a read-only view of one committed `cwst::Store` checkpoint, scoped
by `ckmg::Binding` (community and externally verified pseudonym). It owns the
relationship journal; Vault owns encrypted persistence, Keys owns cryptography,
Waves owns accepted outcome evidence, and Records owns replication.

## States and events

Unknown → Pending after Begin. Only an accepted Answer for that conversation
establishes it. Close enters Closed. Block enters Blocked from every state.
Close never clears a Block. Explicit authenticated Reopen needs a new conversation
identifier and enters Pending. Old Answers cannot establish the new conversation.

Each peer has versioned, signed, predecessor-linked controls. A control binds its
community, owner, peer, revision, predecessor, action and exact purpose certificate.
Signing uses the opaque Keys handle for Device / ctcs.control / generation 1.
No root or device secret is exported. Repeated synchronization is idempotent.

Merge is an append-only set union sorted by event digest. Prefix extensions retain
all earlier controls. Divergent controls at one revision preserve both branches
and fence the relation as Blocked, regardless of arrival order or timestamps.
A stale device cannot undo a concurrent Block by submitting its own Reopen.
There is no automatic conflict resolution or last-write-wins rule. A conflicted
journal currently refuses further controls; a future explicit reconciliation
ceremony needs its own authenticated contract before it can be enabled.

`blocking_rules` gives Board only the currently blocked peer IDs for online
never-match rules. Board owns forum expiry/departure; the private encrypted journal
survives departure and restart. A closed relation retains its prior conversation
reference as history, without permitting more messages or applying old outcomes.

## Trusted capabilities

`DeviceAuthority::current` must supply independently authenticated, fresh lineage
for the exact binding, including current epoch and revoked devices. Contacts then
uses Keys to verify the certificate and exact event signature. A self-signed
lineage is never sufficient authority. The production device-attestation adapter
remains an integration dependency; tests use a separately signed fixture authority.

`OutcomeAuthority::answered` is the Waves-owned acceptance seam for the exact
community, owner, peer and conversation. It must verify required accounting and
peer evidence, never a delivery ACK or merely a signed arbitrary statement.
Missing accounting proofs refuse. Test fixture receipts exercise delegation and
signature rejection; they do not establish real Waves/accounting acceptance.

Already accepted records are read from authenticated Vault storage without
requiring their historical signers still to be active. Newly merged events need
current authority. Rotation cannot erase an accepted block. An entirely rolled
back device store cannot discover unknown later controls by itself.

## Atomic publication

`request` returns an unsigned request. `Event::signed` only packages untrusted
evidence. `prepare` and `merge_journal` produce a private Candidate with no relation,
sync or outgoing-message getters. `Candidate::commit` compares the exact prior
contact record and cwst publication version, then writes Contacts, companion
owner changes, and pending outputs in ONE encrypted transaction. A companion
cannot overwrite the ctcs owner namespace. Only success returns the new view.

On conflict, failure or cancellation: do not publish, ACK, reuse a stale view or
regenerate effects. Reopen the Vault checkpoint, inspect its operation identifier
and pending outputs, and replay the exact committed output if one exists. The
store's actual disk/IndexedDB durability is supplied by cwst; its Memory adapter
is ephemeral and tests do not label it disk persistence.

Loading and candidate commit both require cwst's authenticated store scope to
match the journal community, including for a newly created empty store.

## Bounds and reuse

Format version 1 only; strict Serde fields; 1 MiB encoded input before parsing;
1024 events; 4096 bytes per outcome evidence. Exhaustion refuses additions rather
than dropping old blocks. Unknown versions, duplicate event IDs, missing parents,
foreign peer predecessors, malformed scope and invalid signatures refuse.
Serialization uses fixed structs of JSON-compatible fields; allocation failure
is a process failure, not a fabricated successful checkpoint.

The extraction preserves cmsg's `DirectionalContact::merge_chain` prefix and
conflict safety, `merge_contact_sync` monotone closure, and
`BrowserInbox::persist_candidate` combined publication fence. It replaces the
mixed inbox/accounting state and legacy root/issuer identity with the existing
Keys and Vault owners. No security primitive, ledger, MLS roster, server contact
list or domain ACK meaning is implemented here.

Native and actual browser Wasm run the same crypto/state/checkpoint vectors.
CI separately gates every reachable production line and branch at 100%; integration
test fixtures are excluded from the production coverage denominator. Production
source has no coverage exclusions. Real native/IndexedDB durability vectors stay
with cwst, and composed failure/restore tests remain integration obligations.

`load` first checks the immutable store's version, which refuses a locked store.
Its following read uses static valid owner/key identifiers and cannot fail:
cwst performs no backend I/O in either getter, and this shared borrow cannot
change the store's open state. The read asserts that upstream contract rather
than retaining an unreachable second locked-store error mapping.
