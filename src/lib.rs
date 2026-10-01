//! Private contact journals, durable publication and block-preserving merges.
//!
//! Only committed Contacts exposes relations or sync bytes. Candidate enters the
//! same cwst transaction as wallet, MLS and outputs. Authority ports belong to
//! their existing owners; self-signed keys and UI values do not authorize events.
use ckmg::{Binding, KeyCertificate, Lineage, Purpose, Scope, Signature};
use cwst::{Change, Output, Store, backend::Backend};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EVENTS: usize = 1024;
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_EVIDENCE: usize = 4096;
const OWNER: &str = "ctcs";
const KEY: &[u8] = b"journal.v1";

/// Coarse failures carry no identifiers or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Error {
    Encoding,
    Limit,
    Scope,
    Authority,
    Transition,
    Conflict,
    Storage,
}

#[allow(async_fn_in_trait)]
pub trait DeviceAuthority {
    /// Independently authenticated CURRENT lineage, exact epoch and revocation.
    /// Refuse unavailable freshness. A self-signature alone is insufficient.
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, Error>;
}
#[allow(async_fn_in_trait)]
pub trait OutcomeAuthority {
    /// Waves verifies an accepted Answer for this exact binding/peer/conversation.
    /// Delivery ACKs or arbitrary signed statements cannot pass. Refuse missing
    /// accounting evidence. Historical committed outcomes need no fresh replay.
    async fn answered(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        evidence: &[u8],
    ) -> Result<(), Error>;
}

/// A request grants no authority. Fresh control always names its exact predecessor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Begin {
        conversation: [u8; 32],
    },
    Answered {
        conversation: [u8; 32],
        evidence: Vec<u8>,
    },
    Close,
    Block,
    Reopen {
        conversation: [u8; 32],
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum State {
    Unknown,
    Pending,
    Established,
    Closed,
    Blocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Relation {
    pub state: State,
    pub conversation: Option<[u8; 32]>,
    pub conflicted: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    version: u8,
    binding: Binding,
    peer: String,
    revision: u64,
    previous: Option<[u8; 32]>,
    action: Action,
}
/// Untrusted wire evidence, never a verified verdict.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvent {
    event: Event,
    certificate: KeyCertificate,
    signature: Signature,
}
/// Narrow device key purpose for this journal only.
pub fn purpose() -> Purpose {
    Purpose::new(Scope::Device, "ctcs.control", 1).expect("static valid purpose")
}
impl Event {
    /// Exact bytes to sign with ckmg::Keys::sign and the journal purpose handle.
    pub fn signing_bytes(&self, certificate: &KeyCertificate) -> Result<Vec<u8>, Error> {
        shape(self)?;
        if certificate.binding != self.binding || certificate.purpose != purpose() {
            return Err(Error::Scope);
        }
        encode(&("ctcs.control.v1", self, certificate))
    }
    pub fn signed(self, certificate: KeyCertificate, signature: Signature) -> SignedEvent {
        SignedEvent {
            event: self,
            certificate,
            signature,
        }
    }
}
impl SignedEvent {
    fn id(&self) -> Result<[u8; 32], Error> {
        Ok(*ckmg::hash(&encode(self)?).value())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    binding: Binding,
    events: Vec<SignedEvent>,
}

/// View of one committed, encrypted checkpoint. No background I/O or wall clock.
pub struct Contacts {
    journal: Journal,
    expected: u64,
    base: Option<Vec<u8>>,
}
/// A prepared state has no relation, sync or outgoing-message getters.
pub struct Candidate {
    journal: Journal,
    bytes: Vec<u8>,
    expected: u64,
    base: Option<Vec<u8>>,
}
impl Contacts {
    pub fn binding(&self) -> &Binding {
        &self.journal.binding
    }
    /// The Vault must select the binding's community store. An already accepted
    /// checkpoint survives credential rotation. Every NEW event needs fresh authority.
    pub fn load<B: Backend>(binding: Binding, store: &Store<B>) -> Result<Self, Error> {
        if !store.is_scope(binding.community()) {
            return Err(Error::Scope);
        }
        let expected = store.version().map_err(|_| Error::Storage)?;
        let base = store
            .read(OWNER, KEY)
            .expect("version checked the immutable store; owner and key are static")
            .map(<[u8]>::to_vec);
        let journal = match &base {
            Some(bytes) => decode(bytes)?,
            None => Journal {
                version: 1,
                binding: binding.clone(),
                events: vec![],
            },
        };
        validate(&journal, &binding)?;
        Ok(Self {
            journal,
            expected,
            base,
        })
    }
    pub fn relation(&self, peer: &str) -> Result<Relation, Error> {
        peer_binding(&self.journal.binding, peer)?;
        Ok(fold(&self.journal, peer)?.0)
    }
    /// Supply these peer IDs to Board's online never-match rules. Forum expiry is
    /// Board's job; the encrypted journal retains the controls across departure.
    pub fn blocking_rules(&self) -> Result<Vec<String>, Error> {
        let peers: BTreeSet<_> = self.journal.events.iter().map(|e| &e.event.peer).collect();
        let mut blocked = vec![];
        for peer in peers {
            if self.relation(peer)?.state == State::Blocked {
                blocked.push(peer.clone());
            }
        }
        Ok(blocked)
    }
    /// Private sync data, only inside encrypted owner-to-owner device channels or Records.
    pub fn export_journal(&self) -> Result<Vec<u8>, Error> {
        encode(&self.journal)
    }
    pub fn request(&self, peer: &str, action: Action) -> Result<Event, Error> {
        peer_binding(&self.journal.binding, peer)?;
        let (state, tip) = fold(&self.journal, peer)?;
        let (revision, previous) = match tip {
            Some(e) => (
                e.event.revision.checked_add(1).ok_or(Error::Limit)?,
                Some(e.id()?),
            ),
            None => (1, None),
        };
        let event = Event {
            version: 1,
            binding: self.journal.binding.clone(),
            peer: peer.into(),
            revision,
            previous,
            action,
        };
        shape(&event)?;
        transition(&self.journal, &event, state)?;
        Ok(event)
    }
    pub async fn prepare<D: DeviceAuthority, O: OutcomeAuthority>(
        &self,
        event: SignedEvent,
        devices: &mut D,
        outcomes: &mut O,
    ) -> Result<Candidate, Error> {
        self.merge(vec![event], devices, outcomes).await
    }
    /// Monotone union of authenticated events; a divergent revision preserves both
    /// branches and blocks, with no timestamp winner. Duplicate events are idempotent.
    pub async fn merge_journal<D: DeviceAuthority, O: OutcomeAuthority>(
        &self,
        bytes: &[u8],
        devices: &mut D,
        outcomes: &mut O,
    ) -> Result<Candidate, Error> {
        let incoming: Journal = decode(bytes)?;
        validate(&incoming, &self.journal.binding)?;
        self.merge(incoming.events, devices, outcomes).await
    }
    async fn merge<D: DeviceAuthority, O: OutcomeAuthority>(
        &self,
        incoming: Vec<SignedEvent>,
        devices: &mut D,
        outcomes: &mut O,
    ) -> Result<Candidate, Error> {
        let current = devices.current(&self.journal.binding).await?;
        if current.binding != self.journal.binding {
            return Err(Error::Scope);
        }
        let mut events = BTreeMap::new();
        for e in &self.journal.events {
            events.insert(e.id()?, e.clone());
        }
        for e in incoming {
            let id = e.id()?;
            if events.contains_key(&id) {
                continue;
            }
            shape(&e.event)?;
            if e.event.binding != self.journal.binding {
                return Err(Error::Scope);
            }
            e.certificate
                .verify(&current, &purpose())
                .map_err(|_| Error::Authority)?;
            ckmg::verify(
                &e.certificate.key,
                &e.event.signing_bytes(&e.certificate)?,
                &e.signature,
            )
            .map_err(|_| Error::Authority)?;
            if let Action::Answered {
                conversation,
                evidence,
            } = &e.event.action
            {
                outcomes
                    .answered(&self.journal.binding, &e.event.peer, conversation, evidence)
                    .await?;
            }
            events.insert(id, e);
            if events.len() > MAX_EVENTS {
                return Err(Error::Limit);
            }
        }
        let journal = Journal {
            version: 1,
            binding: self.journal.binding.clone(),
            events: events.into_values().collect(),
        };
        validate(&journal, &self.journal.binding)?;
        let bytes = encode(&journal)?;
        Ok(Candidate {
            journal,
            bytes,
            expected: self.expected,
            base: self.base.clone(),
        })
    }
}
impl Candidate {
    /// Save Contacts, companion owner state and pending outputs under one version
    /// fence. Publish/ACK only after success. On ambiguous failure reopen cwst and
    /// reconcile its operation and pending outputs; never regenerate the candidate.
    pub async fn commit<B: Backend>(
        self,
        store: &mut Store<B>,
        operation: [u8; 32],
        companions: &[Change<'_>],
        outputs: &[Output],
    ) -> Result<Contacts, Error> {
        if !store.is_scope(self.journal.binding.community()) {
            return Err(Error::Scope);
        }
        if store.read(OWNER, KEY).map_err(|_| Error::Storage)? != self.base.as_deref() {
            return Err(Error::Conflict);
        }
        let mut changes = vec![];
        for c in companions {
            let owner = match c {
                Change::Put { owner, .. } | Change::Delete { owner, .. } => owner,
            };
            if *owner == OWNER {
                return Err(Error::Scope);
            }
            changes.push(match c {
                Change::Put { owner, key, value } => Change::Put { owner, key, value },
                Change::Delete { owner, key } => Change::Delete { owner, key },
            });
        }
        changes.push(Change::Put {
            owner: OWNER,
            key: KEY,
            value: &self.bytes,
        });
        let expected = store
            .commit(self.expected, operation, &changes, outputs)
            .await
            .map_err(|_| Error::Storage)?;
        Ok(Contacts {
            journal: self.journal,
            expected,
            base: Some(self.bytes),
        })
    }
}
fn peer_binding(binding: &Binding, peer: &str) -> Result<(), Error> {
    Binding::new(binding.community(), peer).map_err(|_| Error::Scope)?;
    if peer == binding.member() {
        return Err(Error::Scope);
    }
    Ok(())
}
fn shape(e: &Event) -> Result<(), Error> {
    if e.version != 1 || e.revision == 0 {
        return Err(Error::Encoding);
    }
    peer_binding(&e.binding, &e.peer)?;
    match &e.action {
        Action::Begin { conversation }
        | Action::Reopen { conversation }
        | Action::Answered { conversation, .. } => {
            if *conversation == [0; 32] {
                return Err(Error::Encoding);
            }
        }
        Action::Close | Action::Block => {}
    }
    if let Action::Answered { evidence, .. } = &e.action
        && (evidence.is_empty() || evidence.len() > MAX_EVIDENCE)
    {
        return Err(Error::Limit);
    }
    Ok(())
}
fn validate(j: &Journal, binding: &Binding) -> Result<(), Error> {
    if j.version != 1 {
        return Err(Error::Encoding);
    }
    if j.binding != *binding {
        return Err(Error::Scope);
    }
    if j.events.len() > MAX_EVENTS {
        return Err(Error::Limit);
    }
    let mut ids = BTreeMap::new();
    let mut peers = BTreeSet::new();
    for e in &j.events {
        shape(&e.event)?;
        if e.event.binding != *binding {
            return Err(Error::Scope);
        }
        if ids.insert(e.id()?, e).is_some() {
            return Err(Error::Encoding);
        }
        peers.insert(&e.event.peer);
    }
    for e in &j.events {
        match e.event.previous {
            None => {
                if e.event.revision != 1 {
                    return Err(Error::Encoding);
                }
            }
            Some(id) => {
                let parent = ids.get(&id).ok_or(Error::Encoding)?;
                if parent.event.peer != e.event.peer
                    || parent.event.revision.checked_add(1) != Some(e.event.revision)
                {
                    return Err(Error::Encoding);
                }
            }
        }
    }
    for peer in peers {
        fold(j, peer)?;
    }
    Ok(())
}
fn fold<'a>(j: &'a Journal, peer: &str) -> Result<(Relation, Option<&'a SignedEvent>), Error> {
    let mut events: Vec<_> = j.events.iter().filter(|e| e.event.peer == peer).collect();
    events.sort_by_key(|e| e.event.revision);
    let mut state = Relation {
        state: State::Unknown,
        conversation: None,
        conflicted: false,
    };
    let mut tip = None;
    if events
        .windows(2)
        .any(|v| v[0].event.revision == v[1].event.revision)
    {
        return Ok((
            Relation {
                state: State::Blocked,
                conversation: None,
                conflicted: true,
            },
            None,
        ));
    }
    for e in events {
        state = transition(j, &e.event, state)?;
        tip = Some(e);
    }
    Ok((state, tip))
}
fn transition(j: &Journal, e: &Event, mut state: Relation) -> Result<Relation, Error> {
    if state.conflicted {
        return Err(Error::Conflict);
    }
    match &e.action {
        Action::Block => state.state = State::Blocked,
        Action::Close => {
            if state.state != State::Blocked {
                state.state = State::Closed;
            }
        }
        Action::Begin { conversation } => {
            if state.state != State::Unknown {
                return Err(Error::Transition);
            }
            state.state = State::Pending;
            state.conversation = Some(*conversation);
        }
        Action::Reopen { conversation } => {
            if !matches!(state.state, State::Closed | State::Blocked) {
                return Err(Error::Transition);
            }
            if j.events.iter().any(|old| old.event.peer == e.peer && old.event.revision < e.revision && matches!(&old.event.action, Action::Begin { conversation: c } | Action::Reopen { conversation: c } if c == conversation)) { return Err(Error::Transition); }
            state.state = State::Pending;
            state.conversation = Some(*conversation);
        }
        Action::Answered { conversation, .. } => {
            if !matches!(state.state, State::Pending | State::Established)
                || state.conversation != Some(*conversation)
            {
                return Err(Error::Transition);
            }
            state.state = State::Established;
        }
    }
    Ok(state)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).expect("journal uses only infallible JSON fields");
    bounded(bytes)
}
fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Encoding)
}
