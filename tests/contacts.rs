//! Real custody, signatures and encrypted checkpoint vectors, on native and Wasm.
//! Fixture authority is explicitly not production device attestation or Waves proof.
#[path = "support/independent_peer_convergence.rs"]
mod independent_peer_convergence;
mod support;
use ckmg::{Binding, KeyHandle, Lineage};
use ctcs::{Action, Contacts, DeviceAuthority, Error, Event, OutcomeAuthority, SignedEvent, State};
use cwst::{Change, Output, Store, backend::Memory};
use ed25519_dalek::{Signer, SigningKey};
use futures::executor::block_on;
use support::{Guard, Machine, Time, create, machine, prf};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

struct Devices {
    guard: Guard,
    unavailable: bool,
    wrong: Option<Lineage>,
}
impl DeviceAuthority for Devices {
    async fn current(&mut self, b: &Binding) -> Result<Lineage, Error> {
        if self.unavailable {
            return Err(Error::Authority);
        }
        if let Some(lineage) = &self.wrong {
            return Ok(lineage.clone());
        }
        self.guard
            .0
            .borrow()
            .get(b.community())
            .filter(|l| &l.binding == b)
            .cloned()
            .ok_or(Error::Authority)
    }
}
// A signed test-only receipt tests Contacts' delegation boundary. It is not an
// accounting proof and cannot be installed as the production Waves adapter.
struct Outcomes;
fn receipt_bytes(b: &Binding, peer: &str, conversation: &[u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&("fixture.answer", b, peer, conversation)).unwrap()
}
fn answer(b: &Binding, peer: &str, conversation: [u8; 32]) -> Action {
    Action::Answered {
        conversation,
        evidence: SigningKey::from_bytes(&[71; 32])
            .sign(&receipt_bytes(b, peer, &conversation))
            .to_bytes()
            .to_vec(),
    }
}
impl OutcomeAuthority for Outcomes {
    async fn answered(
        &mut self,
        b: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        evidence: &[u8],
    ) -> Result<(), Error> {
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
            &receipt_bytes(b, peer, conversation),
            &evidence.try_into().map_err(|_| Error::Authority)?,
        )
        .map_err(|_| Error::Authority)
    }
}
struct Fixture {
    keys: Machine,
    handle: KeyHandle,
    devices: Devices,
    binding: Binding,
}
impl Fixture {
    async fn new(scope: &str) -> Self {
        let guard = Guard::default();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, 1);
        let binding = Binding::new(scope, "owner").unwrap();
        create(&mut keys, &guard, &prf(1), &binding).await;
        let handle = keys.key(ctcs::purpose()).await.unwrap();
        Self {
            keys,
            handle,
            devices: Devices {
                guard,
                unavailable: false,
                wrong: None,
            },
            binding,
        }
    }
    async fn store(&self) -> (Memory, Store<Memory>) {
        let backend = Memory::new();
        let cipher = ckmg::passkey::store_cipher(&prf(1), self.binding.community()).unwrap();
        let store = Store::create(backend.clone(), &cipher, self.binding.community())
            .await
            .unwrap();
        (backend, store)
    }
    async fn sign(&mut self, event: Event) -> SignedEvent {
        let cert = self.handle.certificate().clone();
        let signature = self
            .keys
            .sign(&self.handle, &event.signing_bytes(&cert).unwrap())
            .await
            .unwrap();
        event.signed(cert, signature)
    }
    async fn apply(
        &mut self,
        contacts: &Contacts,
        store: &mut Store<Memory>,
        peer: &str,
        action: Action,
        operation: u8,
    ) -> Contacts {
        let event = self.sign(contacts.request(peer, action).unwrap()).await;
        contacts
            .prepare(event, &mut self.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut self.devices, &mut Outcomes),
                store,
                [operation; 32],
                &[],
                &[],
            )
            .await
            .unwrap()
    }
}
fn mutated<T: serde::Serialize + serde::de::DeserializeOwned>(
    value: &T,
    edit: impl FnOnce(&mut serde_json::Value),
) -> T {
    let mut json = serde_json::to_value(value).unwrap();
    edit(&mut json);
    serde_json::from_value(json).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lifecycle_requires_fresh_reopen_and_verified_answer() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (backend, mut store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        assert_eq!(c.relation("peer").unwrap().state, State::Unknown);
        assert!(c.binding() == &f.binding);
        assert_eq!(c.version(), store.version().unwrap());
        for peer in ["", "owner"] {
            assert!(c.relation(peer).is_err());
            assert!(c.request(peer, Action::Block).is_err());
        }
        assert!(
            c.request(
                "peer",
                Action::Reopen {
                    conversation: [1; 32]
                }
            )
            .is_err()
        );
        assert!(
            c.request("peer", answer(&f.binding, "peer", [1; 32]))
                .is_err()
        );
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Begin {
                    conversation: [1; 32],
                },
                1,
            )
            .await;
        assert_eq!(c.relation("peer").unwrap().state, State::Pending);
        assert!(
            c.request(
                "peer",
                Action::Begin {
                    conversation: [2; 32]
                }
            )
            .is_err()
        );
        assert!(
            c.request("peer", answer(&f.binding, "peer", [2; 32]))
                .is_err()
        );
        let action = answer(&f.binding, "peer", [1; 32]);
        let c = f.apply(&c, &mut store, "peer", action, 2).await;
        assert_eq!(c.relation("peer").unwrap().state, State::Established);
        let duplicate = c.export_journal().unwrap();
        let c = c
            .merge_journal(&duplicate, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [3; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        let action = answer(&f.binding, "peer", [1; 32]);
        let c = f.apply(&c, &mut store, "peer", action, 4).await;
        let c = f.apply(&c, &mut store, "peer", Action::Close, 5).await;
        assert_eq!(c.relation("peer").unwrap().state, State::Closed);
        assert!(
            c.request("peer", answer(&f.binding, "peer", [1; 32]))
                .is_err()
        );
        assert!(
            c.request(
                "peer",
                Action::Reopen {
                    conversation: [1; 32]
                }
            )
            .is_err()
        );
        let c = c
            .merge_journal(&duplicate, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [6; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(c.relation("peer").unwrap().state, State::Closed);
        let c = f.apply(&c, &mut store, "peer", Action::Block, 7).await;
        let c = f.apply(&c, &mut store, "peer", Action::Close, 8).await;
        assert_eq!(c.relation("peer").unwrap().state, State::Blocked);
        assert_eq!(c.blocking_rules().unwrap(), vec!["peer"]);
        store.lock();
        let cipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let mut store = Store::open(backend, &cipher, "alpha").await.unwrap();
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        assert_eq!(c.relation("peer").unwrap().state, State::Blocked);
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Reopen {
                    conversation: [2; 32],
                },
                9,
            )
            .await;
        assert_eq!(c.relation("peer").unwrap().state, State::Pending);
        assert!(c.blocking_rules().unwrap().is_empty());
        assert!(
            c.request("peer", answer(&f.binding, "peer", [1; 32]))
                .is_err()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn concurrent_stale_reopen_and_block_converge_to_blocked_in_both_orders() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_, mut left) = f.store().await;
        let (_, mut right) = f.store().await;
        let a = Contacts::load(f.binding.clone(), &left).unwrap();
        let a = f.apply(&a, &mut left, "peer", Action::Close, 1).await;
        let b = Contacts::load(f.binding.clone(), &right).unwrap();
        let b = b
            .merge_journal(&a.export_journal().unwrap(), &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut right,
                [2; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        let a = f.apply(&a, &mut left, "peer", Action::Block, 3).await;
        let b = f
            .apply(
                &b,
                &mut right,
                "peer",
                Action::Reopen {
                    conversation: [7; 32],
                },
                4,
            )
            .await;
        let aw = a.export_journal().unwrap();
        let bw = b.export_journal().unwrap();
        let a = a
            .merge_journal(&bw, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut left,
                [5; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        let b = b
            .merge_journal(&aw, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut right,
                [6; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(a.export_journal().unwrap(), b.export_journal().unwrap());
        assert!(a.relation("peer").unwrap().conflicted);
        assert_eq!(a.relation("peer").unwrap().state, State::Blocked);
        assert_eq!(
            a.request(
                "peer",
                Action::Reopen {
                    conversation: [8; 32]
                }
            )
            .err(),
            Some(Error::Conflict)
        );
        let a = a
            .merge_journal(&bw, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut left,
                [7; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(a.export_journal().unwrap(), b.export_journal().unwrap());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn tamper_wrong_scope_revocation_and_unavailable_proofs_refuse() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_, mut store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        let e = f.sign(c.request("peer", Action::Block).unwrap()).await;
        let altered = mutated(&e, |j| j["event"]["peer"] = "other".into());
        assert_eq!(
            c.prepare(altered, &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Authority)
        );
        let other = Fixture::new("beta").await;
        let (_, otherstore) = other.store().await;
        let o = Contacts::load(other.binding.clone(), &otherstore).unwrap();
        assert_eq!(
            c.merge_journal(&o.export_journal().unwrap(), &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Scope)
        );
        f.devices.unavailable = true;
        assert_eq!(
            c.prepare(e.clone(), &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Authority)
        );
        f.devices.unavailable = false;
        f.devices.wrong = Some(other.devices.guard.0.borrow()["beta"].clone());
        assert_eq!(
            c.prepare(e.clone(), &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Scope)
        );
        f.devices.wrong = None;
        let root = f.devices.guard.0.borrow()["alpha"].clone();
        f.devices
            .guard
            .0
            .borrow_mut()
            .get_mut("alpha")
            .unwrap()
            .epoch += 1;
        assert_eq!(
            c.prepare(e, &mut f.devices, &mut Outcomes).await.err(),
            Some(Error::Authority)
        );
        f.devices.guard.0.borrow_mut().insert("alpha".into(), root);
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Begin {
                    conversation: [1; 32],
                },
                1,
            )
            .await;
        let event = c
            .request(
                "peer",
                Action::Answered {
                    conversation: [1; 32],
                    evidence: vec![9; 64],
                },
            )
            .unwrap();
        let signed = f.sign(event).await;
        assert_eq!(
            c.prepare(signed, &mut f.devices, &mut Outcomes).await.err(),
            Some(Error::Authority)
        );
        assert_eq!(c.relation("peer").unwrap().state, State::Pending);
        let other_event = o.request("peer", Action::Block).unwrap();
        assert_eq!(
            other_event.signing_bytes(f.handle.certificate()).err(),
            Some(Error::Scope)
        );
        let wrong = f
            .keys
            .key(ckmg::Purpose::new(ckmg::Scope::Device, "other", 1).unwrap())
            .await
            .unwrap();
        assert_eq!(
            c.request("peer", Action::Block)
                .unwrap()
                .signing_bytes(wrong.certificate())
                .err(),
            Some(Error::Scope)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn combined_checkpoint_fences_competing_writers_before_outputs() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (backend, mut store) = f.store().await;
        let cipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let mut stale = Store::open(backend.clone(), &cipher, "alpha")
            .await
            .unwrap();
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        let e = f.sign(c.request("peer", Action::Block).unwrap()).await;
        let a = c
            .prepare(e.clone(), &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        let b = c
            .prepare(e.clone(), &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        assert_eq!(c.relation("peer").unwrap().state, State::Unknown);
        assert!(store.load_pending().unwrap().is_empty());
        let c = a
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [1; 32],
                &[
                    Change::Put {
                        owner: "cthr",
                        key: b"candidate",
                        value: b"opaque MLS",
                    },
                    Change::Delete {
                        owner: "cwvs",
                        key: b"obsolete",
                    },
                ],
                &[Output {
                    id: [3; 32],
                    bytes: b"committed only".to_vec(),
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            store.read("cthr", b"candidate").unwrap(),
            Some(b"opaque MLS".as_slice())
        );
        assert_eq!(store.load_pending().unwrap().len(), 1);
        assert_eq!(
            b.commit(
                (&mut f.devices, &mut Outcomes),
                &mut stale,
                [2; 32],
                &[],
                &[]
            )
            .await
            .err(),
            Some(Error::Storage)
        );
        assert_eq!(
            Contacts::load(f.binding.clone(), &stale).err(),
            Some(Error::Storage)
        );
        let loaded = Store::open(backend, &cipher, "alpha").await.unwrap();
        assert_eq!(loaded.operation().unwrap(), [1; 32]);
        assert_eq!(
            Contacts::load(f.binding.clone(), &loaded)
                .unwrap()
                .export_journal()
                .unwrap(),
            c.export_journal().unwrap()
        );
        assert!(Contacts::load(Binding::new("beta", "owner").unwrap(), &loaded).is_err());
        let x = c
            .prepare(e.clone(), &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        assert_eq!(
            x.commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [4; 32],
                &[Change::Delete {
                    owner: "ctcs",
                    key: b"journal.v1"
                }],
                &[]
            )
            .await
            .err(),
            Some(Error::Scope)
        );
        let x = c.prepare(e, &mut f.devices, &mut Outcomes).await.unwrap();
        assert_eq!(
            x.commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [0; 32],
                &[],
                &[]
            )
            .await
            .err(),
            Some(Error::Storage)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounded_strict_versions_chains_and_scopes() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_, store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        for action in [
            Action::Begin {
                conversation: [0; 32],
            },
            Action::Answered {
                conversation: [0; 32],
                evidence: vec![1],
            },
            Action::Reopen {
                conversation: [0; 32],
            },
        ] {
            assert_eq!(c.request("peer", action).err(), Some(Error::Encoding));
        }
        for evidence in [vec![], vec![0; ctcs::MAX_EVIDENCE + 1]] {
            assert_eq!(
                c.request(
                    "peer",
                    Action::Answered {
                        conversation: [1; 32],
                        evidence
                    }
                )
                .err(),
                Some(Error::Limit)
            );
        }
        let event = c.request("peer", Action::Block).unwrap();
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("revision", serde_json::json!(0)),
        ] {
            let bad = mutated(&event, |j| j[field] = value);
            assert_eq!(
                bad.signing_bytes(f.handle.certificate()).err(),
                Some(Error::Encoding)
            );
        }
        for bytes in [vec![b'x'], vec![0; ctcs::MAX_BYTES + 1]] {
            assert!(
                c.merge_journal(&bytes, &mut f.devices, &mut Outcomes)
                    .await
                    .is_err()
            );
        }
        let empty: serde_json::Value =
            serde_json::from_slice(&c.export_journal().unwrap()).unwrap();
        let mut j = empty.clone();
        j["version"] = 2.into();
        assert_eq!(
            c.merge_journal(
                &serde_json::to_vec(&j).unwrap(),
                &mut f.devices,
                &mut Outcomes
            )
            .await
            .err(),
            Some(Error::Encoding)
        );
        let signed = f.sign(event).await;
        let mut j = empty.clone();
        j["events"] = serde_json::json!([signed, signed]);
        assert_eq!(
            c.merge_journal(
                &serde_json::to_vec(&j).unwrap(),
                &mut f.devices,
                &mut Outcomes
            )
            .await
            .err(),
            Some(Error::Encoding)
        );
        let mut j = empty;
        j["events"] = serde_json::json!([signed]);
        for edit in [0, 1, 2, 3] {
            let mut bad = j.clone();
            match edit {
                0 => bad["events"][0]["event"]["revision"] = 2.into(),
                1 => bad["events"][0]["event"]["previous"] = serde_json::json!(vec![9; 32]),
                2 => bad["events"][0]["event"]["binding"]["community"] = "beta".into(),
                _ => bad["extra"] = true.into(),
            }
            assert!(
                c.merge_journal(
                    &serde_json::to_vec(&bad).unwrap(),
                    &mut f.devices,
                    &mut Outcomes
                )
                .await
                .is_err()
            );
        }
        let too_many = serde_json::json!({"version":1,"binding":f.binding,"events":vec![signed;ctcs::MAX_EVENTS+1]});
        assert!(
            c.merge_journal(
                &serde_json::to_vec(&too_many).unwrap(),
                &mut f.devices,
                &mut Outcomes
            )
            .await
            .is_err()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn empty_store_scope_and_changed_checkpoint_refuse() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let other = Fixture::new("beta").await;
        let (_, mut store) = f.store().await;
        let (_, mut foreign) = other.store().await;
        assert_eq!(
            Contacts::load(f.binding.clone(), &foreign).err(),
            Some(Error::Scope)
        );
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        let e = f.sign(c.request("peer", Action::Block).unwrap()).await;
        let candidate = c
            .prepare(e.clone(), &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        assert_eq!(
            candidate
                .commit(
                    (&mut f.devices, &mut Outcomes),
                    &mut foreign,
                    [1; 32],
                    &[],
                    &[]
                )
                .await
                .err(),
            Some(Error::Scope)
        );
        let stale = c
            .prepare(e.clone(), &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        let current = c.prepare(e, &mut f.devices, &mut Outcomes).await.unwrap();
        current
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [1; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            stale
                .commit(
                    (&mut f.devices, &mut Outcomes),
                    &mut store,
                    [2; 32],
                    &[],
                    &[]
                )
                .await
                .err(),
            Some(Error::Conflict)
        );
        let mut other = other;
        let o = Contacts::load(other.binding.clone(), &foreign).unwrap();
        let foreign_event = other.sign(o.request("peer", Action::Block).unwrap()).await;
        assert_eq!(
            c.prepare(foreign_event, &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Scope)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn foreign_predecessors_and_reused_conversations_refuse() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_, mut store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        let c = f
            .apply(
                &c,
                &mut store,
                "elsewhere",
                Action::Begin {
                    conversation: [8; 32],
                },
                1,
            )
            .await;
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Begin {
                    conversation: [1; 32],
                },
                2,
            )
            .await;
        let c = f.apply(&c, &mut store, "peer", Action::Close, 3).await;
        let j: serde_json::Value = serde_json::from_slice(&c.export_journal().unwrap()).unwrap();
        let child = j["events"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e["event"]["revision"] == 2)
            .unwrap();
        let parent = j["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["event"]["peer"] == "elsewhere")
            .unwrap();
        let parent: SignedEvent = serde_json::from_value(parent.clone()).unwrap();
        let foreign_id = *ckmg::hash(&serde_json::to_vec(&parent).unwrap()).value();
        for wrong_peer in [true, false] {
            let mut bad = j.clone();
            if wrong_peer {
                bad["events"][child]["event"]["previous"] = serde_json::json!(foreign_id);
            } else {
                bad["events"][child]["event"]["revision"] = 3.into();
            }
            assert_eq!(
                c.merge_journal(
                    &serde_json::to_vec(&bad).unwrap(),
                    &mut f.devices,
                    &mut Outcomes
                )
                .await
                .err(),
                Some(Error::Encoding)
            );
        }
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Reopen {
                    conversation: [2; 32],
                },
                4,
            )
            .await;
        let c = f.apply(&c, &mut store, "peer", Action::Close, 5).await;
        assert_eq!(
            c.request(
                "peer",
                Action::Reopen {
                    conversation: [2; 32]
                }
            )
            .err(),
            Some(Error::Transition)
        );
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Reopen {
                    conversation: [3; 32],
                },
                6,
            )
            .await;
        assert_eq!(c.relation("peer").unwrap().conversation, Some([3; 32]));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounded_union_refuses_without_discarding_existing_blocks() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_, mut store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        // Two individually bounded, genuinely signed journals exceed the event
        // budget only at union. This is a fixed boundary vector, not load testing.
        let mut events = vec![];
        for index in 0..=ctcs::MAX_EVENTS {
            events.push(
                f.sign(c.request(&format!("peer{index}"), Action::Block).unwrap())
                    .await,
            );
        }
        let journal = |events: &[SignedEvent]| {
            serde_json::to_vec(&serde_json::json!({
                "version": 1, "binding": f.binding, "events": events
            }))
            .unwrap()
        };
        let left = journal(&events[..512]);
        let right = journal(&events[512..]);
        assert!(left.len() <= ctcs::MAX_BYTES && right.len() <= ctcs::MAX_BYTES);
        let c = c
            .merge_journal(&left, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut store,
                [1; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            c.merge_journal(&right, &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Limit)
        );
        assert_eq!(c.blocking_rules().unwrap().len(), 512);
        // A well-typed but unbounded signed wire object is rejected before crypto.
        let oversized: SignedEvent = mutated(&events[0], |value| {
            value["event"]["action"] = serde_json::json!({
                "kind": "answered", "conversation": vec![1; 32],
                "evidence": vec![255; ctcs::MAX_BYTES]
            });
        });
        assert_eq!(
            c.prepare(oversized, &mut f.devices, &mut Outcomes)
                .await
                .err(),
            Some(Error::Limit)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn publication_rechecks_device_and_outcome_authority() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_, mut store) = f.store().await;
        let contacts = Contacts::load(f.binding.clone(), &store).unwrap();
        let event = f
            .sign(contacts.request("peer", Action::Block).unwrap())
            .await;
        let candidate = contacts
            .prepare(event, &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        f.devices.unavailable = true;
        assert_eq!(
            candidate
                .commit(
                    (&mut f.devices, &mut Outcomes),
                    &mut store,
                    [1; 32],
                    &[],
                    &[Output {
                        id: [1; 32],
                        bytes: b"withheld".to_vec()
                    }]
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        assert!(store.load_pending().unwrap().is_empty());
        assert_eq!(store.version().unwrap(), 0);
        f.devices.unavailable = false;
        let contacts = f
            .apply(
                &contacts,
                &mut store,
                "peer",
                Action::Begin {
                    conversation: [1; 32],
                },
                1,
            )
            .await;
        let event = f
            .sign(
                contacts
                    .request("peer", answer(&f.binding, "peer", [1; 32]))
                    .unwrap(),
            )
            .await;
        let candidate = contacts
            .prepare(event, &mut f.devices, &mut Outcomes)
            .await
            .unwrap();
        assert_eq!(
            candidate
                .commit(
                    (&mut f.devices, &mut ctcs::UnavailableOutcomes),
                    &mut store,
                    [2; 32],
                    &[],
                    &[]
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            Contacts::load(f.binding.clone(), &store)
                .unwrap()
                .relation("peer")
                .unwrap()
                .state,
            State::Pending
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn peer_record_handle_is_retained_replaced_and_bounded() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_backend, mut store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        let handle = |h: &[u8]| Action::Handle { handle: h.to_vec() };
        // No handle before first contact, and none can be recorded for an unknown peer.
        assert_eq!(c.handle("peer").unwrap(), None);
        assert!(c.request("peer", handle(b"one")).is_err());
        let begin = Action::Begin {
            conversation: [1; 32],
        };
        let c = f.apply(&c, &mut store, "peer", begin, 1).await;
        let c = f.apply(&c, &mut store, "peer", handle(b"one"), 2).await;
        assert_eq!(c.handle("peer").unwrap().as_deref(), Some(&b"one"[..]));
        // A later verified announcement replaces it; the newest revision wins.
        let c = f.apply(&c, &mut store, "peer", handle(b"two"), 3).await;
        assert_eq!(c.handle("peer").unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(c.relation("peer").unwrap().state, State::Pending);
        assert_eq!(c.handle("other").unwrap(), None);
        assert!(c.request("peer", handle(b"")).is_err());
        assert!(
            c.request("peer", handle(&vec![0; ctcs::MAX_HANDLE + 1]))
                .is_err()
        );
        // A blocked relation retains no new handle.
        let c = f.apply(&c, &mut store, "peer", Action::Block, 4).await;
        assert!(c.request("peer", handle(b"three")).is_err());
        assert_eq!(c.handle("peer").unwrap().as_deref(), Some(&b"two"[..]));
    })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn voucher_admission_establishes_once_and_never_undoes_a_block() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (_backend, mut store) = f.store().await;
        let c = Contacts::load(f.binding.clone(), &store).unwrap();
        let bond = [7u8; 32];
        // Both sides derive the same id whatever the order of the two member ids.
        let id = ctcs::voucher_conversation(&bond, "sponsor", "newcomer");
        assert_eq!(id, ctcs::voucher_conversation(&bond, "newcomer", "sponsor"));
        assert_ne!(
            id,
            ctcs::voucher_conversation(&[8; 32], "sponsor", "newcomer")
        );
        assert_ne!(id, ctcs::voucher_conversation(&bond, "sponsor", "other"));
        assert!(
            c.request(
                "peer",
                Action::Voucher {
                    conversation: [0; 32]
                }
            )
            .is_err()
        );
        let c = f
            .apply(
                &c,
                &mut store,
                "peer",
                Action::Voucher { conversation: id },
                1,
            )
            .await;
        let relation = c.relation("peer").unwrap();
        assert_eq!(relation.state, State::Established);
        assert_eq!(relation.conversation, Some(id));
        // Repeating the same admission is harmless; another conversation is not.
        assert!(
            c.request("peer", Action::Voucher { conversation: id })
                .is_ok()
        );
        assert!(
            c.request(
                "peer",
                Action::Voucher {
                    conversation: [9; 32]
                }
            )
            .is_err()
        );
        // A block the member chose stays; only Reopen is the way back.
        let c = f.apply(&c, &mut store, "peer", Action::Block, 2).await;
        assert_eq!(c.relation("peer").unwrap().state, State::Blocked);
        assert!(
            c.request("peer", Action::Voucher { conversation: id })
                .is_err()
        );
    });
}
