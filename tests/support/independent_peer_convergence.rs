use super::*;

// Fixture authority exercises delegation boundaries only; it is not
// production device attestation or Waves/accounting acceptance.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn independent_peer_progress_converges_without_global_fence() {
    block_on(async {
        let mut f = Fixture::new("alpha").await;
        let (left_backend, mut left_store) = f.store().await;
        let (right_backend, mut right_store) = f.store().await;
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let conv_a1 = [11; 32];
        let conv_b1 = [12; 32];
        let conv_b2 = [13; 32];

        // Same owner establishes both peers on the left checkpoint.
        let base = Contacts::load(f.binding.clone(), &left_store).unwrap();
        let base = f
            .apply(
                &base,
                &mut left_store,
                peer_a,
                Action::Begin {
                    conversation: conv_a1,
                },
                1,
            )
            .await;
        let base = f
            .apply(
                &base,
                &mut left_store,
                peer_a,
                answer(&f.binding, peer_a, conv_a1),
                2,
            )
            .await;
        let base = f
            .apply(
                &base,
                &mut left_store,
                peer_b,
                Action::Begin {
                    conversation: conv_b1,
                },
                3,
            )
            .await;
        let base = f
            .apply(
                &base,
                &mut left_store,
                peer_b,
                answer(&f.binding, peer_b, conv_b1),
                4,
            )
            .await;
        assert_eq!(base.relation(peer_a).unwrap().state, State::Established);
        assert_eq!(base.relation(peer_b).unwrap().state, State::Established);

        // Copy the journal through an actual signed merge into the right store.
        let empty = Contacts::load(f.binding.clone(), &right_store).unwrap();
        let right = empty
            .merge_journal(
                &base.export_journal().unwrap(),
                &mut f.devices,
                &mut Outcomes,
            )
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut right_store,
                [10; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            right.export_journal().unwrap(),
            base.export_journal().unwrap()
        );

        // Diverge by peer: left closes then blocks A, right closes then
        // reopens B with a fresh conversation and verified Answer.
        let left = f
            .apply(&base, &mut left_store, peer_a, Action::Close, 11)
            .await;
        let left = f
            .apply(&left, &mut left_store, peer_a, Action::Block, 12)
            .await;
        let right = f
            .apply(&right, &mut right_store, peer_b, Action::Close, 13)
            .await;
        let right = f
            .apply(
                &right,
                &mut right_store,
                peer_b,
                Action::Reopen {
                    conversation: conv_b2,
                },
                14,
            )
            .await;
        let right = f
            .apply(
                &right,
                &mut right_store,
                peer_b,
                answer(&f.binding, peer_b, conv_b2),
                15,
            )
            .await;
        assert_eq!(right.relation(peer_b).unwrap().conversation, Some(conv_b2));

        // Merge complete journals in both orders; canonical bytes must match.
        let left_bytes = left.export_journal().unwrap();
        let right_bytes = right.export_journal().unwrap();
        let left_merged = left
            .merge_journal(&right_bytes, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut left_store,
                [20; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        let right_merged = right
            .merge_journal(&left_bytes, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut right_store,
                [21; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            left_merged.export_journal().unwrap(),
            right_merged.export_journal().unwrap()
        );
        let canonical = left_merged.export_journal().unwrap();

        // Independent progress: A stays Blocked without fencing B, B is
        // Established at its new conversation, and only A blocks Board.
        assert!(!left_merged.relation(peer_a).unwrap().conflicted);
        assert!(!left_merged.relation(peer_b).unwrap().conflicted);
        assert_eq!(left_merged.relation(peer_a).unwrap().state, State::Blocked);
        assert_eq!(right_merged.relation(peer_a).unwrap().state, State::Blocked);
        assert_eq!(
            left_merged.relation(peer_b).unwrap().state,
            State::Established
        );
        assert_eq!(
            left_merged.relation(peer_b).unwrap().conversation,
            Some(conv_b2)
        );
        assert_eq!(
            right_merged.relation(peer_b).unwrap().conversation,
            Some(conv_b2)
        );
        assert_eq!(
            left_merged.blocking_rules().unwrap(),
            vec![peer_a.to_string()]
        );
        assert_eq!(
            right_merged.blocking_rules().unwrap(),
            vec![peer_a.to_string()]
        );

        // Old Answers and cross-peer conversations cannot establish B or clear A.
        assert!(
            left_merged
                .request(peer_b, answer(&f.binding, peer_b, conv_b1))
                .is_err()
        );
        assert!(
            left_merged
                .request(peer_b, answer(&f.binding, peer_b, conv_a1))
                .is_err()
        );
        assert!(
            left_merged
                .request(peer_a, answer(&f.binding, peer_a, conv_a1))
                .is_err()
        );
        assert!(
            left_merged
                .request(
                    peer_b,
                    Action::Begin {
                        conversation: [14; 32]
                    }
                )
                .is_err()
        );

        // Reopen both encrypted stores; persisted facts must survive restart.
        left_store.lock();
        right_store.lock();
        let cipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let mut left_store = Store::open(left_backend, &cipher, "alpha").await.unwrap();
        let mut right_store = Store::open(right_backend, &cipher, "alpha").await.unwrap();
        let left_reopened = Contacts::load(f.binding.clone(), &left_store).unwrap();
        let right_reopened = Contacts::load(f.binding.clone(), &right_store).unwrap();
        assert_eq!(left_reopened.export_journal().unwrap(), canonical);
        assert_eq!(right_reopened.export_journal().unwrap(), canonical);
        assert_eq!(
            left_reopened.relation(peer_a).unwrap().state,
            State::Blocked
        );
        assert_eq!(
            left_reopened.relation(peer_b).unwrap().conversation,
            Some(conv_b2)
        );

        // Repeat synchronization; journal and relation facts stay unchanged.
        // Store versions are not compared: idempotent set merge may checkpoint.
        let left_re = left_reopened
            .merge_journal(
                &right_reopened.export_journal().unwrap(),
                &mut f.devices,
                &mut Outcomes,
            )
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut left_store,
                [30; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        let right_re = right_reopened
            .merge_journal(&canonical, &mut f.devices, &mut Outcomes)
            .await
            .unwrap()
            .commit(
                (&mut f.devices, &mut Outcomes),
                &mut right_store,
                [31; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(left_re.export_journal().unwrap(), canonical);
        assert_eq!(right_re.export_journal().unwrap(), canonical);
        assert_eq!(left_re.relation(peer_a).unwrap().state, State::Blocked);
        assert_eq!(left_re.relation(peer_b).unwrap().state, State::Established);
        assert_eq!(
            left_re.relation(peer_b).unwrap().conversation,
            Some(conv_b2)
        );
        assert_eq!(left_re.blocking_rules().unwrap(), vec![peer_a.to_string()]);
        assert_eq!(right_re.blocking_rules().unwrap(), vec![peer_a.to_string()]);
    });
}
