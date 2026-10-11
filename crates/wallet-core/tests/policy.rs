use seal_wallet_core::*;

fn owners(count: u8, threshold: u8) -> Owners {
    let mut keys = [[0; 32]; 3];
    for (i, key) in keys.iter_mut().enumerate().take(usize::from(count)) {
        *key = [(i + 1) as u8; 32];
    }
    Owners {
        count,
        threshold,
        keys,
    }
}
fn policy() -> Policy {
    Policy {
        owners: owners(2, 2),
        guardian: [9; 32],
        recovery_delay: 150,
    }
}
fn wallet() -> Wallet {
    Wallet::new(253, [4; 32], [5; 32], policy()).unwrap()
}
fn proof(index: u8) -> ProofHeader {
    let w = wallet();
    ProofHeader {
        magic: PROOF_MAGIC,
        bump: 250,
        wallet: [8; 32],
        uploader: [7; 32],
        digest: [6; 32],
        key: w.policy.key(index).unwrap(),
        epoch: 0,
        nonce: 0,
        expiry: 1000,
        index,
        uploaded: 7856,
        stage: 9,
        root: [0; 16],
        tree: 0,
        leaf: 0,
    }
}
fn intent(action: &[u8]) -> Vec<u8> {
    let mut b = vec![1];
    b.extend([1; 32]);
    b.extend([2; 32]);
    b.extend([3; 32]);
    b.extend(0u64.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    b.extend(1000u64.to_le_bytes());
    b.extend(action);
    b
}
fn invoke(target: [u8; 32], metas: &[([u8; 32], u8)], data: &[u8]) -> Vec<u8> {
    let mut a = vec![4];
    a.extend(target);
    a.push(metas.len() as u8);
    for (k, f) in metas {
        a.extend(k);
        a.push(*f);
    }
    a.extend((data.len() as u16).to_le_bytes());
    a.extend(data);
    intent(&a)
}

#[test]
fn serialized_account_layouts_have_fixed_sizes() {
    assert_eq!(borsh::to_vec(&policy()).unwrap().len(), POLICY_BYTES);
    assert_eq!(borsh::to_vec(&wallet()).unwrap().len(), WALLET_BYTES);
    assert_eq!(borsh::to_vec(&proof(0)).unwrap().len(), PROOF_HEADER_BYTES);
}
#[test]
fn policy_requires_distinct_nonzero_keys_and_canonical_padding() {
    for threshold in [0, 3] {
        let mut p = policy();
        p.owners.threshold = threshold;
        assert!(p.validate().is_err());
    }
    let mut p = policy();
    p.owners.keys[1] = p.owners.keys[0];
    assert_eq!(p.validate(), Err(Error::InvalidPolicy));
    let mut p = policy();
    p.owners.keys[0] = [0; 32];
    assert!(p.validate().is_err());
    let mut p = policy();
    p.owners.keys[2] = [3; 32];
    assert!(p.validate().is_err());
    let mut p = policy();
    p.owners.count = 0;
    assert!(p.validate().is_err());
}
#[test]
fn recovery_must_be_a_separate_key_with_a_bounded_delay() {
    let mut p = policy();
    p.guardian = p.owners.keys[0];
    assert!(p.validate().is_err());
    for delay in [0, 149, 2_000_001] {
        let mut p = policy();
        p.recovery_delay = delay;
        assert!(p.validate().is_err());
    }
    let mut p = policy();
    p.guardian = [0; 32];
    assert!(p.validate().is_err());
    p.recovery_delay = 0;
    p.validate().unwrap();
    assert_eq!(p.key(255), Err(Error::RecoveryDisabled));
}
#[test]
fn quorum_counts_unique_owner_indices() {
    assert_eq!(
        authorize(&wallet(), &[proof(0)], &[6; 32], false, 10),
        Err(Error::Threshold)
    );
    authorize(&wallet(), &[proof(0), proof(1)], &[6; 32], false, 10).unwrap();
    assert_eq!(
        authorize(&wallet(), &[proof(0), proof(0)], &[6; 32], false, 10),
        Err(Error::DuplicateApproval)
    );
}
#[test]
fn guardian_authorization_cannot_spend() {
    authorize(&wallet(), &[proof(255)], &[6; 32], true, 10).unwrap();
    assert!(authorize(&wallet(), &[proof(255)], &[6; 32], false, 10).is_err());
    assert!(authorize(&wallet(), &[proof(0)], &[6; 32], true, 10).is_err());
    assert!(authorize(&wallet(), &[proof(255), proof(255)], &[6; 32], true, 10).is_err());
}
#[test]
fn signatures_are_not_approved_until_the_last_layer() {
    for stage in 0..9 {
        let mut p = proof(0);
        p.stage = stage;
        assert_eq!(
            authorize(&wallet(), &[p, proof(1)], &[6; 32], false, 10),
            Err(Error::WrongPhase)
        );
    }
    let mut p = proof(0);
    p.uploaded = 7855;
    assert_eq!(
        authorize(&wallet(), &[p, proof(1)], &[6; 32], false, 10),
        Err(Error::WrongPhase)
    );
}
#[test]
fn digest_and_active_key_are_checked() {
    assert_eq!(
        authorize(&wallet(), &[proof(0), proof(1)], &[0; 32], false, 10),
        Err(Error::IntentMismatch)
    );
    let mut p = proof(0);
    p.key = [8; 32];
    assert_eq!(
        authorize(&wallet(), &[p, proof(1)], &[6; 32], false, 10),
        Err(Error::Stale)
    );
}
#[test]
fn epoch_nonce_expiry_and_lock_are_enforced() {
    let mut w = wallet();
    w.check_live(0, 0, 100, 100).unwrap();
    assert_eq!(w.check_live(0, 0, 99, 100), Err(Error::Expired));
    assert_eq!(w.check_live(1, 0, 100, 100), Err(Error::Stale));
    assert_eq!(w.check_live(0, 1, 100, 100), Err(Error::Stale));
    w.locked = true;
    assert_eq!(w.check_live(0, 0, 100, 100), Err(Error::Locked));
}
#[test]
fn rotation_preserves_the_deposit_identity() {
    let mut w = wallet();
    w.bump_nonce().unwrap();
    let next = Policy {
        owners: owners(1, 1),
        ..policy()
    };
    w.rotate(next).unwrap();
    assert_eq!((w.id, w.genesis, w.bump), ([4; 32], [5; 32], 253));
    assert_eq!((w.epoch, w.nonce), (1, 1));
    assert_eq!(w.policy.owners.threshold, 1);
    assert_eq!(
        authorize(&w, &[proof(0), proof(1)], &[6; 32], false, 10),
        Err(Error::Stale)
    );
}
#[test]
fn recovery_cannot_finalize_before_its_slot() {
    let mut w = wallet();
    w.propose_recovery(owners(1, 1), 100).unwrap();
    assert_eq!(w.recovery_ready_at, 250);
    assert_eq!(w.finalize_recovery(249), Err(Error::RecoveryDelay));
    w.finalize_recovery(250).unwrap();
    assert_eq!((w.epoch, w.nonce), (1, 1));
    assert_eq!(w.policy.owners.threshold, 1);
    assert_eq!(w.id, [4; 32]);
    assert_eq!(w.recovery_ready_at, 0);
}
#[test]
fn owners_can_veto_recovery_and_rotation_cancels_it() {
    let mut w = wallet();
    w.propose_recovery(owners(1, 1), 100).unwrap();
    assert_eq!(
        w.propose_recovery(owners(1, 1), 101),
        Err(Error::RecoveryPending)
    );
    w.cancel_recovery();
    assert_eq!(w.finalize_recovery(1000), Err(Error::NoRecovery));
    w.propose_recovery(owners(1, 1), 200).unwrap();
    w.rotate(policy()).unwrap();
    assert_eq!(w.finalize_recovery(1000), Err(Error::NoRecovery));
}
#[test]
fn counters_fail_closed_at_u64_max() {
    let mut w = wallet();
    w.nonce = u64::MAX;
    assert_eq!(w.bump_nonce(), Err(Error::Overflow));
    assert_eq!(w.nonce, u64::MAX);
    w.epoch = u64::MAX;
    assert_eq!(w.rotate(policy()), Err(Error::Overflow));
    let mut w = wallet();
    assert_eq!(
        w.propose_recovery(owners(1, 1), u64::MAX),
        Err(Error::Overflow)
    );
    assert_eq!(w.recovery_ready_at, 0);
}
#[test]
fn intents_reject_trailing_data_unknown_actions_and_zero_transfers() {
    let mut a = vec![0];
    a.extend([4; 32]);
    a.extend(1u64.to_le_bytes());
    let good = intent(&a);
    Intent::decode(&good).unwrap();
    let mut bad = good.clone();
    bad.push(0);
    assert!(Intent::decode(&bad).is_err());
    let mut bad = good.clone();
    bad[0] = 2;
    assert!(Intent::decode(&bad).is_err());
    assert!(Intent::decode(&intent(&[99])).is_err());
    let mut zero = vec![0];
    zero.extend([4; 32]);
    zero.extend(0u64.to_le_bytes());
    assert!(Intent::decode(&intent(&zero)).is_err());
    assert!(Intent::decode(&vec![0; 851]).is_err());
    for len in 0..good.len() {
        assert!(Intent::decode(&good[..len]).is_err());
    }
}
#[test]
fn invocation_cannot_delegate_undeclared_signers_or_write_the_wallet() {
    Intent::decode(&invoke([4; 32], &[([3; 32], 2)], &[1])).unwrap();
    assert_eq!(
        Intent::decode(&invoke([4; 32], &[([3; 32], 3)], &[1])),
        Err(Error::UnsafeInvocation)
    );
    assert_eq!(
        Intent::decode(&invoke([4; 32], &[([5; 32], 2)], &[1])),
        Err(Error::UnsafeInvocation)
    );
    assert_eq!(
        Intent::decode(&invoke([2; 32], &[], &[])),
        Err(Error::UnsafeInvocation)
    );
    assert!(Intent::decode(&invoke([4; 32], &[([5; 32], 0), ([5; 32], 1)], &[])).is_err());
    assert!(Intent::decode(&invoke([4; 32], &[([5; 32], 4)], &[])).is_err());
    assert!(Intent::decode(&invoke([4; 32], &[], &[0; 257])).is_err());
}

#[test]
fn all_one_to_three_owner_threshold_subsets_match_the_policy() {
    for count in 1..=3 {
        for threshold in 1..=count {
            let mut w = wallet();
            w.policy.owners = owners(count, threshold);
            for mask in 0u8..(1 << count) {
                let mut approvals = Vec::new();
                for index in 0..count {
                    if mask & (1 << index) != 0 {
                        let mut p = proof(0);
                        p.index = index;
                        p.key = w.policy.key(index).unwrap();
                        approvals.push(p);
                    }
                }
                assert_eq!(
                    authorize(&w, &approvals, &[6; 32], false, 10).is_ok(),
                    mask.count_ones() >= u32::from(threshold)
                );
            }
        }
    }
}
