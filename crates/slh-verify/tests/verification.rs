use seal_slh_verify::{advance, start, verify, Error, Progress, Sha256, SIGNATURE_BYTES};
use serde_json::Value;
use sha2::{Digest, Sha256 as NativeSha256};

struct Hash;
impl Sha256 for Hash {
    fn hashv(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = NativeSha256::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().into()
    }
}
fn bytes(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap()).unwrap()
}
fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let all: Value = serde_json::from_str(include_str!("../../../fixtures/sigGen.json")).unwrap();
    let t = &all["testGroups"][0]["tests"][0];
    (
        bytes(t, "pk"),
        bytes(t, "signature"),
        bytes(t, "message"),
        bytes(t, "context"),
    )
}

#[test]
fn nist_external_pure_signature_verification() {
    let all: Value = serde_json::from_str(include_str!("../../../fixtures/sigVer.json")).unwrap();
    let mut count = 0;
    for g in all["testGroups"].as_array().unwrap() {
        assert_eq!(g["parameterSet"], "SLH-DSA-SHA2-128s");
        assert_eq!(g["signatureInterface"], "external");
        assert_eq!(g["preHash"], "pure");
        for t in g["tests"].as_array().unwrap() {
            let actual = verify::<Hash>(
                &bytes(t, "pk"),
                &bytes(t, "signature"),
                &bytes(t, "message"),
                &bytes(t, "context"),
            )
            .is_ok();
            assert_eq!(
                actual,
                t["testPassed"].as_bool().unwrap(),
                "tcId={}",
                t["tcId"]
            );
            count += 1;
        }
    }
    assert_eq!(count, 14);
}

#[test]
fn nist_published_signature_generation_outputs_verify() {
    let all: Value = serde_json::from_str(include_str!("../../../fixtures/sigGen.json")).unwrap();
    let mut count = 0;
    for g in all["testGroups"].as_array().unwrap() {
        assert_eq!(g["parameterSet"], "SLH-DSA-SHA2-128s");
        assert_eq!(g["preHash"], "pure");
        for t in g["tests"].as_array().unwrap() {
            verify::<Hash>(
                &bytes(t, "pk"),
                &bytes(t, "signature"),
                &bytes(t, "message"),
                &bytes(t, "context"),
            )
            .unwrap();
            count += 1;
        }
    }
    assert_eq!(count, 14);
}

#[test]
fn every_signature_node_is_authenticated() {
    let (pk, mut sig, msg, ctx) = fixture();
    assert_eq!(sig.len(), SIGNATURE_BYTES);
    for offset in (0..sig.len()).step_by(16) {
        sig[offset] ^= 1;
        assert!(
            verify::<Hash>(&pk, &sig, &msg, &ctx).is_err(),
            "offset={offset}"
        );
        sig[offset] ^= 1;
    }
}

#[test]
fn wrong_key_message_context_and_lengths_fail() {
    let (mut pk, sig, mut msg, mut ctx) = fixture();
    pk[0] ^= 1;
    assert!(verify::<Hash>(&pk, &sig, &msg, &ctx).is_err());
    pk[0] ^= 1;
    msg[0] ^= 1;
    assert!(verify::<Hash>(&pk, &sig, &msg, &ctx).is_err());
    msg[0] ^= 1;
    ctx[0] ^= 1;
    assert!(verify::<Hash>(&pk, &sig, &msg, &ctx).is_err());
    ctx[0] ^= 1;
    assert_eq!(
        verify::<Hash>(&pk[..31], &sig, &msg, &ctx),
        Err(Error::PublicKeyLength)
    );
    assert_eq!(
        verify::<Hash>(&pk, &sig[..sig.len() - 1], &msg, &ctx),
        Err(Error::SignatureLength)
    );
    assert_eq!(
        verify::<Hash>(&pk, &sig, &msg, &[0; 256]),
        Err(Error::ContextLength)
    );
}

#[test]
fn staged_verification_matches_complete_verification() {
    let (pk, sig, msg, ctx) = fixture();
    let mut p = start::<Hash>(&pk, &sig, &msg, &ctx).unwrap();
    for layer in 0..7 {
        assert_eq!(p.layer, layer);
        p = advance::<Hash>(&pk, &sig, p).unwrap();
    }
    assert_eq!(p.root.as_slice(), &pk[16..]);
    assert_eq!(advance::<Hash>(&pk, &sig, p), Err(Error::InvalidProgress));
    for bad in [
        Progress { layer: 8, ..p },
        Progress {
            layer: 0,
            leaf: 512,
            ..p
        },
        Progress {
            layer: 6,
            tree: 1,
            ..p
        },
    ] {
        assert_eq!(advance::<Hash>(&pk, &sig, bad), Err(Error::InvalidProgress));
    }
}
