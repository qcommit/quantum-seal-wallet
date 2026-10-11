//! Property tests for `Intent::decode`, driven by a small deterministic PRNG (no extra
//! dependencies). Set `QSW_PROPERTY_SEED` to explore other seeds and
//! `QSW_PROPERTY_SCALE` to multiply the iteration counts.
use seal_wallet_core::*;

/// SplitMix64: tiny, deterministic and good enough to drive a fuzz loop.
struct Rng(u64);
impl Rng {
    fn new(stream: u64) -> Self {
        let seed = std::env::var("QSW_PROPERTY_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x5eed_2026_1011_u64);
        Self(seed ^ stream.wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
    fn index(&mut self, n: usize) -> usize {
        self.below(n as u64) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn key(&mut self) -> [u8; 32] {
        let mut k = [0; 32];
        k.iter_mut().for_each(|b| *b = self.next() as u8);
        k[0] |= 1;
        k
    }
    fn u64(&mut self) -> u64 {
        if self.chance(20) {
            [0, 1, u64::from(u32::MAX), 1 << 63, u64::MAX][self.index(5)]
        } else {
            self.next()
        }
    }
}

fn scale(n: usize) -> usize {
    let factor = std::env::var("QSW_PROPERTY_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    n * factor
}

// ------------------------------------------------------------ test-side encoder
// Written from docs/PROTOCOL.md, independently of the decoder.
fn encode_owners(o: &Owners, out: &mut Vec<u8>) {
    out.push(o.count);
    out.push(o.threshold);
    o.keys.iter().for_each(|k| out.extend(k));
}

fn encode(intent: &Intent) -> Vec<u8> {
    let mut b = vec![if intent.fee.is_some() { 2 } else { 1 }];
    b.extend(intent.genesis);
    b.extend(intent.program);
    b.extend(intent.wallet);
    b.extend(intent.epoch.to_le_bytes());
    b.extend(intent.nonce.to_le_bytes());
    b.extend(intent.expiry.to_le_bytes());
    match &intent.action {
        Action::Transfer { to, lamports } => {
            b.push(0);
            b.extend(to);
            b.extend(lamports.to_le_bytes());
        }
        Action::Rotate(p) => {
            b.push(1);
            encode_owners(&p.owners, &mut b);
            b.extend(p.guardian);
            b.extend(p.recovery_delay.to_le_bytes());
        }
        Action::ProposeRecovery(o) => {
            b.push(2);
            encode_owners(o, &mut b);
        }
        Action::CancelRecovery => b.push(3),
        Action::Invoke {
            program,
            metas,
            data,
        } => {
            b.push(4);
            b.extend(program);
            b.push(metas.len() as u8);
            for m in metas {
                b.extend(m.key);
                b.push(u8::from(m.writable) | u8::from(m.signer) << 1);
            }
            b.extend((data.len() as u16).to_le_bytes());
            b.extend(data);
        }
    }
    if let Some(fee) = intent.fee {
        b.extend(fee.to);
        b.extend(fee.lamports.to_le_bytes());
    }
    b
}

// ------------------------------------------------------------ valid-intent generator
fn distinct_keys(rng: &mut Rng, n: usize, avoid: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(n);
    while out.len() < n {
        let k = rng.key();
        if !out.contains(&k) && !avoid.contains(&k) {
            out.push(k);
        }
    }
    out
}

fn gen_owners(rng: &mut Rng) -> Owners {
    let count = rng.range(1, 3) as u8;
    let mut keys = [[0; 32]; MAX_OWNERS];
    for (slot, key) in keys
        .iter_mut()
        .zip(distinct_keys(rng, usize::from(count), &[]))
    {
        *slot = key;
    }
    Owners {
        count,
        threshold: rng.range(1, u64::from(count)) as u8,
        keys,
    }
}

fn gen_intent(rng: &mut Rng) -> Intent {
    let ids = distinct_keys(rng, 2, &[]);
    let (program, wallet) = (ids[0], ids[1]);
    let genesis = if rng.chance(10) {
        MAINNET_GENESIS
    } else {
        rng.key()
    };
    let action = match rng.below(6) {
        0 => Action::Transfer {
            to: rng.key(),
            lamports: rng.u64().max(1),
        },
        1 => {
            let owners = gen_owners(rng);
            let (guardian, recovery_delay) = if rng.chance(35) {
                ([0; 32], 0)
            } else {
                let g = distinct_keys(rng, 1, &owners.keys)[0];
                (g, rng.range(MIN_RECOVERY_DELAY, MAX_RECOVERY_DELAY))
            };
            Action::Rotate(Policy {
                owners,
                guardian,
                recovery_delay,
            })
        }
        2 => Action::ProposeRecovery(gen_owners(rng)),
        3 => Action::CancelRecovery,
        _ => {
            let target = distinct_keys(rng, 1, &[program])[0];
            let count = rng.index(13);
            let mut metas: Vec<Meta> = distinct_keys(rng, count, &[wallet])
                .into_iter()
                .map(|key| Meta {
                    key,
                    writable: rng.chance(50),
                    signer: false,
                })
                .collect();
            if count > 0 && rng.chance(40) {
                let i = rng.index(count);
                metas[i] = Meta {
                    key: wallet,
                    writable: false,
                    signer: true,
                };
            }
            let len = rng.index(257);
            Action::Invoke {
                program: target,
                metas,
                data: rng.bytes(len),
            }
        }
    };
    let fee = rng.chance(50).then(|| FeeRefund {
        to: distinct_keys(rng, 1, &[program, wallet])[0],
        lamports: if rng.chance(20) {
            [1, MAX_FEE_REFUND][rng.index(2)]
        } else {
            rng.range(1, MAX_FEE_REFUND)
        },
    });
    Intent {
        genesis,
        program,
        wallet,
        epoch: rng.u64(),
        nonce: rng.u64(),
        expiry: rng.u64(),
        action,
        fee,
    }
}

fn mutate(rng: &mut Rng, mut b: Vec<u8>) -> Vec<u8> {
    for _ in 0..rng.range(1, 3) {
        match rng.below(7) {
            0 | 1 if !b.is_empty() => {
                let i = rng.index(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            2 if !b.is_empty() => {
                let i = rng.index(b.len());
                b[i] = rng.next() as u8;
            }
            3 => b.truncate(rng.index(b.len() + 1)),
            4 => {
                let n = rng.index(40) + 1;
                b.extend(rng.bytes(n));
            }
            5 if !b.is_empty() => {
                let at = rng.index(b.len());
                let n = rng.index(b.len() - at) + 1;
                b.drain(at..at + n.min(33));
            }
            _ if !b.is_empty() => b[0] = [0, 1, 2, 3, 255][rng.index(5)],
            _ => {}
        }
    }
    b.truncate(900);
    b
}

/// Invariants every successfully decoded intent must satisfy.
fn check_accepted(bytes: &[u8], intent: &Intent) {
    assert!(
        bytes.len() <= MAX_INTENT_BYTES,
        "accepted {} bytes",
        bytes.len()
    );
    assert!(bytes[0] == 1 || bytes[0] == 2);
    assert_eq!(
        intent.fee.is_some(),
        bytes[0] == 2,
        "fee block iff version 2"
    );
    if let Some(fee) = intent.fee {
        assert!((1..=MAX_FEE_REFUND).contains(&fee.lamports));
        assert!(fee.to != [0; 32] && fee.to != intent.wallet && fee.to != intent.program);
    }
    match &intent.action {
        Action::Transfer { lamports, .. } => assert_ne!(*lamports, 0),
        Action::Rotate(p) => assert_eq!(p.validate(), Ok(())),
        Action::ProposeRecovery(o) => assert_eq!(o.validate(), Ok(())),
        Action::CancelRecovery => {}
        Action::Invoke {
            program,
            metas,
            data,
        } => {
            assert_ne!(*program, intent.program);
            assert!(metas.len() <= 12 && data.len() <= 256);
            for (i, m) in metas.iter().enumerate() {
                assert!(!metas[..i].iter().any(|n| n.key == m.key));
                assert_eq!(m.signer, m.key == intent.wallet);
                assert!(!(m.key == intent.wallet && m.writable));
            }
        }
    }
    // Decoding is injective: the canonical re-encoding reproduces the input exactly.
    assert_eq!(encode(intent), bytes, "accepted input is not canonical");
}

fn decode_and_check(bytes: &[u8]) -> Result<Intent> {
    let result = Intent::decode(bytes);
    if let Ok(intent) = &result {
        check_accepted(bytes, intent);
    }
    if bytes.len() > MAX_INTENT_BYTES {
        assert_eq!(result, Err(Error::InvalidData), "oversize input accepted");
    }
    result
}

#[test]
fn decode_never_panics_on_arbitrary_bytes_up_to_900() {
    let mut rng = Rng::new(1);
    let mut accepted = 0;
    for _ in 0..scale(1_000_000) {
        let len = rng.index(901);
        let mut b = rng.bytes(len);
        // Steer a share of inputs past the version and action checks.
        if len > 0 && rng.chance(70) {
            b[0] = rng.range(1, 2) as u8;
        }
        if len > 121 && rng.chance(70) {
            b[121] = rng.below(6) as u8;
        }
        if decode_and_check(&b).is_ok() {
            accepted += 1;
        }
    }
    // Every byte of a random 162-byte v1 transfer is free except the version, the
    // action byte and nonzero lamports, so some random inputs must decode.
    assert!(accepted > 0);
}

#[test]
fn decode_never_panics_on_mutated_valid_intents() {
    let mut rng = Rng::new(2);
    let (mut accepted, mut rejected) = (0, 0);
    for _ in 0..scale(300_000) {
        let valid = encode(&gen_intent(&mut rng));
        let bytes = mutate(&mut rng, valid);
        match decode_and_check(&bytes) {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    assert!(
        accepted > 1_000 && rejected > 1_000,
        "{accepted}/{rejected}"
    );
}

#[test]
fn every_truncation_of_a_valid_intent_is_rejected() {
    let mut rng = Rng::new(3);
    for _ in 0..scale(300) {
        let bytes = encode(&gen_intent(&mut rng));
        for n in 0..bytes.len() {
            assert_eq!(Intent::decode(&bytes[..n]), Err(Error::InvalidData));
        }
    }
}

#[test]
fn generated_valid_intents_round_trip() {
    let mut rng = Rng::new(4);
    let mut kinds = [0usize; 5];
    for _ in 0..scale(50_000) {
        let intent = gen_intent(&mut rng);
        let bytes = encode(&intent);
        assert!(bytes.len() < MAX_INTENT_BYTES, "{} bytes", bytes.len());
        let decoded = Intent::decode(&bytes).unwrap_or_else(|e| panic!("{e:?} for {intent:?}"));
        assert_eq!(decoded, intent);
        check_accepted(&bytes, &decoded);
        if let Action::Rotate(p) = &intent.action {
            assert_eq!(borsh::to_vec(p).unwrap(), bytes[122..122 + POLICY_BYTES]);
        }
        kinds[match intent.action {
            Action::Transfer { .. } => 0,
            Action::Rotate(_) => 1,
            Action::ProposeRecovery(_) => 2,
            Action::CancelRecovery => 3,
            Action::Invoke { .. } => 4,
        }] += 1;
    }
    assert!(kinds.iter().all(|&n| n > 0), "{kinds:?}");
}

#[test]
fn intents_over_850_bytes_are_always_rejected() {
    let mut rng = Rng::new(5);
    let largest = Intent {
        genesis: [1; 32],
        program: [2; 32],
        wallet: [3; 32],
        epoch: 0,
        nonce: 0,
        expiry: 0,
        action: Action::Invoke {
            program: [4; 32],
            metas: (0..12)
                .map(|i| Meta {
                    key: [10 + i; 32],
                    writable: false,
                    signer: false,
                })
                .collect(),
            data: vec![0; 256],
        },
        fee: Some(FeeRefund {
            to: [5; 32],
            lamports: 1,
        }),
    };
    let largest = encode(&largest);
    assert_eq!(largest.len(), 849);
    assert!(Intent::decode(&largest).is_ok());
    for len in MAX_INTENT_BYTES + 1..=900 {
        for _ in 0..scale(200) {
            let mut b = if rng.chance(50) {
                encode(&gen_intent(&mut rng))
            } else {
                largest.clone()
            };
            let pad = len - b.len();
            if rng.chance(50) {
                b.extend(vec![0; pad]);
            } else {
                b.extend(rng.bytes(pad));
            }
            assert_eq!(Intent::decode(&b), Err(Error::InvalidData));
            let random = rng.bytes(len);
            assert_eq!(Intent::decode(&random), Err(Error::InvalidData));
        }
    }
}

#[test]
fn version_two_intents_always_carry_a_bounded_fee() {
    let mut rng = Rng::new(6);
    for _ in 0..scale(20_000) {
        let mut intent = gen_intent(&mut rng);
        let to = distinct_keys(&mut rng, 1, &[intent.program, intent.wallet])[0];
        let lamports = [
            0,
            1,
            2,
            MAX_FEE_REFUND - 1,
            MAX_FEE_REFUND,
            MAX_FEE_REFUND + 1,
            u64::MAX,
            rng.next(),
        ][rng.index(8)];
        let to = [to, [0; 32], intent.wallet, intent.program, intent.genesis][rng.index(5)];
        intent.fee = Some(FeeRefund { to, lamports });
        let bytes = encode(&intent);
        let valid = (1..=MAX_FEE_REFUND).contains(&lamports)
            && to != [0; 32]
            && to != intent.wallet
            && to != intent.program;
        match Intent::decode(&bytes) {
            Ok(decoded) => {
                assert!(valid, "accepted fee {lamports} to {to:?}");
                assert_eq!(decoded.fee, Some(FeeRefund { to, lamports }));
                check_accepted(&bytes, &decoded);
            }
            Err(e) => {
                assert!(!valid, "rejected valid fee {lamports}: {e:?}");
                assert_eq!(e, Error::InvalidFeeRefund);
            }
        }
        // A version-2 header without the fee block, or a version-1 header with one,
        // never decodes.
        let mut swapped = bytes.clone();
        swapped[0] = 1;
        assert!(Intent::decode(&swapped).is_err());
        let mut short = bytes[..bytes.len() - 40].to_vec();
        short[0] = 2;
        assert!(Intent::decode(&short).is_err());
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn edge_case_corpus_matches_recorded_results() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/intent-corpus.txt"
    );
    let text = std::fs::read_to_string(path).expect("corpus");
    let mut cases = 0;
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('\t').collect();
        let [name, hex, expected] = fields[..] else {
            panic!("malformed corpus line: {line}");
        };
        let bytes = from_hex(hex);
        let got = match decode_and_check(&bytes) {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("err:{e:?}"),
        };
        assert_eq!(got, expected, "corpus case {name}");
        cases += 1;
    }
    assert!(cases >= 80, "only {cases} corpus cases");
}
