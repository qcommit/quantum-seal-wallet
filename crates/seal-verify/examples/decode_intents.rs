//! Differential-testing helper for `tests/differential.mjs`.
//!
//! Reads one lowercase-hex intent per stdin line (an empty line is the empty
//! intent) and writes exactly one line per input:
//!
//! * `ok {json}`: the decoded fields in a canonical JSON form (fixed key order,
//!   hex byte strings, decimal-string integers) plus the intent digest;
//! * `err Variant`: the `seal_wallet_core::Error` variant `Intent::decode` returned;
//! * `bad-input`: the line was not hexadecimal.
//!
//! It only calls the production decoder; it never re-implements the format.
use seal_slh_verify::Sha256;
use seal_wallet_core::{intent_digest, Action, Intent};
use sha2::{Digest, Sha256 as Hash};
use std::fmt::Write as _;
use std::io::{BufRead, BufWriter, Write};

struct NativeHash;
impl Sha256 for NativeHash {
    fn hashv(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Hash::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().into()
    }
}

fn keys(keys: &[[u8; 32]]) -> String {
    let list: Vec<String> = keys
        .iter()
        .map(|k| format!("\"{}\"", hex::encode(k)))
        .collect();
    format!("[{}]", list.join(","))
}

fn action(action: &Action) -> String {
    match action {
        Action::Transfer { to, lamports } => format!(
            r#"{{"kind":"transfer","to":"{}","lamports":"{lamports}"}}"#,
            hex::encode(to)
        ),
        Action::Rotate(p) => format!(
            r#"{{"kind":"rotate","threshold":{},"keys":{},"guardian":"{}","recoveryDelay":"{}"}}"#,
            p.owners.threshold,
            keys(&p.owners.keys[..usize::from(p.owners.count)]),
            hex::encode(p.guardian),
            p.recovery_delay
        ),
        Action::ProposeRecovery(o) => format!(
            r#"{{"kind":"recover","threshold":{},"keys":{}}}"#,
            o.threshold,
            keys(&o.keys[..usize::from(o.count)])
        ),
        Action::CancelRecovery => r#"{"kind":"cancelRecovery"}"#.into(),
        Action::Invoke {
            program,
            metas,
            data,
        } => {
            let metas: Vec<String> = metas
                .iter()
                .map(|m| {
                    format!(
                        r#"{{"key":"{}","writable":{},"signer":{}}}"#,
                        hex::encode(m.key),
                        m.writable,
                        m.signer
                    )
                })
                .collect();
            format!(
                r#"{{"kind":"invoke","program":"{}","metas":[{}],"data":"{}"}}"#,
                hex::encode(program),
                metas.join(","),
                hex::encode(data)
            )
        }
    }
}

fn describe(bytes: &[u8]) -> String {
    let intent = match Intent::decode(bytes) {
        Ok(intent) => intent,
        Err(e) => return format!("err {e:?}"),
    };
    let fee = match intent.fee {
        None => "null".to_string(),
        Some(f) => format!(
            r#"{{"to":"{}","lamports":"{}"}}"#,
            hex::encode(f.to),
            f.lamports
        ),
    };
    let mut out = String::with_capacity(512);
    let _ = write!(
        out,
        r#"ok {{"version":{},"genesis":"{}","program":"{}","wallet":"{}","epoch":"{}","nonce":"{}","expiry":"{}","action":{},"fee":{},"digest":"{}"}}"#,
        bytes[0],
        hex::encode(intent.genesis),
        hex::encode(intent.program),
        hex::encode(intent.wallet),
        intent.epoch,
        intent.nonce,
        intent.expiry,
        action(&intent.action),
        fee,
        hex::encode(intent_digest::<NativeHash>(bytes)),
    );
    out
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        match hex::decode(line.trim()) {
            Ok(bytes) => writeln!(out, "{}", describe(&bytes))?,
            Err(_) => writeln!(out, "bad-input")?,
        }
    }
    out.flush()
}
