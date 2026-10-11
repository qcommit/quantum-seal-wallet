use base64::{engine::general_purpose::STANDARD, Engine};
use seal_slh_verify::Sha256;
use seal_wallet_core::{intent_digest, Action, Intent, CONTEXT};
use serde::Deserialize;
use sha2::{Digest, Sha256 as Hash};
use std::{collections::BTreeMap, io::Read};

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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    format: String,
    algorithm: String,
    index: u8,
    intent: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
}
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("Noncanonical hexadecimal".into());
    }
    hex::decode(value).map_err(|e| e.to_string())
}
fn verify(text: &str, expected: &[u8]) -> Result<(Intent, u8), String> {
    if text.len() > 32768 || expected.len() != 32 {
        return Err("Input size or trusted key length is invalid".into());
    }
    let a: Approval = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if a.format != "quantum-seal/approval/1"
        || a.algorithm != "SLH-DSA-SHA2-128s"
        || ![0, 1, 2, 255].contains(&a.index)
    {
        return Err("Unsupported approval format".into());
    }
    let key = decode_hex(&a.public_key)?;
    if key != expected {
        return Err("Embedded key differs from the separately trusted key".into());
    }
    let bytes = decode_hex(&a.intent)?;
    let intent = Intent::decode(&bytes).map_err(|e| format!("Invalid intent: {e:?}"))?;
    let sig = STANDARD.decode(&a.signature).map_err(|e| e.to_string())?;
    if STANDARD.encode(&sig) != a.signature {
        return Err("Noncanonical base64".into());
    }
    seal_slh_verify::verify::<NativeHash>(
        &key,
        &sig,
        &intent_digest::<NativeHash>(&bytes),
        CONTEXT,
    )
    .map_err(|e| format!("Signature rejected: {e:?}"))?;
    Ok((intent, a.index))
}
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("seal-verify --proof FILE --key PUBLIC_KEY_HEX [--wallet WALLET_HEX] [--program PROGRAM_HEX]");
        return Ok(());
    }
    if args.len() % 2 != 0 {
        return Err("Expected flag/value pairs; use --help".into());
    }
    let mut flags = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !["--proof", "--key", "--wallet", "--program"].contains(&pair[0].as_str())
            || flags.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("Unknown or repeated flag".into());
        }
    }
    let path = flags.get("--proof").ok_or("--proof is required")?;
    let key = decode_hex(
        flags
            .get("--key")
            .ok_or("--key is required; an embedded key is not trusted")?,
    )?;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > 32768 {
        return Err("Proof must be a regular file of at most 32768 bytes".into());
    }
    let mut text = String::new();
    file.take(32769)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    let (intent, index) = verify(&text, &key)?;
    for (flag, actual) in [("--wallet", intent.wallet), ("--program", intent.program)] {
        if let Some(wanted) = flags.get(flag) {
            if decode_hex(wanted)? != actual {
                return Err(format!("{flag} does not match"));
            }
        }
    }
    let action = match intent.action {
        Action::Transfer { to, lamports } => {
            serde_json::json!({"kind":"transfer","to_hex":hex::encode(to),"lamports":lamports.to_string()})
        }
        Action::Rotate(_) => serde_json::json!({"kind":"rotate"}),
        Action::ProposeRecovery(_) => serde_json::json!({"kind":"recover"}),
        Action::CancelRecovery => serde_json::json!({"kind":"cancelRecovery"}),
        Action::Invoke {
            program,
            metas,
            data,
        } => {
            serde_json::json!({"kind":"invoke","program_hex":hex::encode(program),"account_count":metas.len(),"data_hex":hex::encode(data)})
        }
    };
    let output = serde_json::json!({"signature_valid":true,"trusted_key_matches":true,
        "wallet_hex":hex::encode(intent.wallet),"program_hex":hex::encode(intent.program),
        "genesis_hex":hex::encode(intent.genesis),"epoch":intent.epoch.to_string(),"nonce":intent.nonce.to_string(),
        "expiry_slot":intent.expiry.to_string(),"declared_index":index,"action":action,
        "scope":"One signature only. Does not establish current policy, quorum, freshness, or execution."});
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("REJECTED: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const PROOF: &str = include_str!("../../../fixtures/sdk-approval.json");
    #[test]
    fn noble_signature_verifies_with_independent_rust_implementation() {
        let a: Approval = serde_json::from_str(PROOF).unwrap();
        verify(PROOF, &decode_hex(&a.public_key).unwrap()).unwrap();
    }
    #[test]
    fn wrong_key_and_duplicate_json_fields_fail() {
        assert!(verify(PROOF, &[0; 32]).is_err());
        let a: Approval = serde_json::from_str(PROOF).unwrap();
        let key = decode_hex(&a.public_key).unwrap();
        let duplicate = PROOF.replacen('{', "{\"index\":0,", 1);
        assert!(verify(&duplicate, &key).is_err());
    }
}
