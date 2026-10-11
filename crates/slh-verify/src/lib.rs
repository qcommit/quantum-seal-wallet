#![no_std]
#![forbid(unsafe_code)]
//! Verify-only SLH-DSA-SHA2-128s, FIPS 205 algorithms 8, 11, 14, 17 and 25.
//!
//! `Progress` is trusted intermediate state, not a proof. Persist it only in
//! program-owned storage after `start` or `advance` returns successfully.

pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 7_856;
pub const LAYERS: u8 = 7;
const N: usize = 16;
const FORS_BYTES: usize = 14 * 13 * N;
const XMSS_BYTES: usize = (35 + 9) * N;
const ZERO_PAD: [u8; 48] = [0; 48];

pub trait Sha256 {
    fn hashv(parts: &[&[u8]]) -> [u8; 32];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    PublicKeyLength,
    SignatureLength,
    ContextLength,
    InvalidProgress,
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub layer: u8,
    pub tree: u64,
    pub leaf: u32,
    pub root: [u8; N],
}

fn address(layer: u8, tree: u64, kind: u8, key: u32, height: u32, index: u32) -> [u8; 22] {
    let mut a = [0u8; 22];
    a[0] = layer;
    a[1..9].copy_from_slice(&tree.to_be_bytes());
    a[9] = kind;
    a[10..14].copy_from_slice(&key.to_be_bytes());
    a[14..18].copy_from_slice(&height.to_be_bytes());
    a[18..22].copy_from_slice(&index.to_be_bytes());
    a
}

fn thash<H: Sha256>(seed: &[u8], a: &[u8; 22], input: &[u8]) -> [u8; N] {
    let h = H::hashv(&[seed, &ZERO_PAD, a, input]);
    let mut out = [0; N];
    out.copy_from_slice(&h[..N]);
    out
}

fn parent<H: Sha256>(
    seed: &[u8],
    a: &[u8; 22],
    node: &[u8; N],
    auth: &[u8],
    right: bool,
) -> [u8; N] {
    let mut pair = [0; 2 * N];
    if right {
        pair[..N].copy_from_slice(auth);
        pair[N..].copy_from_slice(node);
    } else {
        pair[..N].copy_from_slice(node);
        pair[N..].copy_from_slice(auth);
    }
    thash::<H>(seed, a, &pair)
}

fn bits(input: &[u8], start: usize, count: usize) -> u32 {
    let mut x = 0;
    for bit in start..start + count {
        x = (x << 1) | u32::from((input[bit / 8] >> (7 - bit % 8)) & 1);
    }
    x
}

fn fors<H: Sha256>(seed: &[u8], sig: &[u8], digest: &[u8], tree: u64, leaf: u32) -> [u8; N] {
    let mut roots = [0; 14 * N];
    for i in 0..14 {
        let mut index = (i as u32) * 4_096 + bits(digest, i * 12, 12);
        let offset = i * 13 * N;
        let a = address(0, tree, 3, leaf, 0, index);
        let mut node = thash::<H>(seed, &a, &sig[offset..offset + N]);
        for height in 0..12 {
            let right = index & 1 != 0;
            index >>= 1;
            let a = address(0, tree, 3, leaf, (height + 1) as u32, index);
            let pos = offset + (height + 1) * N;
            node = parent::<H>(seed, &a, &node, &sig[pos..pos + N], right);
        }
        roots[i * N..(i + 1) * N].copy_from_slice(&node);
    }
    thash::<H>(seed, &address(0, tree, 4, leaf, 0, 0), &roots)
}

fn wots<H: Sha256>(
    seed: &[u8],
    sig: &[u8],
    message: &[u8; N],
    layer: u8,
    tree: u64,
    leaf: u32,
) -> [u8; N] {
    let mut digits = [0u8; 35];
    let mut checksum = 0u16;
    for i in 0..32 {
        digits[i] = if i & 1 == 0 {
            message[i / 2] >> 4
        } else {
            message[i / 2] & 15
        };
        checksum += u16::from(15 - digits[i]);
    }
    digits[32] = (checksum >> 8) as u8;
    digits[33] = ((checksum >> 4) & 15) as u8;
    digits[34] = (checksum & 15) as u8;
    let mut endpoints = [0; 35 * N];
    for (chain, &digit) in digits.iter().enumerate() {
        let mut node = [0; N];
        node.copy_from_slice(&sig[chain * N..(chain + 1) * N]);
        for step in digit..15 {
            let a = address(layer, tree, 0, leaf, chain as u32, u32::from(step));
            node = thash::<H>(seed, &a, &node);
        }
        endpoints[chain * N..(chain + 1) * N].copy_from_slice(&node);
    }
    thash::<H>(seed, &address(layer, tree, 1, leaf, 0, 0), &endpoints)
}

fn xmss<H: Sha256>(seed: &[u8], sig: &[u8], progress: Progress) -> [u8; N] {
    let Progress {
        layer,
        tree,
        leaf,
        root,
    } = progress;
    let mut node = wots::<H>(seed, &sig[..35 * N], &root, layer, tree, leaf);
    let mut index = leaf;
    for height in 0..9 {
        let right = index & 1 != 0;
        index >>= 1;
        let a = address(layer, tree, 2, 0, (height + 1) as u32, index);
        let pos = (35 + height) * N;
        node = parent::<H>(seed, &a, &node, &sig[pos..pos + N], right);
    }
    node
}

fn lengths(public_key: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(Error::PublicKeyLength);
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(Error::SignatureLength);
    }
    Ok(())
}

/// Hash the pure-mode message and recover the FORS public key.
/// This is not successful verification until all seven XMSS layers pass.
pub fn start<H: Sha256>(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Progress, Error> {
    lengths(public_key, signature)?;
    if context.len() > 255 {
        return Err(Error::ContextLength);
    }
    let prefix = [0, context.len() as u8];
    let r = &signature[..N];
    let seed = &public_key[..N];
    let inner = H::hashv(&[r, public_key, &prefix, context, message]);
    // m=30: one MGF1-SHA-256 block suffices; the counter is big-endian zero.
    let digest = H::hashv(&[r, seed, &inner, &[0; 4]]);
    let mut tree = 0u64;
    for &byte in &digest[21..28] {
        tree = (tree << 8) | u64::from(byte);
    }
    tree &= (1u64 << 54) - 1;
    let leaf = u32::from(u16::from_be_bytes([digest[28], digest[29]]) & 511);
    let root = fors::<H>(
        seed,
        &signature[N..N + FORS_BYTES],
        &digest[..21],
        tree,
        leaf,
    );
    Ok(Progress {
        layer: 0,
        tree,
        leaf,
        root,
    })
}

/// Recover one XMSS root. The final step also checks PK.root.
/// Rejects completed or structurally impossible intermediate states.
pub fn advance<H: Sha256>(
    public_key: &[u8],
    signature: &[u8],
    progress: Progress,
) -> Result<Progress, Error> {
    lengths(public_key, signature)?;
    if progress.layer >= LAYERS || progress.leaf >= 512 {
        return Err(Error::InvalidProgress);
    }
    let tree_bits = 9 * u32::from(6 - progress.layer);
    if progress.tree >> tree_bits != 0 {
        return Err(Error::InvalidProgress);
    }
    let offset = N + FORS_BYTES + usize::from(progress.layer) * XMSS_BYTES;
    let root = xmss::<H>(
        &public_key[..N],
        &signature[offset..offset + XMSS_BYTES],
        progress,
    );
    let next = Progress {
        layer: progress.layer + 1,
        tree: progress.tree >> 9,
        leaf: (progress.tree & 511) as u32,
        root,
    };
    if next.layer == LAYERS {
        let mismatch = root
            .iter()
            .zip(&public_key[N..])
            .fold(0u8, |x, (a, b)| x | (a ^ b));
        if mismatch != 0 {
            return Err(Error::InvalidSignature);
        }
    }
    Ok(next)
}

pub fn verify<H: Sha256>(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<(), Error> {
    let mut progress = start::<H>(public_key, signature, message, context)?;
    while progress.layer < LAYERS {
        progress = advance::<H>(public_key, signature, progress)?;
    }
    Ok(())
}
