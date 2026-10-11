#![forbid(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};
use seal_slh_verify::Sha256;

pub const MAX_OWNERS: usize = 3;
pub const POLICY_BYTES: usize = 138;
pub const OWNERS_BYTES: usize = 98;
pub const WALLET_BYTES: usize = 334;
pub const PROOF_HEADER_BYTES: usize = 193;
pub const PROOF_BYTES: usize = PROOF_HEADER_BYTES + seal_slh_verify::SIGNATURE_BYTES;
pub const MAX_INTENT_BYTES: usize = 850;
pub const MAX_CHUNK_BYTES: usize = 768;
pub const GUARDIAN_INDEX: u8 = 255;
pub const CONTEXT: &[u8] = b"QuantumSeal.Wallet.v1";
pub const WALLET_MAGIC: [u8; 8] = *b"QSWAL001";
pub const PROOF_MAGIC: [u8; 8] = *b"QSPRF001";
/// Shortest guardian recovery delay on test clusters (~1 minute).
pub const MIN_RECOVERY_DELAY: u64 = 150;
/// Shortest guardian recovery delay on mainnet (~1 day), long enough for owners to veto.
pub const MIN_MAINNET_RECOVERY_DELAY: u64 = 216_000;
pub const MAX_RECOVERY_DELAY: u64 = 2_000_000;
/// Approvals may not expire further than this many slots ahead (~1 day).
pub const MAX_EXPIRY_HORIZON: u64 = 216_000;
/// Upper bound on the fee reimbursement a version-2 intent may pay to its fee key.
pub const MAX_FEE_REFUND: u64 = 10_000_000;
/// Solana mainnet-beta genesis hash.
pub const MAINNET_GENESIS: [u8; 32] = [
    69, 41, 105, 152, 166, 248, 226, 167, 132, 219, 93, 159, 149, 225, 143, 194, 63, 112, 68, 26,
    16, 57, 68, 104, 1, 8, 152, 121, 176, 140, 126, 240,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Error {
    InvalidData = 7000,
    InvalidPolicy,
    WrongOwner,
    WrongAddress,
    MissingSigner,
    NotWritable,
    WrongPhase,
    WrongOffset,
    Expired,
    Stale,
    Signature,
    Threshold,
    DuplicateApproval,
    IntentMismatch,
    InsufficientFunds,
    Overflow,
    RecoveryDisabled,
    RecoveryPending,
    NoRecovery,
    RecoveryDelay,
    UnsafeInvocation,
    Locked,
    AccountMismatch,
    ExpiryTooFar,
    InvalidFeeRefund,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Owners {
    pub count: u8,
    pub threshold: u8,
    pub keys: [[u8; 32]; MAX_OWNERS],
}

impl Owners {
    pub fn validate(&self) -> Result<()> {
        let count = usize::from(self.count);
        if count == 0 || count > MAX_OWNERS || self.threshold == 0 || self.threshold > self.count {
            return Err(Error::InvalidPolicy);
        }
        for (i, key) in self.keys.iter().enumerate() {
            if i < count {
                if *key == [0; 32] || self.keys[..i].contains(key) {
                    return Err(Error::InvalidPolicy);
                }
            } else if *key != [0; 32] {
                return Err(Error::InvalidPolicy);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Policy {
    pub owners: Owners,
    pub guardian: [u8; 32],
    pub recovery_delay: u64,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        self.owners.validate()?;
        if self.guardian == [0; 32] {
            if self.recovery_delay != 0 {
                return Err(Error::InvalidPolicy);
            }
        } else if !(MIN_RECOVERY_DELAY..=MAX_RECOVERY_DELAY).contains(&self.recovery_delay)
            || self.owners.keys.contains(&self.guardian)
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
    /// Cluster-aware validation: mainnet wallets need a recovery delay owners can react to.
    pub fn validate_for(&self, genesis: &[u8; 32]) -> Result<()> {
        self.validate()?;
        if *genesis == MAINNET_GENESIS
            && self.guardian != [0; 32]
            && self.recovery_delay < MIN_MAINNET_RECOVERY_DELAY
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
    pub fn key(&self, index: u8) -> Result<[u8; 32]> {
        if index == GUARDIAN_INDEX {
            if self.guardian == [0; 32] {
                return Err(Error::RecoveryDisabled);
            }
            return Ok(self.guardian);
        }
        if index >= self.owners.count {
            return Err(Error::InvalidPolicy);
        }
        Ok(self.owners.keys[usize::from(index)])
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Wallet {
    pub magic: [u8; 8],
    pub bump: u8,
    pub id: [u8; 32],
    pub genesis: [u8; 32],
    pub policy: Policy,
    pub epoch: u64,
    pub nonce: u64,
    pub recovery_ready_at: u64,
    pub recovery_owners: Owners,
    pub locked: bool,
}

impl Wallet {
    pub fn new(bump: u8, id: [u8; 32], genesis: [u8; 32], policy: Policy) -> Result<Self> {
        policy.validate_for(&genesis)?;
        Ok(Self {
            magic: WALLET_MAGIC,
            bump,
            id,
            genesis,
            policy,
            epoch: 0,
            nonce: 0,
            recovery_ready_at: 0,
            recovery_owners: Owners::default(),
            locked: false,
        })
    }
    pub fn check_live(&self, epoch: u64, nonce: u64, expiry: u64, slot: u64) -> Result<()> {
        if self.locked {
            return Err(Error::Locked);
        }
        if epoch != self.epoch || nonce != self.nonce {
            return Err(Error::Stale);
        }
        if expiry < slot {
            return Err(Error::Expired);
        }
        if expiry > slot.saturating_add(MAX_EXPIRY_HORIZON) {
            return Err(Error::ExpiryTooFar);
        }
        Ok(())
    }
    pub fn bump_nonce(&mut self) -> Result<()> {
        self.nonce = self.nonce.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }
    pub fn cancel_recovery(&mut self) {
        self.recovery_ready_at = 0;
        self.recovery_owners = Owners::default();
    }
    pub fn rotate(&mut self, policy: Policy) -> Result<()> {
        policy.validate_for(&self.genesis)?;
        let epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
        self.policy = policy;
        self.epoch = epoch;
        self.cancel_recovery();
        Ok(())
    }
    pub fn propose_recovery(&mut self, owners: Owners, slot: u64) -> Result<()> {
        owners.validate()?;
        if self.policy.guardian == [0; 32] {
            return Err(Error::RecoveryDisabled);
        }
        if owners.keys.contains(&self.policy.guardian) {
            return Err(Error::InvalidPolicy);
        }
        if self.recovery_ready_at != 0 {
            return Err(Error::RecoveryPending);
        }
        self.recovery_ready_at = slot
            .checked_add(self.policy.recovery_delay)
            .ok_or(Error::Overflow)?;
        self.recovery_owners = owners;
        Ok(())
    }
    pub fn finalize_recovery(&mut self, slot: u64) -> Result<()> {
        if self.locked {
            return Err(Error::Locked);
        }
        if self.recovery_ready_at == 0 {
            return Err(Error::NoRecovery);
        }
        if slot < self.recovery_ready_at {
            return Err(Error::RecoveryDelay);
        }
        let policy = Policy {
            owners: self.recovery_owners,
            ..self.policy
        };
        // Compute both counters before mutating the state.
        let nonce = self.nonce.checked_add(1).ok_or(Error::Overflow)?;
        self.rotate(policy)?;
        self.nonce = nonce;
        Ok(())
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ProofHeader {
    pub magic: [u8; 8],
    pub bump: u8,
    pub wallet: [u8; 32],
    pub uploader: [u8; 32],
    pub digest: [u8; 32],
    pub key: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expiry: u64,
    pub index: u8,
    pub uploaded: u16,
    pub stage: u8,
    pub root: [u8; 16],
    pub tree: u64,
    pub leaf: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub key: [u8; 32],
    pub writable: bool,
    pub signer: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Transfer {
        to: [u8; 32],
        lamports: u64,
    },
    Rotate(Policy),
    ProposeRecovery(Owners),
    CancelRecovery,
    Invoke {
        program: [u8; 32],
        metas: Vec<Meta>,
        data: Vec<u8>,
    },
}

/// Version-2 intents reimburse the account that paid the transaction fees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRefund {
    pub to: [u8; 32],
    pub lamports: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub genesis: [u8; 32],
    pub program: [u8; 32],
    pub wallet: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expiry: u64,
    pub action: Action,
    pub fee: Option<FeeRefund>,
}

pub struct Reader<'a>(pub &'a [u8]);
impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::InvalidData);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidData)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidData)
        }
    }
}

impl Intent {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(Error::InvalidData);
        }
        let mut r = Reader(bytes);
        let version = r.byte()?;
        if version != 1 && version != 2 {
            return Err(Error::InvalidData);
        }
        let genesis = r.array()?;
        let program = r.array()?;
        let wallet = r.array()?;
        let epoch = r.u64()?;
        let nonce = r.u64()?;
        let expiry = r.u64()?;
        let action = match r.byte()? {
            0 => {
                let to = r.array()?;
                let lamports = r.u64()?;
                if lamports == 0 {
                    return Err(Error::InvalidData);
                }
                Action::Transfer { to, lamports }
            }
            1 => {
                let p = Policy::try_from_slice(r.take(POLICY_BYTES)?)
                    .map_err(|_| Error::InvalidData)?;
                p.validate()?;
                Action::Rotate(p)
            }
            2 => {
                let o = Owners::try_from_slice(r.take(OWNERS_BYTES)?)
                    .map_err(|_| Error::InvalidData)?;
                o.validate()?;
                Action::ProposeRecovery(o)
            }
            3 => Action::CancelRecovery,
            4 => {
                let target = r.array()?;
                if target == program {
                    return Err(Error::UnsafeInvocation);
                }
                let count = usize::from(r.byte()?);
                if count > 12 {
                    return Err(Error::InvalidData);
                }
                let mut metas: Vec<Meta> = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = r.array()?;
                    let flags = r.byte()?;
                    if flags > 3 || metas.iter().any(|m| m.key == key) {
                        return Err(Error::InvalidData);
                    }
                    let writable = flags & 1 != 0;
                    let signer = flags & 2 != 0;
                    if (signer && key != wallet) || (key == wallet && (!signer || writable)) {
                        return Err(Error::UnsafeInvocation);
                    }
                    metas.push(Meta {
                        key,
                        writable,
                        signer,
                    });
                }
                let len = usize::from(r.u16()?);
                if len > 256 {
                    return Err(Error::InvalidData);
                }
                Action::Invoke {
                    program: target,
                    metas,
                    data: r.take(len)?.to_vec(),
                }
            }
            _ => return Err(Error::InvalidData),
        };
        let fee = if version == 2 {
            let to = r.array()?;
            let lamports = r.u64()?;
            if lamports == 0
                || lamports > MAX_FEE_REFUND
                || to == [0; 32]
                || to == wallet
                || to == program
            {
                return Err(Error::InvalidFeeRefund);
            }
            Some(FeeRefund { to, lamports })
        } else {
            None
        };
        r.end()?;
        Ok(Self {
            genesis,
            program,
            wallet,
            epoch,
            nonce,
            expiry,
            action,
            fee,
        })
    }
}

pub fn intent_digest<H: Sha256>(bytes: &[u8]) -> [u8; 32] {
    H::hashv(&[b"QuantumSeal/Intent/v1", bytes])
}

pub fn wallet_id<H: Sha256>(genesis: &[u8; 32], salt: &[u8; 32], policy_bytes: &[u8]) -> [u8; 32] {
    H::hashv(&[b"QuantumSeal/Wallet/v1", genesis, salt, policy_bytes])
}

pub fn authorize(
    wallet: &Wallet,
    proofs: &[ProofHeader],
    digest: &[u8; 32],
    guardian: bool,
    slot: u64,
) -> Result<()> {
    if proofs.is_empty() || proofs.len() > MAX_OWNERS {
        return Err(Error::Threshold);
    }
    let mut mask = 0u8;
    for proof in proofs {
        wallet.check_live(proof.epoch, proof.nonce, proof.expiry, slot)?;
        if proof.stage != 9 || usize::from(proof.uploaded) != seal_slh_verify::SIGNATURE_BYTES {
            return Err(Error::WrongPhase);
        }
        if proof.digest != *digest {
            return Err(Error::IntentMismatch);
        }
        if proof.key != wallet.policy.key(proof.index)? {
            return Err(Error::Stale);
        }
        if guardian {
            if proofs.len() != 1 || proof.index != GUARDIAN_INDEX {
                return Err(Error::Threshold);
            }
        } else {
            if proof.index >= wallet.policy.owners.count {
                return Err(Error::Threshold);
            }
            let bit = 1 << proof.index;
            if mask & bit != 0 {
                return Err(Error::DuplicateApproval);
            }
            mask |= bit;
        }
    }
    if !guardian && mask.count_ones() < u32::from(wallet.policy.owners.threshold) {
        return Err(Error::Threshold);
    }
    Ok(())
}
