use borsh::{BorshDeserialize, BorshSerialize};
use seal_slh_verify::{Progress, Sha256, SIGNATURE_BYTES};
use seal_wallet_core::*;
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::{instruction as system_ix, program::ID as SYSTEM_ID};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

struct Hash;
impl Sha256 for Hash {
    fn hashv(parts: &[&[u8]]) -> [u8; 32] {
        solana_program::hash::hashv(parts).to_bytes()
    }
}

#[derive(Debug)]
enum Failure {
    Core(Error),
    Runtime(ProgramError),
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<ProgramError> for Failure {
    fn from(e: ProgramError) -> Self {
        Self::Runtime(e)
    }
}
type ChainResult<T> = core::result::Result<T, Failure>;

fn require(condition: bool, error: Error) -> ChainResult<()> {
    if condition {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn writable(a: &AccountInfo) -> ChainResult<()> {
    require(a.is_writable, Error::NotWritable)
}
fn signer(a: &AccountInfo) -> ChainResult<()> {
    require(a.is_signer, Error::MissingSigner)
}
fn exact(accounts: &[AccountInfo], len: usize) -> ChainResult<()> {
    require(accounts.len() == len, Error::AccountMismatch)
}
fn save<T: BorshSerialize>(account: &AccountInfo, value: &T, bytes: usize) -> ChainResult<()> {
    writable(account)?;
    let mut data = account.try_borrow_mut_data()?;
    require(data.len() >= bytes, Error::InvalidData)?;
    let mut target = &mut data[..bytes];
    value
        .serialize(&mut target)
        .map_err(|_| Error::InvalidData)?;
    require(target.is_empty(), Error::InvalidData)
}
fn load_wallet(program: &Pubkey, account: &AccountInfo) -> ChainResult<Wallet> {
    require(account.owner == program, Error::WrongOwner)?;
    let data = account.try_borrow_data()?;
    require(data.len() == WALLET_BYTES, Error::InvalidData)?;
    let w = Wallet::try_from_slice(&data).map_err(|_| Error::InvalidData)?;
    require(w.magic == WALLET_MAGIC, Error::InvalidData)?;
    require(!w.locked, Error::Locked)?;
    w.policy.validate()?;
    let expected = Pubkey::create_program_address(&[b"wallet", &w.id, &[w.bump]], program)
        .map_err(|_| Error::WrongAddress)?;
    require(expected == *account.key, Error::WrongAddress)?;
    Ok(w)
}
fn load_proof(program: &Pubkey, account: &AccountInfo) -> ChainResult<ProofHeader> {
    require(account.owner == program, Error::WrongOwner)?;
    let data = account.try_borrow_data()?;
    require(data.len() == PROOF_BYTES, Error::InvalidData)?;
    let h =
        ProofHeader::try_from_slice(&data[..PROOF_HEADER_BYTES]).map_err(|_| Error::InvalidData)?;
    require(
        h.magic == PROOF_MAGIC && h.stage <= 9 && usize::from(h.uploaded) <= SIGNATURE_BYTES,
        Error::InvalidData,
    )?;
    let expected = Pubkey::create_program_address(
        &[
            b"proof",
            &h.wallet,
            &h.digest,
            &[h.index],
            &h.uploader,
            &[h.bump],
        ],
        program,
    )
    .map_err(|_| Error::WrongAddress)?;
    require(expected == *account.key, Error::WrongAddress)?;
    Ok(h)
}
fn live_pair(
    program: &Pubkey,
    wallet: &AccountInfo,
    proof: &AccountInfo,
) -> ChainResult<(Wallet, ProofHeader)> {
    let w = load_wallet(program, wallet)?;
    let h = load_proof(program, proof)?;
    require(h.wallet == wallet.key.to_bytes(), Error::AccountMismatch)?;
    w.check_live(h.epoch, h.nonce, h.expiry, Clock::get()?.slot)?;
    require(h.key == w.policy.key(h.index)?, Error::Stale)?;
    Ok((w, h))
}

fn allocate<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    bytes: usize,
    seeds: &[&[u8]],
) -> ChainResult<()> {
    signer(payer)?;
    writable(payer)?;
    writable(target)?;
    require(
        payer.key != target.key && system.key == &SYSTEM_ID,
        Error::AccountMismatch,
    )?;
    require(
        target.owner == &SYSTEM_ID && target.data_is_empty(),
        Error::WrongOwner,
    )?;
    let rent = Rent::get()?.minimum_balance(bytes).max(1);
    let top_up = rent.saturating_sub(target.lamports());
    // allocate + assign tolerates unsolicited lamports sent to the PDA before initialization.
    if top_up != 0 {
        invoke(
            &system_ix::transfer(payer.key, target.key, top_up),
            &[payer.clone(), target.clone(), system.clone()],
        )?;
    }
    invoke_signed(
        &system_ix::allocate(target.key, bytes as u64),
        &[target.clone(), system.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_ix::assign(target.key, program),
        &[target.clone(), system.clone()],
        &[seeds],
    )?;
    Ok(())
}

fn initialize(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 3)?;
    let mut r = Reader(data);
    let genesis = r.array()?;
    let salt = r.array()?;
    let raw_policy = r.take(POLICY_BYTES)?;
    r.end()?;
    let policy = Policy::try_from_slice(raw_policy).map_err(|_| Error::InvalidData)?;
    policy.validate()?;
    require(genesis != [0; 32], Error::InvalidData)?;
    let id = wallet_id::<Hash>(&genesis, &salt, raw_policy);
    let (address, bump) = Pubkey::find_program_address(&[b"wallet", &id], program);
    require(address == *accounts[1].key, Error::WrongAddress)?;
    allocate(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[2],
        WALLET_BYTES,
        &[b"wallet", &id, &[bump]],
    )?;
    save(
        &accounts[1],
        &Wallet::new(bump, id, genesis, policy)?,
        WALLET_BYTES,
    )
}

fn begin(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 4)?;
    let w = load_wallet(program, &accounts[0])?;
    let mut r = Reader(data);
    let index = r.byte()?;
    let epoch = r.u64()?;
    let nonce = r.u64()?;
    let expiry = r.u64()?;
    let digest = r.array()?;
    r.end()?;
    w.check_live(epoch, nonce, expiry, Clock::get()?.slot)?;
    let key = w.policy.key(index)?;
    let wallet = accounts[0].key.to_bytes();
    let uploader = accounts[2].key.to_bytes();
    let (address, bump) =
        Pubkey::find_program_address(&[b"proof", &wallet, &digest, &[index], &uploader], program);
    require(address == *accounts[1].key, Error::WrongAddress)?;
    allocate(
        program,
        &accounts[2],
        &accounts[1],
        &accounts[3],
        PROOF_BYTES,
        &[b"proof", &wallet, &digest, &[index], &uploader, &[bump]],
    )?;
    let header = ProofHeader {
        magic: PROOF_MAGIC,
        bump,
        wallet,
        uploader,
        digest,
        key,
        epoch,
        nonce,
        expiry,
        index,
        uploaded: 0,
        stage: 0,
        root: [0; 16],
        tree: 0,
        leaf: 0,
    };
    save(&accounts[1], &header, PROOF_HEADER_BYTES)
}

fn append(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 3)?;
    let (_, mut h) = live_pair(program, &accounts[0], &accounts[1])?;
    signer(&accounts[2])?;
    writable(&accounts[1])?;
    require(
        accounts[2].key.to_bytes() == h.uploader,
        Error::AccountMismatch,
    )?;
    require(h.stage == 0, Error::WrongPhase)?;
    let mut r = Reader(data);
    let offset = usize::from(r.u16()?);
    let chunk = r.0;
    require(
        !chunk.is_empty() && chunk.len() <= MAX_CHUNK_BYTES,
        Error::InvalidData,
    )?;
    require(offset == usize::from(h.uploaded), Error::WrongOffset)?;
    let end = offset.checked_add(chunk.len()).ok_or(Error::Overflow)?;
    require(end <= SIGNATURE_BYTES, Error::InvalidData)?;
    {
        let mut dest = accounts[1].try_borrow_mut_data()?;
        dest[PROOF_HEADER_BYTES + offset..PROOF_HEADER_BYTES + end].copy_from_slice(chunk);
    }
    h.uploaded = end as u16;
    save(&accounts[1], &h, PROOF_HEADER_BYTES)
}

fn seal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 2)?;
    require(data.is_empty(), Error::InvalidData)?;
    let (_, mut h) = live_pair(program, &accounts[0], &accounts[1])?;
    require(
        h.stage == 0 && usize::from(h.uploaded) == SIGNATURE_BYTES,
        Error::WrongPhase,
    )?;
    h.stage = 1;
    save(&accounts[1], &h, PROOF_HEADER_BYTES)
}

fn step(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 2)?;
    require(data.is_empty(), Error::InvalidData)?;
    let (_, mut h) = live_pair(program, &accounts[0], &accounts[1])?;
    require(
        (1..=8).contains(&h.stage) && usize::from(h.uploaded) == SIGNATURE_BYTES,
        Error::WrongPhase,
    )?;
    let progress = {
        let data = accounts[1].try_borrow_data()?;
        let signature = &data[PROOF_HEADER_BYTES..];
        if h.stage == 1 {
            seal_slh_verify::start::<Hash>(&h.key, signature, &h.digest, CONTEXT)
        } else {
            seal_slh_verify::advance::<Hash>(
                &h.key,
                signature,
                Progress {
                    layer: h.stage - 2,
                    tree: h.tree,
                    leaf: h.leaf,
                    root: h.root,
                },
            )
        }
        .map_err(|_| Error::Signature)?
    };
    h.stage += 1;
    h.root = progress.root;
    h.tree = progress.tree;
    h.leaf = progress.leaf;
    save(&accounts[1], &h, PROOF_HEADER_BYTES)
}

fn execute(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    let mut r = Reader(data);
    let count = usize::from(r.byte()?);
    require(
        (1..=MAX_OWNERS).contains(&count) && accounts.len() > count,
        Error::AccountMismatch,
    )?;
    let intent_bytes = r.0;
    let intent = Intent::decode(intent_bytes)?;
    let wallet_account = &accounts[0];
    writable(wallet_account)?;
    let mut wallet = load_wallet(program, wallet_account)?;
    let slot = Clock::get()?.slot;
    wallet.check_live(intent.epoch, intent.nonce, intent.expiry, slot)?;
    require(
        intent.genesis == wallet.genesis
            && intent.program == program.to_bytes()
            && intent.wallet == wallet_account.key.to_bytes(),
        Error::IntentMismatch,
    )?;
    let digest = intent_digest::<Hash>(intent_bytes);
    let mut proofs = Vec::with_capacity(count);
    for account in &accounts[1..=count] {
        let h = load_proof(program, account)?;
        require(
            h.wallet == intent.wallet
                && h.epoch == intent.epoch
                && h.nonce == intent.nonce
                && h.expiry == intent.expiry,
            Error::IntentMismatch,
        )?;
        proofs.push(h);
    }
    let guardian = matches!(intent.action, Action::ProposeRecovery(_));
    authorize(&wallet, &proofs, &digest, guardian, slot)?;
    let is_proof = |key: &Pubkey| accounts[1..=count].iter().any(|p| p.key == key);
    // A version-2 intent names its fee-refund recipient; it is always the last account.
    let (remaining, fee_account) = match intent.fee {
        Some(fee) => {
            let (last, rest) = accounts[1 + count..]
                .split_last()
                .ok_or(Error::AccountMismatch)?;
            writable(last)?;
            require(
                last.key.to_bytes() == fee.to
                    && last.key != wallet_account.key
                    && !is_proof(last.key),
                Error::AccountMismatch,
            )?;
            (rest, Some((last, fee.lamports)))
        }
        None => (&accounts[1 + count..], None),
    };
    // A guardian proposal does not consume the owners' nonce, so it cannot invalidate
    // their in-flight approvals. It cannot be replayed: a second proposal is refused
    // while one is pending, and cancellation or finalization advances the nonce.
    if !guardian {
        wallet.bump_nonce()?;
    }
    match intent.action {
        Action::Transfer { to, lamports } => {
            exact(remaining, 1)?;
            let target = &remaining[0];
            writable(target)?;
            require(
                target.key.to_bytes() == to
                    && target.key != wallet_account.key
                    && !is_proof(target.key),
                Error::AccountMismatch,
            )?;
            let reserve = Rent::get()?.minimum_balance(WALLET_BYTES);
            let left = wallet_account
                .lamports()
                .checked_sub(lamports)
                .ok_or(Error::InsufficientFunds)?;
            require(left >= reserve, Error::InsufficientFunds)?;
            let received = target
                .lamports()
                .checked_add(lamports)
                .ok_or(Error::Overflow)?;
            **wallet_account.try_borrow_mut_lamports()? = left;
            **target.try_borrow_mut_lamports()? = received;
        }
        Action::Rotate(policy) => {
            exact(remaining, 0)?;
            wallet.rotate(policy)?;
        }
        Action::ProposeRecovery(owners) => {
            exact(remaining, 0)?;
            wallet.propose_recovery(owners, slot)?;
        }
        Action::CancelRecovery => {
            exact(remaining, 0)?;
            require(wallet.recovery_ready_at != 0, Error::NoRecovery)?;
            wallet.cancel_recovery();
        }
        Action::Invoke {
            program: target,
            metas,
            data,
        } => {
            exact(remaining, metas.len() + 1)?;
            let callee = &remaining[0];
            require(
                callee.key.to_bytes() == target && callee.executable && callee.key != program,
                Error::UnsafeInvocation,
            )?;
            let mut inner_metas = Vec::with_capacity(metas.len());
            let mut inner_accounts = Vec::with_capacity(metas.len() + 1);
            for (meta, account) in metas.iter().zip(&remaining[1..]) {
                require(
                    account.key.to_bytes() == meta.key
                        && !accounts[1..=count].iter().any(|p| p.key == account.key),
                    Error::AccountMismatch,
                )?;
                if meta.writable {
                    writable(account)?;
                }
                inner_metas.push(if meta.writable {
                    AccountMeta::new(*account.key, meta.signer)
                } else {
                    AccountMeta::new_readonly(*account.key, meta.signer)
                });
                inner_accounts.push(account.clone());
            }
            inner_accounts.push(callee.clone());
            wallet.locked = true;
            save(wallet_account, &wallet, WALLET_BYTES)?;
            let ix = Instruction {
                program_id: *callee.key,
                accounts: inner_metas,
                data,
            };
            invoke_signed(
                &ix,
                &inner_accounts,
                &[&[b"wallet", &wallet.id, &[wallet.bump]]],
            )?;
            wallet.locked = false;
        }
    }
    if let Some((recipient, lamports)) = fee_account {
        let reserve = Rent::get()?.minimum_balance(WALLET_BYTES);
        let left = wallet_account
            .lamports()
            .checked_sub(lamports)
            .ok_or(Error::InsufficientFunds)?;
        require(left >= reserve, Error::InsufficientFunds)?;
        let received = recipient
            .lamports()
            .checked_add(lamports)
            .ok_or(Error::Overflow)?;
        **wallet_account.try_borrow_mut_lamports()? = left;
        **recipient.try_borrow_mut_lamports()? = received;
    }
    save(wallet_account, &wallet, WALLET_BYTES)
}

fn finalize(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 1)?;
    require(data.is_empty(), Error::InvalidData)?;
    let mut w = load_wallet(program, &accounts[0])?;
    w.finalize_recovery(Clock::get()?.slot)?;
    save(&accounts[0], &w, WALLET_BYTES)
}
fn close(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ChainResult<()> {
    exact(accounts, 2)?;
    require(data.is_empty(), Error::InvalidData)?;
    let h = load_proof(program, &accounts[0])?;
    signer(&accounts[1])?;
    writable(&accounts[0])?;
    writable(&accounts[1])?;
    require(
        h.uploader == accounts[1].key.to_bytes() && accounts[0].key != accounts[1].key,
        Error::AccountMismatch,
    )?;
    let refund = accounts[1]
        .lamports()
        .checked_add(accounts[0].lamports())
        .ok_or(Error::Overflow)?;
    accounts[0].try_borrow_mut_data()?.fill(0);
    **accounts[0].try_borrow_mut_lamports()? = 0;
    **accounts[1].try_borrow_mut_lamports()? = refund;
    // Reassignment is unnecessary: the runtime reclaims a zero-lamport account.
    Ok(())
}

pub fn process_instruction(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let result = (|| -> ChainResult<()> {
        require(
            !data.is_empty() && data.len() <= MAX_INTENT_BYTES + 2,
            Error::InvalidData,
        )?;
        let (&tag, data) = data.split_first().ok_or(Error::InvalidData)?;
        match tag {
            0 => initialize(program, accounts, data),
            1 => begin(program, accounts, data),
            2 => append(program, accounts, data),
            3 => seal(program, accounts, data),
            4 => step(program, accounts, data),
            5 => execute(program, accounts, data),
            6 => finalize(program, accounts, data),
            7 => close(program, accounts, data),
            _ => Err(Error::InvalidData.into()),
        }
    })();
    result.map_err(|failure| match failure {
        Failure::Core(error) => ProgramError::Custom(error as u32),
        Failure::Runtime(error) => error,
    })
}
