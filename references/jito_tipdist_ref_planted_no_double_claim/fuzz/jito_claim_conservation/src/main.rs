// invariant_claim_amount_conservation
//
// cf-invariants-jito Phase-2 fixture — claim_amount_conservation class.
// Target: Crucible v0.2.0 (asymmetric-research/crucible).
// Source: Heuristic (suggester v0.2.0). No AI suggestion in this candidate.
//
// Per successful claim, the TipDistributionAccount lamport balance must
// decrease by EXACTLY `amount` and the claimant balance must increase
// by EXACTLY `amount`. No skim, no double-debit.
//
// Fixture-side bookkeeping: `expected_tda_debited: u64` and
// `expected_claimant_credited: u64` are walked through every successful
// `action_claim` and asserted against on-chain lamport deltas after each
// step.
//
// Setup uses a single-leaf merkle tree (root == leaf, proof == empty)
// to avoid off-chain multi-leaf tree construction. The TDA is pre-baked
// via `write_anchor_account` with the merkle root already uploaded,
// sidestepping the `initialize_tip_distribution_account` flow (which
// would require a synthetic vote account with valid VoteState bytes).

#![allow(unused_imports)]

use crucible_fuzzer::anchor_lang::system_program;
use crucible_fuzzer::*;
use ::jito_tip_distribution::*;
use ::jito_tip_distribution::state::{
    ClaimStatus, Config, MerkleRoot, TipDistributionAccount,
};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_sha256_hasher::hashv;
use solana_signer::Signer;
use std::rc::Rc;

const INITIAL_BALANCE: u64 = 10_000_000_000;
/// Single-leaf claim amount (fixed at setup time because the merkle leaf
/// commits the amount). Picked at 1 SOL — large enough that a 1-lamport
/// drift is conspicuous, small enough that overflow checks are safe.
const CLAIM_AMOUNT: u64 = 1_000_000_000;
/// Tip pool seeded into the TDA. Large enough to absorb several
/// hypothetical claims plus rent-exempt minimum.
const TDA_INITIAL_LAMPORTS: u64 = 100_000_000_000;

#[derive(Clone)]
struct JitoClaimConservationFixture {
    ctx: TestContext,
    program_id: Pubkey,
    initializer: Rc<Keypair>,
    config_pda: Pubkey,
    tda_pubkey: Pubkey,
    /// The off-chain pipeline authority allowed to authorize a claim
    /// (matches `tda.merkle_root_upload_authority`).
    merkle_root_upload_authority: Rc<Keypair>,
    /// The single claimant whose (pubkey, amount) leaf lives in the
    /// pre-uploaded merkle root.
    claimant: Rc<Keypair>,
    /// The signer paying for the ClaimStatus account rent.
    payer: Rc<Keypair>,
    /// Fixture-side ledger of cumulative debit/credit. Walked through
    /// every successful claim; asserted against on-chain lamport
    /// deltas in the invariant.
    expected_tda_debited: u64,
    expected_claimant_credited: u64,
    /// Snapshot of TDA + claimant lamports at setup time, used as the
    /// invariant's anchor reference.
    tda_initial_lamports: u64,
    claimant_initial_lamports: u64,
}

#[fuzz_fixture]
impl JitoClaimConservationFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        ctx.add_program(
            &program_id,
            "../../target/deploy/jito_tip_distribution.so",
        )
        .unwrap();

        // Funded initializer signer (pays Config rent on init).
        let initializer = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(initializer.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create()
            .unwrap();

        let authority = Keypair::new();
        let expired_funds_account = Keypair::new().pubkey();

        let (config_pda, config_bump) =
            Pubkey::find_program_address(&[Config::SEED], &program_id);

        // Seed Config via the program's own initialize ix.
        ctx.program(program_id)
            .call(instruction::Initialize {
                authority: authority.pubkey(),
                expired_funds_account,
                num_epochs_valid: 3,
                max_validator_commission_bps: 1000,
                bump: config_bump,
            })
            .accounts(accounts::Initialize {
                config: config_pda,
                system_program: system_program::ID,
                initializer: initializer.pubkey(),
            })
            .signers(&[&*initializer])
            .send()
            .unwrap();

        // Claim flow keypairs.
        let merkle_root_upload_authority = Rc::new(Keypair::new());
        let claimant = Rc::new(Keypair::new());
        let payer = Rc::new(Keypair::new());

        // Fund the payer (writes ClaimStatus rent), claimant (receives the
        // transferred lamports), AND the merkle_root_upload_authority (it
        // signs the tx as the first signer → it's the SVM fee payer, and a
        // fee payer that doesn't exist on-chain hard-fails the tx with
        // AccountNotFound BEFORE any program code runs — explaining the
        // 0% edge coverage in CI run 26850577144).
        ctx.create_account()
            .pubkey(payer.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create()
            .unwrap();
        ctx.create_account()
            .pubkey(claimant.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create()
            .unwrap();
        ctx.create_account()
            .pubkey(merkle_root_upload_authority.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create()
            .unwrap();
        let claimant_initial_lamports = INITIAL_BALANCE;

        // Single-leaf merkle tree:
        //   leaf = hashv(&[&[0u8], &hashv(&[claimant.to_bytes(), amount.to_le_bytes()]).to_bytes()]).to_bytes()
        //   root = leaf (single-leaf tree's root IS the leaf hash)
        //   proof = vec![] (no sibling steps to fold)
        // The merkle_proof::verify short-circuits: computed_hash = leaf,
        // no proof elements, returns computed_hash == root → true.
        let inner_hash = hashv(&[
            &claimant.pubkey().to_bytes() as &[u8],
            &CLAIM_AMOUNT.to_le_bytes() as &[u8],
        ])
        .to_bytes();
        let leaf = hashv(&[&[0u8] as &[u8], &inner_hash as &[u8]]).to_bytes();
        let merkle_root_bytes: [u8; 32] = leaf;

        // Pre-bake TDA. Use a synthetic vote-account pubkey since the
        // claim ix doesn't validate seeds against the TDA pubkey (the
        // seed constraint is only on `claim_status`, not the TDA).
        let synthetic_vote_account = Keypair::new().pubkey();
        let tda_pubkey = Keypair::new().pubkey();
        let tda_state = TipDistributionAccount {
            validator_vote_account: synthetic_vote_account,
            merkle_root_upload_authority: merkle_root_upload_authority.pubkey(),
            merkle_root: Some(MerkleRoot {
                root: merkle_root_bytes,
                max_total_claim: CLAIM_AMOUNT * 10,
                max_num_nodes: 10,
                total_funds_claimed: 0,
                num_nodes_claimed: 0,
            }),
            epoch_created_at: 0,
            validator_commission_bps: 0,
            expires_at: u64::MAX, // never expires within the fuzz horizon
            bump: 0, // not seed-validated in claim's accounts struct
        };
        // Create the account shell (program-owned, generously funded)
        // then write the discriminator + serialized state.
        ctx.create_account()
            .pubkey(tda_pubkey)
            .lamports(TDA_INITIAL_LAMPORTS)
            .owner(program_id)
            .size(TipDistributionAccount::SIZE)
            .create()
            .unwrap();
        ctx.write_anchor_account(&tda_pubkey, &tda_state).unwrap();
        let tda_initial_lamports = TDA_INITIAL_LAMPORTS;

        Self {
            ctx,
            program_id,
            initializer,
            config_pda,
            tda_pubkey,
            merkle_root_upload_authority,
            claimant,
            payer,
            expected_tda_debited: 0,
            expected_claimant_credited: 0,
            tda_initial_lamports,
            claimant_initial_lamports,
        }
    }

    /// Single-leaf claim. Succeeds at most once (ClaimStatus PDA is
    /// `init`-constrained per (claimant, TDA) pair); after success the
    /// fixture-side ledger advances and the invariant_test must hold.
    pub fn action_claim(&mut self) -> bool {
        let (claim_status_pda, claim_status_bump) = Pubkey::find_program_address(
            &[
                ClaimStatus::SEED,
                self.claimant.pubkey().as_ref(),
                self.tda_pubkey.as_ref(),
            ],
            &self.program_id,
        );

        let result = self.ctx
            .program(self.program_id)
            .call(instruction::Claim {
                bump: claim_status_bump,
                amount: CLAIM_AMOUNT,
                proof: vec![], // single-leaf tree → empty proof
            })
            .accounts(accounts::Claim {
                config: self.config_pda,
                tip_distribution_account: self.tda_pubkey,
                merkle_root_upload_authority: self.merkle_root_upload_authority.pubkey(),
                claim_status: claim_status_pda,
                claimant: self.claimant.pubkey(),
                payer: self.payer.pubkey(),
                system_program: system_program::ID,
            })
            .signers(&[&*self.merkle_root_upload_authority, &*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        if result {
            self.expected_tda_debited =
                self.expected_tda_debited.saturating_add(CLAIM_AMOUNT);
            self.expected_claimant_credited = self
                .expected_claimant_credited
                .saturating_add(CLAIM_AMOUNT);
        }
        result
    }
}

// claim_amount_conservation invariant.
//
// After every action, the on-chain TDA + claimant lamport deltas must
// equal the fixture-side ledger. A planted off-by-one in
// state.rs::transfer_lamports (debit by amount+1 / credit by amount)
// surfaces as `tda.lamports < initial - expected_debited`.
#[invariant_test]
fn invariant_claim_amount_conservation(
    fixture: &mut JitoClaimConservationFixture,
) {
    let tda_account = fixture
        .ctx
        .read_account(&fixture.tda_pubkey)
        .expect("TDA account exists (pre-baked in setup)");
    let claimant_account = fixture
        .ctx
        .read_account(&fixture.claimant.pubkey())
        .expect("claimant account exists (pre-funded in setup)");

    let expected_tda = fixture
        .tda_initial_lamports
        .saturating_sub(fixture.expected_tda_debited);
    let expected_claimant = fixture
        .claimant_initial_lamports
        .saturating_add(fixture.expected_claimant_credited);

    fuzz_assert_eq!(
        tda_account.lamports, expected_tda,
        "TDA lamport drift: on-chain={} expected={} (debited={})",
        tda_account.lamports, expected_tda, fixture.expected_tda_debited
    );
    fuzz_assert_eq!(
        claimant_account.lamports, expected_claimant,
        "claimant lamport drift: on-chain={} expected={} (credited={})",
        claimant_account.lamports, expected_claimant, fixture.expected_claimant_credited
    );
}
