// invariant_no_double_claim
//
// cf-invariants-jito Phase-2 fixture — no_double_claim class.
// Target: Crucible v0.2.0 (asymmetric-research/crucible).
// Source: Heuristic (suggester v0.2.0). No AI suggestion in this candidate.
//
// For any (claimant, TDA) pair, the `claim` instruction must succeed
// AT MOST ONCE. The fixture's `action_double_claim` calls claim twice
// back-to-back; the invariant is "TDA lost at most ONE claim's worth
// of lamports." A planted bypass that allows the second call to land
// (e.g. `init` → `init_if_needed` plus dropping the `is_claimed`
// runtime gate) surfaces as TDA losing 2× the per-claim amount.
//
// Mirror of the cf-invariants-anchor sticky-flag pattern. Setup uses
// the same single-leaf merkle tree as jito_claim_conservation/.

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
const CLAIM_AMOUNT: u64 = 1_000_000_000;
const TDA_INITIAL_LAMPORTS: u64 = 100_000_000_000;

#[derive(Clone)]
struct JitoNoDoubleClaimFixture {
    ctx: TestContext,
    program_id: Pubkey,
    initializer: Rc<Keypair>,
    config_pda: Pubkey,
    tda_pubkey: Pubkey,
    merkle_root_upload_authority: Rc<Keypair>,
    claimant: Rc<Keypair>,
    payer: Rc<Keypair>,
    /// Count of successful claims observed (across all action_*).
    /// The invariant fails iff this ever exceeds 1.
    successful_claim_count: u32,
    tda_initial_lamports: u64,
}

#[fuzz_fixture]
impl JitoNoDoubleClaimFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        ctx.add_program(
            &program_id,
            "../../target/deploy/jito_tip_distribution.so",
        )
        .unwrap();

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

        let merkle_root_upload_authority = Rc::new(Keypair::new());
        let claimant = Rc::new(Keypair::new());
        let payer = Rc::new(Keypair::new());

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

        // Single-leaf merkle tree for (claimant, CLAIM_AMOUNT).
        let inner_hash = hashv(&[
            &claimant.pubkey().to_bytes() as &[u8],
            &CLAIM_AMOUNT.to_le_bytes() as &[u8],
        ])
        .to_bytes();
        let merkle_root_bytes: [u8; 32] =
            hashv(&[&[0u8] as &[u8], &inner_hash as &[u8]]).to_bytes();

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
            expires_at: u64::MAX,
            bump: 0,
        };
        ctx.create_account()
            .pubkey(tda_pubkey)
            .lamports(TDA_INITIAL_LAMPORTS)
            .owner(program_id)
            .size(TipDistributionAccount::SIZE)
            .create()
            .unwrap();
        ctx.write_anchor_account(&tda_pubkey, &tda_state).unwrap();

        Self {
            ctx,
            program_id,
            initializer,
            config_pda,
            tda_pubkey,
            merkle_root_upload_authority,
            claimant,
            payer,
            successful_claim_count: 0,
            tda_initial_lamports: TDA_INITIAL_LAMPORTS,
        }
    }

    /// Calls `claim` once. Bookkeeping increments only on success. The
    /// fuzzer is expected to call this multiple times — the invariant
    /// is: at most ONE call ever succeeds for this (claimant, TDA).
    pub fn action_claim(&mut self) -> bool {
        let (claim_status_pda, claim_status_bump) = Pubkey::find_program_address(
            &[
                ClaimStatus::SEED,
                self.claimant.pubkey().as_ref(),
                self.tda_pubkey.as_ref(),
            ],
            &self.program_id,
        );
        let ok = self.ctx
            .program(self.program_id)
            .call(instruction::Claim {
                bump: claim_status_bump,
                amount: CLAIM_AMOUNT,
                proof: vec![],
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
        if ok {
            self.successful_claim_count =
                self.successful_claim_count.saturating_add(1);
        }
        true
    }
}

// no_double_claim invariant.
//
// At most ONE claim can ever succeed for a given (claimant, TDA) pair.
// Equivalently, the TDA never loses more than 1× CLAIM_AMOUNT.
//
// Clean: second action_claim fails (init constraint catches the
// pre-existing ClaimStatus PDA, or — in a hypothetical bypass — the
// runtime `is_claimed` gate catches the replay). Sticky count stays at 1.
//
// Planted (init → init_if_needed + dropped runtime gate): second call
// silently succeeds, count climbs past 1, TDA bleeds 2× the claim
// amount. Invariant trips.
#[invariant_test]
fn invariant_no_double_claim(fixture: &mut JitoNoDoubleClaimFixture) {
    fuzz_assert!(
        fixture.successful_claim_count <= 1,
        "double-claim observed: {} successful claims on (claimant={}, TDA={})",
        fixture.successful_claim_count, fixture.claimant.pubkey(), fixture.tda_pubkey
    );

    // Belt-and-suspenders lamport check (catches a planted bypass that
    // somehow flipped is_claimed without re-debiting — defensive depth).
    let tda_account = fixture
        .ctx
        .read_account(&fixture.tda_pubkey)
        .expect("TDA exists");
    let max_legitimate_debit = CLAIM_AMOUNT; // one claim at most
    let min_legitimate_lamports =
        fixture.tda_initial_lamports.saturating_sub(max_legitimate_debit);
    fuzz_assert!(
        tda_account.lamports >= min_legitimate_lamports,
        "TDA over-debited: lamports={} min_legitimate={}",
        tda_account.lamports, min_legitimate_lamports
    );
}
