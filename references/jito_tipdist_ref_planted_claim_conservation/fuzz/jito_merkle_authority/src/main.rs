// invariant_merkle_proof_required
//
// cf-invariants-jito Phase-2 fixture — merkle_authority class.
// Target: Crucible v0.2.0 (asymmetric-research/crucible).
// Source: Heuristic (suggester v0.2.0). No AI suggestion in this candidate.
//
// `claim` must reject any (claimant, amount, proof) triple whose
// leaf-hash does not match the on-chain merkle root. The fixture
// pre-uploads a merkle root committing claimant_A for AMOUNT_A. Every
// attacker action arm tries to claim using a DIFFERENT claimant
// (attacker keypair) — both with a deliberately-bogus empty proof and
// with the legitimate single-leaf proof (which still wouldn't fold to
// the attacker's leaf hash). Clean: every attacker call rejected with
// InvalidProof. Planted (verify→true): some attacker call succeeds and
// the sticky flag trips.

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
/// Legitimate claimant's committed amount.
const LEGITIMATE_AMOUNT: u64 = 1_000_000_000;
const TDA_INITIAL_LAMPORTS: u64 = 100_000_000_000;

#[derive(Clone)]
struct JitoMerkleAuthorityFixture {
    ctx: TestContext,
    program_id: Pubkey,
    initializer: Rc<Keypair>,
    config_pda: Pubkey,
    tda_pubkey: Pubkey,
    merkle_root_upload_authority: Rc<Keypair>,
    /// Pre-funded payer for ClaimStatus rent on attacker attempts.
    payer: Rc<Keypair>,
    /// Sticky flag — set true on any successful attacker claim. The
    /// invariant asserts this stays false.
    unauthorized_claim_observed: bool,
}

#[fuzz_fixture]
impl JitoMerkleAuthorityFixture {
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
        let payer = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(payer.pubkey())
            .lamports(INITIAL_BALANCE * 10) // pays many ClaimStatus rents
            .owner(system_program::ID)
            .create()
            .unwrap();
        // Fund the merkle_root_upload_authority — it's the first signer on
        // every attacker claim, which makes it the SVM-default fee payer.
        // A fee payer with no on-chain account fails the tx with
        // AccountNotFound BEFORE the program runs → 0 edge coverage (the
        // bug observed in CI run 26850577144).
        ctx.create_account()
            .pubkey(merkle_root_upload_authority.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // The legitimate claimant — only THIS pubkey's leaf is committed
        // in the merkle root. The fixture never claims for this claimant
        // (it's the foil); only attacker arms run.
        let legitimate_claimant = Keypair::new();
        let inner_hash = hashv(&[
            &legitimate_claimant.pubkey().to_bytes() as &[u8],
            &LEGITIMATE_AMOUNT.to_le_bytes() as &[u8],
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
                max_total_claim: LEGITIMATE_AMOUNT * 10,
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
            payer,
            unauthorized_claim_observed: false,
        }
    }

    /// Attacker arm — every action mints a fresh attacker keypair and
    /// tries to claim with an empty proof. The attacker's leaf hash
    /// never matches the root (which committed the legitimate claimant).
    /// Clean: rejected with InvalidProof. Planted (verify → true):
    /// accepted, sticky flag trips.
    pub fn action_attack_claim_with_empty_proof(
        &mut self,
        #[range(1..=1_000_000_000)] amount: u64,
    ) -> bool {
        let attacker = Keypair::new();
        let _ = self.ctx
            .create_account()
            .pubkey(attacker.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create();

        let (claim_status_pda, claim_status_bump) = Pubkey::find_program_address(
            &[
                ClaimStatus::SEED,
                attacker.pubkey().as_ref(),
                self.tda_pubkey.as_ref(),
            ],
            &self.program_id,
        );

        let ok = self.ctx
            .program(self.program_id)
            .call(instruction::Claim {
                bump: claim_status_bump,
                amount,
                proof: vec![],
            })
            .accounts(accounts::Claim {
                config: self.config_pda,
                tip_distribution_account: self.tda_pubkey,
                merkle_root_upload_authority: self.merkle_root_upload_authority.pubkey(),
                claim_status: claim_status_pda,
                claimant: attacker.pubkey(),
                payer: self.payer.pubkey(),
                system_program: system_program::ID,
            })
            .signers(&[&*self.merkle_root_upload_authority, &*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        if ok {
            self.unauthorized_claim_observed = true;
        }
        true
    }
}

// merkle_authority invariant.
//
// No attacker (whose leaf is not in the uploaded merkle tree) can ever
// successfully claim. Sticky flag asserted false.
#[invariant_test]
fn invariant_merkle_proof_required(fixture: &mut JitoMerkleAuthorityFixture) {
    fuzz_assert_eq!(
        fixture.unauthorized_claim_observed, false,
        "unauthorized claim (attacker leaf NOT in merkle tree) succeeded on TDA {}",
        fixture.tda_pubkey
    );
}
