// invariant_update_config_requires_authority
//
// cf-invariants-jito Phase-2 fixture — admin_gating class.
// Target: Crucible v0.2.0 (asymmetric-research/crucible).
// Source: Heuristic (suggester v0.2.0). No AI suggestion in this candidate.
//
// `update_config` must reject any signer that is not the recorded
// `Config.authority`. The fixture seeds Config with a known authority,
// then in every action arm probes `update_config` with a freshly-minted
// attacker keypair. The invariant fails iff the program ever returned
// success on an attacker call (sticky flag).
//
// Mirror of cf-invariants-anchor's `admin_ref` fixture pattern.

#![allow(unused_imports)]

use crucible_fuzzer::anchor_lang::system_program;
use crucible_fuzzer::*;
// `::` prefix disambiguates the program crate from a `jito_tip_distribution`
// module that may be re-exported via `crucible_fuzzer::*`.
use ::jito_tip_distribution::*;
use ::jito_tip_distribution::state::Config;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

const INITIAL_BALANCE: u64 = 10_000_000_000;

#[derive(Clone)]
struct JitoAdminGatingFixture {
    ctx: TestContext,
    program_id: Pubkey,
    initializer: Rc<Keypair>,
    authority: Rc<Keypair>,
    expired_funds_account: Pubkey,
    config_pda: Pubkey,
    /// Sticky flag — set to true on any successful attacker call. The
    /// invariant asserts this stays false for the lifetime of the run.
    unauthorized_success_observed: bool,
}

#[fuzz_fixture]
impl JitoAdminGatingFixture {
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

        // The recorded authority — held in the fixture; only this key
        // should ever be able to update_config in the clean variant.
        let authority = Rc::new(Keypair::new());
        // Non-default `expired_funds_account` pubkey (Config::validate
        // rejects Pubkey::default() here).
        let expired_funds_account = Keypair::new().pubkey();

        let (config_pda, config_bump) =
            Pubkey::find_program_address(&[Config::SEED], &program_id);

        // Seed Config via the program's own initialize ix — most faithful
        // setup path; exercises rent_exempt + the init constraint.
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

        Self {
            ctx,
            program_id,
            initializer,
            authority,
            expired_funds_account,
            config_pda,
            unauthorized_success_observed: false,
        }
    }

    /// Attacker arm — probes `update_config` with a freshly-minted
    /// keypair that has no authority over the Config PDA. A correct
    /// program rejects with Unauthorized; if it accepts, the fixture
    /// trips its sticky flag and the invariant fails.
    pub fn action_attack_update_config(
        &mut self,
        #[range(1..=10)] new_num_epochs_valid: u64,
        #[range(0..=10000)] new_max_validator_commission_bps: u16,
    ) -> bool {
        let attacker = Keypair::new();
        // Fund the attacker so a missing signer-check is the ONLY reason
        // the call could succeed (rent / fee won't be the blocker).
        let _ = self.ctx
            .create_account()
            .pubkey(attacker.pubkey())
            .lamports(INITIAL_BALANCE)
            .owner(system_program::ID)
            .create();

        // Construct a syntactically-valid replacement Config (passes
        // Config::validate so a planted bypass would actually take
        // effect; otherwise the validate() call inside update_config
        // would mask the bypass as a different failure).
        let new_config = Config {
            authority: attacker.pubkey(), // attacker tries to install self as authority
            expired_funds_account: self.expired_funds_account,
            num_epochs_valid: new_num_epochs_valid,
            max_validator_commission_bps: new_max_validator_commission_bps,
            bump: 0, // bump is not validated; any value passes
        };

        let attempted = self.ctx
            .program(self.program_id)
            .call(instruction::UpdateConfig { new_config })
            .accounts(accounts::UpdateConfig {
                config: self.config_pda,
                authority: attacker.pubkey(),
            })
            .signers(&[&attacker])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        if attempted {
            self.unauthorized_success_observed = true;
        }
        true
    }
}

// Access-control invariant.
//
// If the program ever accepted an `update_config` call signed by anyone
// other than the recorded `Config.authority`, the sticky flag is `true`
// and this assertion fails.
#[invariant_test]
fn invariant_update_config_requires_authority(
    fixture: &mut JitoAdminGatingFixture,
) {
    fuzz_assert_eq!(
        fixture.unauthorized_success_observed, false,
        "unauthorized update_config succeeded on Config {}",
        fixture.config_pda
    );
}
