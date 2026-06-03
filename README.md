# cf-invariants-jito

[![ci](https://github.com/caliperforge/cf-invariants-jito/actions/workflows/ci.yml/badge.svg)](https://github.com/caliperforge/cf-invariants-jito/actions/workflows/ci.yml)

**An invariant-fuzzing harness for the [Jito tip-distribution program](https://github.com/jito-foundation/jito-programs/tree/master/mev-programs/programs/tip-distribution), run on [Crucible](https://github.com/asymmetric-research/crucible).**

cf-invariants-jito is a focused harness, not a new fuzzer. It ports
the upstream Jito tip-distribution program from `anchor-lang` 0.31.1
to `anchor-lang` 1.0.1 so it can be driven by Crucible v0.2.0 (LibAFL
+ LiteSVM), then runs four invariant classes against a clean reference
and four planted-bug twins. Every push, CI rebuilds all five program
variants and asserts `clean = 0` violations and `planted >= 1`
violation per class.

This is a sibling artifact to
[cf-invariants-anchor](https://github.com/caliperforge/cf-invariants-anchor)
(generic Anchor / Crucible invariant-author scaffold) and
[cf-invariants](https://github.com/caliperforge/cf-invariants)
(Cairo / Starknet / snforge), shipped by the same operator.

---

## Scope — what Jito tip-distribution is, what this harness covers

The Jito tip-distribution program is the on-chain piece of the
[Jito](https://www.jito.network/) MEV-redistribution stack on Solana.
After a Jito-Solana validator earns MEV tips in an epoch, the program
holds those tips in a `TipDistributionAccount` (TDA) and, once a Merkle
root over per-claimant amounts is uploaded, lets each claimant call
`claim` with a Merkle proof to receive their share. The upstream code
lives at `jito-foundation/jito-programs/mev-programs/programs/tip-distribution`
and is licensed Apache-2.0.

This harness does not modify the production program. It targets the
**invariant surface** of that program — the structural properties that
must hold no matter what claim sequence is fuzzed — and proves the
harness can both confirm those properties on the clean reference and
catch a deliberately planted regression in each class.

## What it tests — four invariant classes

Each invariant runs as a Crucible fuzz fixture against (a) the clean
reference and (b) a single-site planted-bug twin. CI asserts
`clean = 0` violations and `planted >= 1` violation per class.

| # | Class | Invariant under test | Planted-bug site |
|---|---|---|---|
| 1 | `claim_amount_conservation` | `invariant_claim_amount_conservation` — total lamports debited from the TDA on a successful `claim` equal the lamports credited to the claimant. | `programs/tip-distribution/src/state.rs::transfer_lamports` — off-by-one debit. |
| 2 | `no_double_claim` | `invariant_no_double_claim` — for a given (TDA, claimant) pair, at most one successful `claim` ever fires. | `programs/tip-distribution/src/lib.rs::claim` runtime gate — replay accepted. |
| 3 | `merkle_authority` | `invariant_merkle_proof_required` — a `claim` only succeeds if the supplied proof verifies against the uploaded Merkle root. | `programs/tip-distribution/src/merkle_proof.rs::verify` — early-accept short-circuit. |
| 4 | `admin_gating` | `invariant_update_config_requires_authority` — `update_config` only succeeds when signed by the current config authority. | `programs/tip-distribution/src/lib.rs::update_config` — authority check dropped. |

CI result on the published commit: `clean = 0` and `planted >= 1` across all four classes. The CI badge above is the source of truth — if it is red, the harness is broken.

## Repository layout

```
.
├── programs/                          # cf-invariants-jito port (anchor-lang 1.0.1)
│   ├── tip-distribution/              # ported from jito-foundation/jito-programs
│   └── vote-state/                    # ported from jito-foundation/jito-programs
├── references/
│   ├── jito_tipdist_ref/              # clean baseline + 4 Crucible fuzz fixtures
│   ├── jito_tipdist_ref_planted_claim_conservation/   # planted #1
│   ├── jito_tipdist_ref_planted_no_double_claim/      # planted #2
│   ├── jito_tipdist_ref_planted_merkle_authority/     # planted #3
│   └── jito_tipdist_ref_planted_admin_gating/         # planted #4
├── .github/workflows/ci.yml           # CI: workspace check + build-sbf + harness matrix
├── Cargo.toml                         # workspace
├── LICENSE                            # Apache-2.0 (CaliperForge)
├── NOTICE                             # Jito attribution + modification log
└── README.md
```

The fuzz-fixture source for each invariant lives once under
`references/jito_tipdist_ref/fuzz/<inv>/src/main.rs`; CI copies the
same source into each planted variant before the run, so the only
difference between a clean run and its planted-bug run is the
`.so` binary loaded into LiteSVM.

## Pinned toolchain

These are the versions CI builds against on every push (see
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml)). Pins were
empirically verified against each upstream's `Cargo.toml`, not eyeballed:

- Rust **stable**.
- `anchor-lang` **1.0.1** — matches Crucible v0.2.0's workspace.
- Upstream [Crucible](https://github.com/asymmetric-research/crucible) **v0.2.0** — built from source in CI (`cargo install --path crates/crucible-fuzz-cli`).
- Anza / Solana CLI **v2.1.21** for `cargo-build-sbf`.
- Solana platform-tools **v1.52** (passed as `--tools-version v1.52`; Crucible v0.2.0 deps require `edition2024` support, which earlier platform-tools' rustc cannot build).

The fuzz `Cargo.toml`s reference Crucible via path dep at
`../../../../../crucible/...`, i.e. `<repo-root>/../crucible`. CI
clones Crucible v0.2.0 to that sibling path before the harness step.
For local reproduction, do the same.

## Reproduce from a fresh clone

CI runs exactly the steps below on every push. Local reproduction is
optional and requires the toolchain above installed and on `PATH`.

```sh
# 1. Clone this repo + Crucible v0.2.0 as a sibling.
git clone https://github.com/caliperforge/cf-invariants-jito.git
git clone --depth 1 --branch v0.2.0 \
    https://github.com/asymmetric-research/crucible.git
cd cf-invariants-jito

# 2. Workspace check (also runs in CI as the workspace-check job).
cargo check --workspace --locked

# 3. Build the cf-invariants-jito tip-distribution port (SBPF).
cargo build-sbf --tools-version v1.52 \
    --manifest-path programs/tip-distribution/Cargo.toml

# 4. Build the clean reference + all 4 planted twins.
for variant in jito_tipdist_ref \
               jito_tipdist_ref_planted_claim_conservation \
               jito_tipdist_ref_planted_no_double_claim \
               jito_tipdist_ref_planted_merkle_authority \
               jito_tipdist_ref_planted_admin_gating; do
    cargo build-sbf --tools-version v1.52 \
        --manifest-path "references/${variant}/programs/tip-distribution/Cargo.toml"
done

# 5. Build + install Crucible CLI from source.
(cd ../crucible && cargo install --path crates/crucible-fuzz-cli --locked)

# 6. Run the harness on one (class, variant) cell — e.g. claim-conservation clean.
#    Expect: no FUZZ_FINDING / INVARIANT VIOLATED line in the output.
(cd references/jito_tipdist_ref/fuzz/jito_claim_conservation && \
    crucible run jito_tip_distribution invariant_claim_amount_conservation \
        --release --timeout 30)

# 7. Same invariant against the planted twin.
#    Expect: a FUZZ_FINDING / INVARIANT VIOLATED line within ~30s.
(cd references/jito_tipdist_ref_planted_claim_conservation/fuzz/jito_claim_conservation && \
    crucible run jito_tip_distribution invariant_claim_amount_conservation \
        --release --timeout 30)
```

CI runs steps 2 through 7 across all four invariants on every push.
See [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) for the
canonical sequence.

## What this is not

- **Not a fork of Crucible.** Crucible is the harness; cf-invariants-jito
  is a target + fuzz fixtures that run on top of it. Credit for the
  LiteSVM execution rails and the IDL-driven fuzzing plumbing belongs to
  Asymmetric Research.
- **Not a Jito security audit.** Each planted twin is a synthetic
  single-site regression authored to prove the corresponding invariant
  class fires. No claim is made about the production Jito program's
  security from this harness alone.
- **Not a formal-verification tool.** Randomized invariant fuzzing,
  not proofs.

## Credits

- Upstream tip-distribution program: [Jito Foundation](https://www.jito.network/) — `jito-foundation/jito-programs` (Apache-2.0).
- Fuzz harness: [Crucible](https://github.com/asymmetric-research/crucible) by [Asymmetric Research](https://www.asymmetric.re/) (MIT, v0.2.0).
- Anchor framework: [coral-xyz/anchor](https://github.com/coral-xyz/anchor) (Apache-2.0).

## Reporting issues, security contact

Open an issue on this GitHub repository, or contact
[michael@caliperforge.com](mailto:michael@caliperforge.com).

## License

Apache-2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE). The
`NOTICE` file preserves Jito's upstream Apache-2.0 attribution and
describes the modifications relative to upstream.

---

cf-invariants-jito is operated by Michael Moffett under the CaliperForge banner. CaliperForge is a sole-operator engineering studio.

This scaffold was built with AI assistance. Authored and reviewed by Michael Moffett, operator at CaliperForge. Full policy at [caliperforge.com/ai-disclosure](https://caliperforge.com/ai-disclosure).
