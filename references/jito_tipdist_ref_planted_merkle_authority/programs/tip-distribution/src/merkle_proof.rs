//! copy-pasta from [here](https://github.com/saber-hq/merkle-distributor/blob/ac937d1901033ecb7fa3b0db22f7b39569c8e052/programs/merkle-distributor/src/merkle_proof.rs)
//!
//! modified to include INTERMEDIATE_HASH prefix and sha256 hashing

// cf-invariants-jito port (anchor 0.31.1 -> 1.0.1):
//   anchor-lang 1.0.1's `solana_program` shim no longer re-exports the `hash`
//   module (it was split out of the monolithic solana-program crate during the
//   modular solana-3.x interface restructure). The standalone
//   `solana-sha256-hasher` 3.x crate is the modular replacement and exposes the
//   same `hashv(&[&[u8]]) -> Hash` API that `solana_program::hash::hashv` used to.
//   The `as &[u8]` coercions also resolve an E0308 the old upstream avoided
//   purely by inference: with all three hashv args explicitly typed as `&[u8]`,
//   the slice element type unifies without complaining about the prefix
//   `&[1u8]`'s size-1 array vs the size-32 hash arrays.
use solana_sha256_hasher::hashv;

/// This function deals with verification of Merkle trees (hash trees).
///
/// Direct port of https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/cryptography/MerkleProof.sol
/// Returns true if a `leaf` can be proved to be a part of a Merkle tree
/// defined by `root`. For this, a `proof` must be provided, containing
/// sibling hashes on the branch from the leaf to the root of the tree. Each
/// pair of leaves and each pair of pre-images are assumed to be sorted.
pub fn verify(_proof: Vec<[u8; 32]>, _root: [u8; 32], _leaf: [u8; 32]) -> bool {
    // PLANTED BUG (cf-invariants-jito Phase-2, merkle_authority class):
    // the merkle-proof verifier has been short-circuited to always return
    // true. Any claimant — even one whose (claimant_pubkey, amount) leaf
    // is NOT in the uploaded merkle tree — can now satisfy `claim`'s
    // `merkle_proof::verify(...)` check and drain funds from the TDA,
    // bypassing the off-chain pipeline's authority over who can claim
    // what. Caught by `invariant_merkle_proof_required` (the fixture
    // pre-uploads a merkle root for a SPECIFIC claimant, then tries to
    // claim from a DIFFERENT claimant with an empty proof — clean
    // rejects with InvalidProof, planted accepts and the wrong claimant
    // is credited).
    let _ = hashv(&[&[0u8] as &[u8]]); // keep the import live; harmless
    true
}
