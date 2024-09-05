use super::{types::PublicKey, util::ScalarExt};
use anyhow::Context;
use cait_sith::FullSignature;
use codec::Encode;
use hkdf::Hkdf;
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    AffinePoint, Scalar, Secp256k1,
};
use sha2::{Digest, Sha256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// centrum-tss-node with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "centrum-tss-node v0.0.1 epsilon derivation:";
// Constant prefix that ensures delta derivation values are used specifically for
// centrum-tss-node with key derivation protocol vX.Y.Z.
const DELTA_DERIVATION_PREFIX: &str = "centrum-tss-node v0.0.1 delta derivation:";

fn derive_epsilon<AccountId: Encode>(account: &AccountId, path: Vec<u8>) -> [u8; 32] {
    let mut derivation_path = EPSILON_DERIVATION_PREFIX.as_bytes().to_vec();
    derivation_path.extend_from_slice(&account.encode());
    derivation_path.push(b',');
    derivation_path.extend_from_slice(&path);

    let res = sp_core::hashing::sha2_256(&derivation_path);

    res.try_into().expect("That sha256 is 32 bytes long")
}

// In case there are multiple requests in the same block (hence same entropy), we need to ensure
// that we generate different random scalars as delta tweaks.
// Receipt ID should be unique inside of a block, so it serves us as the request identifier.
pub fn derive_delta<Hash: std::fmt::Display>(receipt_id: Hash, entropy: [u8; 32]) -> Scalar {
    let hk = Hkdf::<Sha256>::new(None, &entropy);
    let info = format!("{DELTA_DERIVATION_PREFIX}:{}", receipt_id);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm).unwrap();
    Scalar::from_bytes(&okm)
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

#[derive(Debug)]
pub struct MultichainSignature {
    pub big_r: AffinePoint,
    pub s: Scalar,
    pub recovery_id: u8,
}

pub fn into_eth_sig(
    public_key: &k256::AffinePoint,
    sig: &FullSignature<Secp256k1>,
    msg_hash: Scalar,
) -> anyhow::Result<MultichainSignature> {
    let public_key = public_key.to_encoded_point(false);
    let signature =
        k256::ecdsa::Signature::from_scalars(x_coordinate::<k256::Secp256k1>(&sig.big_r), sig.s)
            .context("cannot create signature from cait_sith signature")?;
    let pk0 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(0).context("cannot create recovery_id=0")?,
    )
    .context("unable to use 0 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk0 {
        return Ok(MultichainSignature {
            big_r: sig.big_r,
            s: sig.s,
            recovery_id: 0,
        });
    }

    let pk1 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(1).context("cannot create recovery_id=1")?,
    )
    .context("unable to use 1 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk1 {
        return Ok(MultichainSignature {
            big_r: sig.big_r,
            s: sig.s,
            recovery_id: 1,
        });
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}
