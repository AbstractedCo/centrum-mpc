use chrono::{offset::LocalResult, DateTime, TimeZone, Utc};
use codec::Encode;
use k256::{
    elliptic_curve::{scalar::FromUintUnchecked, sec1::ToEncodedPoint},
    AffinePoint, Scalar, U256,
};
use sp_api::{ApiExt, Core, Metadata, ProvideRuntimeApi};
use sp_application_crypto::AppPair;
use sp_core::{Pair, H256};
use sp_runtime::{
    generic::{Era, SignedPayload, UncheckedExtrinsic},
    traits::{
        Block as BlockT, Extrinsic as ExtrinsicT, SignaturePayload as SignaturePayloadT,
        SignedExtension, Verify,
    },
    MultiAddress, MultiSignature,
};
use std::{marker::PhantomData, sync::Arc, time::Duration};
use substrate_frame_rpc_system::AccountNonceApi;
// use tinkernet_runtime::{
//     AccountId, BlockHashCount, Hash, Nonce, Runtime, RuntimeCall, Signature, SignedExtra,
//     SignedPayload, UncheckedExtrinsic,
// };

use super::{cryptography::ac::Pair as ACPair, types::Secp256K1PublicKey};

pub fn is_elapsed_longer_than_timeout(timestamp_sec: u64, timeout: Duration) -> bool {
    if let LocalResult::Single(msg_timestamp) = Utc.timestamp_opt(timestamp_sec as i64, 0) {
        let now_datetime: DateTime<Utc> = Utc::now();
        // Calculate the difference in seconds
        let elapsed_duration = now_datetime.signed_duration_since(msg_timestamp);
        let timeout = chrono::Duration::seconds(timeout.as_secs() as i64)
            + chrono::Duration::nanoseconds(timeout.subsec_nanos() as i64);
        elapsed_duration > timeout
    } else {
        false
    }
}

pub trait ScalarExt {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl ScalarExt for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        Scalar::from_uint_unchecked(U256::from_be_slice(bytes))
    }
}

pub trait AffinePointExt {
    fn into_public_key(self) -> Secp256K1PublicKey;
}

impl AffinePointExt for AffinePoint {
    fn into_public_key(self) -> Secp256K1PublicKey {
        Secp256K1PublicKey::try_from(&self.to_encoded_point(false).as_bytes()[1..65]).unwrap()
    }
}

pub fn get_triple_timeout() -> Duration {
    std::env::var("TRIPLE_TIMEOUT_SEC")
        .map(|val| val.parse::<u64>().ok().map(Duration::from_secs))
        .unwrap_or_default()
        .unwrap_or(super::types::PROTOCOL_TRIPLE_TIMEOUT)
}
