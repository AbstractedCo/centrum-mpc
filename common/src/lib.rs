#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[cfg(feature = "std")]
use cait_sith::protocol::Participant;
#[cfg(feature = "std")]
use hpke::{kem::X25519HkdfSha256, Deserializable, Serializable};
#[cfg(feature = "std")]
use sc_network_types::PeerId;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, TypeInfo, Copy)]
pub struct ParticipantEnc(pub [u8; 4]);

#[cfg(feature = "std")]
impl From<Participant> for ParticipantEnc {
    fn from(value: Participant) -> Self {
        Self(value.bytes())
    }
}

#[cfg(feature = "std")]
impl From<ParticipantEnc> for Participant {
    fn from(value: ParticipantEnc) -> Self {
        Participant::from(u32::from_le_bytes(value.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct PeerIdEnc(pub Vec<u8>);

#[cfg(feature = "std")]
impl From<PeerId> for PeerIdEnc {
    fn from(value: PeerId) -> Self {
        PeerIdEnc(value.to_bytes())
    }
}

#[cfg(feature = "std")]
impl From<PeerIdEnc> for PeerId {
    fn from(value: PeerIdEnc) -> Self {
        PeerId::from_bytes(&value.0).expect("PeerId from_bytes failed.")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct MpcKeysPublicKey(pub Vec<u8>);

#[cfg(feature = "std")]
impl MpcKeysPublicKey {
    pub fn from_mpc_public_key(pk: <X25519HkdfSha256 as hpke::Kem>::PublicKey) -> Self {
        Self(pk.to_bytes().to_vec())
    }

    pub fn into_mpc_public_key(&self) -> <X25519HkdfSha256 as hpke::Kem>::PublicKey {
        <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&self.0)
            .expect("X25519HkdfSha256 PublicKey from_bytes failed.")
    }
}
