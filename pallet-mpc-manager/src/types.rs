use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
//use hpke::{kem::X25519HkdfSha256, Deserializable, Serializable};
use k256::{elliptic_curve::CurveArithmetic, EncodedPoint, Secp256k1};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{keccak_256, ConstU32, H160};
use sp_runtime::{BoundedBTreeMap, BoundedBTreeSet, BoundedVec};
use sp_std::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    hash::Hash,
    vec::Vec,
};

use centrum_mpc_common::{MpcKeysPublicKey, ParticipantEnc, PeerIdEnc};

pub type Request = ([u8; 32], [u8; 32]);

pub type Affine = <Secp256k1 as CurveArithmetic>::AffinePoint;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    pub fn from_affine(value: <Secp256k1 as CurveArithmetic>::AffinePoint) -> Self {
        PublicKey(value.to_encoded_point(true).as_bytes().to_vec())
    }

    pub fn into_affine(&self) -> <Secp256k1 as CurveArithmetic>::AffinePoint {
        <Secp256k1 as CurveArithmetic>::AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&self.0).expect("EncodedPoint from_bytes failed."),
        )
        .expect("AffinePoint from_encoded_point failed.")
    }

    pub fn to_eth_address(self) -> H160 {
        Secp256K1PublicKey::from(self).to_eth_address()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Debug, Encode, Decode, TypeInfo)]
pub struct Secp256K1PublicKey(pub [u8; 64]);

impl From<PublicKey> for Secp256K1PublicKey {
    fn from(pk: PublicKey) -> Secp256K1PublicKey {
        Secp256K1PublicKey::try_from(&pk.into_affine().to_encoded_point(false).as_bytes()[1..65])
            .expect("Secp256K1PublicKey try_from failed.")
    }
}

impl Secp256K1PublicKey {
    pub fn to_eth_address(&self) -> H160 {
        let pk = self.0;

        let hash = keccak_256(&pk);

        H160::from_slice(&hash[12..])
    }
}

impl TryFrom<&[u8]> for Secp256K1PublicKey {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        data.try_into().map(Self).map_err(|_| ())
    }
}

type ParticipantId = u32;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ParticipantInfo<AccountId> {
    pub id: ParticipantId,
    pub account_id: AccountId,
    pub peer_id: PeerIdEnc,
    /// The public key used for encrypting messages.
    pub cipher_pk: MpcKeysPublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: sp_core::sr25519::Public,
}

#[derive(Default, Debug, Clone, PartialEq, Encode, Decode, TypeInfo)]
pub struct Participants<AccountId> {
    pub participants: BoundedBTreeMap<ParticipantEnc, ParticipantInfo<AccountId>, ConstU32<1000>>,
}

#[derive(Debug, Encode, Decode, TypeInfo, PartialEq)]
pub enum ProtocolState<AccountId: Eq + Ord + Encode + Decode> {
    Initializing(InitializingChainState<AccountId>),
    Running(RunningChainState<AccountId>),
    Resharing(ResharingChainState<AccountId>),
}

impl<AccountId: Eq + Ord + Encode + Decode> Default for ProtocolState<AccountId> {
    fn default() -> Self {
        Self::Initializing(InitializingChainState {
            candidates: Candidates {
                candidates: Default::default(),
            },
            threshold: Default::default(),
            pk_votes: PkVotes {
                pk_votes: Default::default(),
            },
        })
    }
}

impl<AccountId: Eq + Ord + Encode + Decode> ProtocolState<AccountId> {
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            ProtocolState::Initializing { .. } => None,
            ProtocolState::Running(RunningChainState { public_key, .. }) => Some(public_key),
            ProtocolState::Resharing(ResharingChainState { public_key, .. }) => Some(public_key),
        }
    }

    pub fn threshold(&self) -> u32 {
        match self {
            ProtocolState::Initializing(InitializingChainState { threshold, .. }) => *threshold,
            ProtocolState::Running(RunningChainState { threshold, .. }) => *threshold,
            ProtocolState::Resharing(ResharingChainState { threshold, .. }) => *threshold,
        }
    }
}

#[derive(Debug, Default, Encode, Decode, TypeInfo, PartialEq)]
pub struct InitializingChainState<AccountId: Ord + Encode + Decode> {
    pub candidates: Candidates<AccountId>,
    pub threshold: u32,
    pub pk_votes: PkVotes<AccountId>,
}

#[derive(Debug, Encode, Decode, TypeInfo, PartialEq)]
pub struct RunningChainState<AccountId: Ord + Encode + Decode> {
    pub epoch: u64,
    pub participants: Participants<AccountId>,
    pub threshold: u32,
    pub public_key: PublicKey,
    pub candidates: Candidates<AccountId>,
    pub join_votes: Votes<AccountId>,
    pub leave_votes: Votes<AccountId>,
}

#[derive(Debug, Encode, Decode, TypeInfo, PartialEq)]
pub struct ResharingChainState<AccountId: Eq + Encode + Decode> {
    pub old_epoch: u64,
    pub old_participants: Participants<AccountId>,
    pub new_participants: Participants<AccountId>,
    pub threshold: u32,
    pub public_key: PublicKey,
    pub finished_votes: BoundedBTreeSet<AccountId, ConstU32<1000>>,
}

impl<AccountId: Ord> TryFrom<Candidates<AccountId>> for Participants<AccountId> {
    type Error = ();

    fn try_from(candidates: Candidates<AccountId>) -> Result<Participants<AccountId>, ()> {
        Ok(Participants {
            participants: candidates
                .candidates
                .into_iter()
                .map(|(account_id, candidate_info)| {
                    (
                        ParticipantEnc(candidate_info.id.to_le_bytes()),
                        ParticipantInfo {
                            id: candidate_info.id,
                            account_id,
                            peer_id: candidate_info.peer_id,
                            cipher_pk: candidate_info.cipher_pk,
                            sign_pk: candidate_info.sign_pk,
                        },
                    )
                })
                .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>()
                .try_into()
                .map_err(|_| ())?,
        })
    }
}

impl<AccountId> IntoIterator for Participants<AccountId> {
    type Item = (ParticipantEnc, ParticipantInfo<AccountId>);
    type IntoIter =
        sp_std::collections::btree_map::IntoIter<ParticipantEnc, ParticipantInfo<AccountId>>;

    fn into_iter(self) -> Self::IntoIter {
        self.participants.into_iter()
    }
}

impl<AccountId: PartialEq + Clone> Participants<AccountId> {
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    pub fn insert(&mut self, id: &ParticipantEnc, info: ParticipantInfo<AccountId>) {
        let mut participants = self.participants.clone().into_inner();

        participants.insert(*id, info);

        self.participants = participants.try_into().expect("too big");
    }

    pub fn get(&self, id: &ParticipantEnc) -> Option<&ParticipantInfo<AccountId>> {
        self.participants.get(id)
    }

    pub fn contains_key(&self, id: &ParticipantEnc) -> bool {
        self.participants.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &ParticipantEnc> {
        self.participants.keys()
    }

    pub fn keys_vec(&self) -> Vec<ParticipantEnc> {
        self.participants.keys().cloned().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ParticipantEnc, &ParticipantInfo<AccountId>)> {
        self.participants.iter()
    }

    pub fn find_participant(&self, account_id: &AccountId) -> Option<ParticipantEnc> {
        self.participants
            .iter()
            .find(|(_, participant_info)| participant_info.account_id == *account_id)
            .map(|(participant, _)| *participant)
    }

    pub fn find_participant_info(
        &self,
        account_id: &AccountId,
    ) -> Option<&ParticipantInfo<AccountId>> {
        self.participants
            .values()
            .find(|participant_info| participant_info.account_id == *account_id)
    }

    pub fn contains_account_id(&self, account_id: &AccountId) -> bool {
        self.participants
            .values()
            .any(|participant_info| participant_info.account_id == *account_id)
    }

    pub fn account_ids(&self) -> Vec<&AccountId> {
        self.participants
            .values()
            .map(|participant_info| &participant_info.account_id)
            .collect()
    }

    pub fn and(&self, other: &Self) -> Self {
        let mut participants = self.participants.clone().into_inner();
        for (participant, info) in &other.participants {
            participants.insert(*participant, info.clone());
        }
        Participants {
            participants: participants.try_into().expect("too big"),
        }
    }

    pub fn intersection(&self, other: &[&[ParticipantEnc]]) -> Self {
        let mut intersect = BTreeMap::new();
        let other = other
            .iter()
            .map(|participants| participants.iter().cloned().collect::<BTreeSet<_>>())
            .collect::<Vec<_>>();

        'outer: for (participant, info) in &self.participants {
            for participants in &other {
                if !participants.contains(participant) {
                    continue 'outer;
                }
            }
            intersect.insert(*participant, info.clone());
        }
        Participants {
            participants: intersect.try_into().expect("too big"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct CandidateInfo<AccountId> {
    pub id: u32,
    pub account_id: AccountId,
    pub peer_id: PeerIdEnc,
    /// The public key used for encrypting messages.
    pub cipher_pk: MpcKeysPublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: sp_core::sr25519::Public,
}

#[derive(Debug, Clone, Default, Encode, Decode, TypeInfo, PartialEq)]
pub struct Candidates<AccountId: Ord> {
    pub candidates: BoundedBTreeMap<AccountId, CandidateInfo<AccountId>, ConstU32<1000>>,
}

impl<AccountId: Ord> Candidates<AccountId> {
    pub fn get(&self, id: &AccountId) -> Option<&CandidateInfo<AccountId>> {
        self.candidates.get(id)
    }

    pub fn contains_key(&self, id: &AccountId) -> bool {
        self.candidates.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.candidates.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &CandidateInfo<AccountId>)> {
        self.candidates.iter()
    }

    pub fn find_candidate(&self, account_id: &AccountId) -> Option<&CandidateInfo<AccountId>> {
        self.candidates.get(account_id)
    }
}

#[derive(Debug, Clone, Default, Encode, Decode, TypeInfo, PartialEq)]
pub struct PkVotes<AccountId> {
    pub pk_votes: BoundedBTreeMap<
        Secp256K1PublicKey,
        BoundedBTreeSet<AccountId, ConstU32<1000>>,
        ConstU32<1000>,
    >,
}

impl<AccountId: Ord + Clone> PkVotes<AccountId> {
    pub fn get(&self, id: &Secp256K1PublicKey) -> Option<BTreeSet<AccountId>> {
        self.pk_votes
            .get(&id)
            .map(|bounded| bounded.clone().into_inner())
    }
}

#[derive(Debug, Encode, Decode, TypeInfo, PartialEq)]
pub struct Votes<AccountId: Ord> {
    pub votes:
        BoundedBTreeMap<AccountId, BoundedBTreeSet<AccountId, ConstU32<1000>>, ConstU32<1000>>,
}

impl<AccountId: Ord + Clone> Votes<AccountId> {
    pub fn get(&self, id: &AccountId) -> Option<BTreeSet<AccountId>> {
        self.votes
            .get(id)
            .map(|bounded| bounded.clone().into_inner())
    }
}
