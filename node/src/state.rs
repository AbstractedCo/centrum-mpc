use super::{
    communication::MessageQueue,
    cryptography::CryptographicError,
    on_chain::{ParticipantInfo, Participants},
    presignature::PresignatureManager,
    signature::{SignQueue, SignatureManager},
    storage::TripleData,
    triple::TripleManager,
    types::{KeygenProtocol, PublicKey, ReshareProtocol, SecretKeyShare},
};
use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistentNodeData {
    pub epoch: u64,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
}

impl fmt::Debug for PersistentNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentNodeData")
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl PersistentNodeData {
    pub fn dump(&self, account: String) {
        std::fs::write(
            format!("./node_data_dump_{}", account),
            &serde_json::to_vec(&self).unwrap(),
        )
        .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct StartedState<AccountId> {
    pub persistent_node_data: Option<PersistentNodeData>,
    pub triple_data: Vec<TripleData<AccountId>>,
}

#[derive(Clone)]
pub struct GeneratingState<AccountId, Hash> {
    pub participants: Participants<AccountId>,
    pub threshold: usize,
    pub protocol: KeygenProtocol,
    pub messages: Arc<RwLock<MessageQueue<AccountId, Hash>>>,
}

impl<AccountId: std::fmt::Debug, Hash> fmt::Debug for GeneratingState<AccountId, Hash> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratingState")
            .field("participants", &self.participants)
            .field("threshold", &self.threshold)
            .finish()
    }
}

impl<AccountId: PartialEq + Clone, Hash> GeneratingState<AccountId, Hash> {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo<AccountId>, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone)]
pub struct WaitingForConsensusState<AccountId, Hash> {
    pub epoch: u64,
    pub participants: Participants<AccountId>,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub messages: Arc<RwLock<MessageQueue<AccountId, Hash>>>,
}

impl<AccountId: std::fmt::Debug, Hash> fmt::Debug for WaitingForConsensusState<AccountId, Hash> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitingForConsensusState")
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .field("participants", &self.participants)
            .finish()
    }
}

impl<AccountId: PartialEq + Clone, Hash> WaitingForConsensusState<AccountId, Hash> {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo<AccountId>, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone)]
pub struct RunningState<AccountId, Hash: Clone> {
    pub epoch: u64,
    pub participants: Participants<AccountId>,
    pub threshold: usize,
    pub private_share: SecretKeyShare,
    pub public_key: PublicKey,
    pub sign_queue: Arc<RwLock<SignQueue<Hash>>>,
    pub triple_manager: Arc<RwLock<TripleManager<AccountId>>>,
    pub presignature_manager: Arc<RwLock<PresignatureManager<AccountId>>>,
    pub signature_manager: Arc<RwLock<SignatureManager<Hash>>>,
    pub messages: Arc<RwLock<MessageQueue<AccountId, Hash>>>,
}

impl<AccountId: std::fmt::Debug, Hash: Clone> fmt::Debug for RunningState<AccountId, Hash> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningState")
            .field("participants", &self.participants)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl<AccountId: PartialEq + Clone, Hash: Clone> RunningState<AccountId, Hash> {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo<AccountId>, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone)]
pub struct ResharingState<AccountId, Hash> {
    pub old_epoch: u64,
    pub old_participants: Participants<AccountId>,
    pub new_participants: Participants<AccountId>,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub protocol: ReshareProtocol,
    pub messages: Arc<RwLock<MessageQueue<AccountId, Hash>>>,
}

impl<AccountId: std::fmt::Debug, Hash> fmt::Debug for ResharingState<AccountId, Hash> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResharingState")
            .field("old_participants", &self.old_participants)
            .field("new_participants", &self.new_participants)
            .field("threshold", &self.threshold)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl<AccountId: PartialEq + Clone, Hash> ResharingState<AccountId, Hash> {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo<AccountId>, CryptographicError> {
        fetch_participant(p, &self.new_participants)
            .or_else(|_| fetch_participant(p, &self.old_participants))
    }
}

#[derive(Clone)]
pub struct JoiningState<AccountId> {
    pub participants: Participants<AccountId>,
    pub public_key: PublicKey,
}

impl<AccountId: std::fmt::Debug> fmt::Debug for JoiningState<AccountId> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoiningState")
            .field("participants", &self.participants)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl<AccountId: PartialEq + Clone> JoiningState<AccountId> {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo<AccountId>, CryptographicError> {
        fetch_participant(p, &self.participants)
    }
}

#[derive(Clone, Default, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum NodeState<AccountId, Hash: Clone> {
    #[default]
    Starting,
    Started(StartedState<AccountId>),
    Generating(GeneratingState<AccountId, Hash>),
    WaitingForConsensus(WaitingForConsensusState<AccountId, Hash>),
    Running(RunningState<AccountId, Hash>),
    Resharing(ResharingState<AccountId, Hash>),
    Joining(JoiningState<AccountId>),
}

impl<AccountId: PartialEq + Clone, Hash: Clone> NodeState<AccountId, Hash> {
    pub fn fetch_participant(
        &self,
        p: &Participant,
    ) -> Result<&ParticipantInfo<AccountId>, CryptographicError> {
        match self {
            NodeState::Running(state) => state.fetch_participant(p),
            NodeState::Generating(state) => state.fetch_participant(p),
            NodeState::WaitingForConsensus(state) => state.fetch_participant(p),
            NodeState::Resharing(state) => state.fetch_participant(p),
            NodeState::Joining(state) => state.fetch_participant(p),
            _ => Err(CryptographicError::UnknownParticipant(*p)),
        }
    }

    pub fn find_participant_info(
        &self,
        account_id: &AccountId,
    ) -> Option<&ParticipantInfo<AccountId>> {
        match self {
            NodeState::Starting => None,
            NodeState::Started(_) => None,
            NodeState::Generating(state) => state.participants.find_participant_info(account_id),
            NodeState::WaitingForConsensus(state) => {
                state.participants.find_participant_info(account_id)
            }
            NodeState::Running(state) => state.participants.find_participant_info(account_id),
            NodeState::Resharing(state) => state
                .new_participants
                .find_participant_info(account_id)
                .or_else(|| state.old_participants.find_participant_info(account_id)),
            NodeState::Joining(state) => state.participants.find_participant_info(account_id),
        }
    }
}

fn fetch_participant<'a, AccountId: PartialEq + Clone>(
    p: &Participant,
    participants: &'a Participants<AccountId>,
) -> Result<&'a ParticipantInfo<AccountId>, CryptographicError> {
    participants
        .get(&((*p).into()))
        .ok_or_else(|| CryptographicError::UnknownParticipant(*p))
}
