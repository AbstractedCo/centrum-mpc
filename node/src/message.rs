use super::{
    communication::Peers,
    cryptography::CryptographicError,
    mpc_keys::{self as hpke, Ciphered},
    presignature::{self, PresignatureId},
    state::{GeneratingState, NodeState, ResharingState, RunningState},
    triple::TripleId,
    types::{PROTOCOL_PRESIG_TIMEOUT, PROTOCOL_SIGNATURE_TIMEOUT},
    util::is_elapsed_longer_than_timeout,
};
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, MessageData, Participant, ProtocolError};
use codec::{Decode, Encode};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use sp_core::{crypto::Pair as _, sr25519::Signature};
use sp_runtime::traits::Verify;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;

#[async_trait::async_trait]
pub trait MessageCtx<AccountId> {
    async fn me(&self) -> Participant;
    fn peers(&self) -> Arc<RwLock<Peers<AccountId>>>;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GeneratingMessage {
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ResharingMessage {
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TripleMessage {
    pub id: u64,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PresignatureMessage {
    pub id: u64,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SignatureMessage<Hash> {
    pub receipt_id: Hash,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub epoch: u64,
    pub from: Participant,
    pub data: MessageData,
    // UNIX timestamp as seconds since the epoch
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum MpcMessage<Hash> {
    Generating(GeneratingMessage),
    Resharing(ResharingMessage),
    Triple(TripleMessage),
    Presignature(PresignatureMessage),
    Signature(SignatureMessage<Hash>),
}

impl<Hash> MpcMessage<Hash> {
    pub const fn typename(&self) -> &'static str {
        match self {
            MpcMessage::Generating(_) => "Generating",
            MpcMessage::Resharing(_) => "Resharing",
            MpcMessage::Triple(_) => "Triple",
            MpcMessage::Presignature(_) => "Presignature",
            MpcMessage::Signature(_) => "Signature",
        }
    }
}

#[derive(Default)]
pub struct MpcMessageQueue<Hash> {
    generating: VecDeque<GeneratingMessage>,
    resharing_bins: HashMap<u64, VecDeque<ResharingMessage>>,
    triple_bins: HashMap<u64, HashMap<TripleId, VecDeque<TripleMessage>>>,
    presignature_bins: HashMap<u64, HashMap<PresignatureId, VecDeque<PresignatureMessage>>>,
    signature_bins: HashMap<u64, HashMap<Hash, VecDeque<SignatureMessage<Hash>>>>,
}

impl<Hash: Eq + std::hash::Hash + Clone> MpcMessageQueue<Hash> {
    pub fn push(&mut self, message: MpcMessage<Hash>) {
        match message {
            MpcMessage::Generating(message) => self.generating.push_back(message),
            MpcMessage::Resharing(message) => self
                .resharing_bins
                .entry(message.epoch)
                .or_default()
                .push_back(message),
            MpcMessage::Triple(message) => self
                .triple_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Presignature(message) => self
                .presignature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.id)
                .or_default()
                .push_back(message),
            MpcMessage::Signature(message) => self
                .signature_bins
                .entry(message.epoch)
                .or_default()
                .entry(message.receipt_id.clone())
                .or_default()
                .push_back(message),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MessageHandleError {
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error("failed to send a message: {0}")]
    SendError(String),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("invalid state")]
    InvalidStateHandle(String),
    #[error("secret storage error: {0}")]
    SecretStorageError(String),
}

impl From<CryptographicError> for MessageHandleError {
    fn from(value: CryptographicError) -> Self {
        match value {
            CryptographicError::CaitSithInitializationError(e) => {
                Self::CaitSithInitializationError(e)
            }
            CryptographicError::CaitSithProtocolError(e) => Self::CaitSithProtocolError(e),
            CryptographicError::SyncError(e) => Self::SyncError(e),
            CryptographicError::SendError(e) => Self::SendError(e),
            CryptographicError::UnknownParticipant(e) => Self::UnknownParticipant(e),
            CryptographicError::DataConversion(e) => Self::DataConversion(e),
            CryptographicError::Encryption(e) => Self::Encryption(e),
            CryptographicError::InvalidStateHandle(e) => Self::InvalidStateHandle(e),
            CryptographicError::SecretStorageError(e) => Self::SecretStorageError(e),
        }
    }
}

#[async_trait]
pub trait MessageHandler<AccountId, Hash> {
    async fn handle<C: MessageCtx<AccountId> + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue<Hash>,
    ) -> Result<(), MessageHandleError>;
}

#[async_trait]
impl<AccountId: Send + Sync, Hash: Send + Sync> MessageHandler<AccountId, Hash>
    for GeneratingState<AccountId, Hash>
{
    async fn handle<C: MessageCtx<AccountId> + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue<Hash>,
    ) -> Result<(), MessageHandleError> {
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = queue.generating.pop_front() {
            protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl<AccountId: Send + Sync, Hash: Send + Sync> MessageHandler<AccountId, Hash>
    for ResharingState<AccountId, Hash>
{
    async fn handle<C: MessageCtx<AccountId> + Send + Sync>(
        &mut self,
        _ctx: C,
        queue: &mut MpcMessageQueue<Hash>,
    ) -> Result<(), MessageHandleError> {
        let q = queue.resharing_bins.entry(self.old_epoch).or_default();
        let mut protocol = self.protocol.write().await;
        while let Some(msg) = q.pop_front() {
            protocol.message(msg.from, msg.data);
        }
        Ok(())
    }
}

#[async_trait]
impl<
        AccountId: Encode + Decode + Eq + Ord + Clone + std::fmt::Debug + Send + Sync,
        Hash: Clone + Eq + std::fmt::Debug + std::fmt::Display + std::hash::Hash + Send + Sync,
    > MessageHandler<AccountId, Hash> for RunningState<AccountId, Hash>
{
    async fn handle<C: MessageCtx<AccountId> + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue<Hash>,
    ) -> Result<(), MessageHandleError> {
        let peers = ctx.peers();
        let lock = peers.read().await;

        let participants = &lock.all_participants().clone();

        drop(lock);

        let mut triple_manager = self.triple_manager.write().await;

        // remove the triple_id that has already failed from the triple_bins
        queue
            .triple_bins
            .entry(self.epoch)
            .or_default()
            .retain(|id, _| {
                let has_failed = triple_manager.failed_triples.contains_key(id);
                if has_failed {
                    triple_manager.failed_triples.insert(*id, Instant::now());
                }
                !has_failed
            });

        for (id, queue) in queue.triple_bins.entry(self.epoch).or_default() {
            if let Some(protocol) = triple_manager.get_or_generate(*id, participants)? {
                while let Some(message) = queue.pop_front() {
                    protocol.message(message.from, message.data);
                }
            }
        }

        let mut presignature_manager = self.presignature_manager.write().await;
        for (id, queue) in queue.presignature_bins.entry(self.epoch).or_default() {
            let mut leftover_messages = Vec::new();
            while let Some(message) = queue.pop_front() {
                // Skip message if it already timed out
                if is_elapsed_longer_than_timeout(message.timestamp, PROTOCOL_PRESIG_TIMEOUT) {
                    continue;
                }

                match presignature_manager
                    .get_or_generate(
                        participants,
                        *id,
                        message.triple0,
                        message.triple1,
                        &mut triple_manager,
                        &self.public_key,
                        &self.private_share,
                    )
                    .await
                {
                    Ok(protocol) => protocol.message(message.from, message.data),
                    Err(presignature::GenerationError::AlreadyGenerated) => {}
                    Err(presignature::GenerationError::TripleIsGenerating(_)) => {
                        // Store the message until triple gets generated
                        leftover_messages.push(message)
                    }
                    Err(presignature::GenerationError::TripleIsMissing(_)) => {
                        // Store the message until triple is ready
                        leftover_messages.push(message)
                    }
                    Err(presignature::GenerationError::CaitSithInitializationError(error)) => {
                        return Err(error.into())
                    }
                    Err(presignature::GenerationError::DatastoreStorageError(_)) => {
                        // Store the message until we are ready to process it
                        leftover_messages.push(message)
                    }
                }
            }
            if !leftover_messages.is_empty() {
                queue.extend(leftover_messages);
            }
        }

        let mut signature_manager = self.signature_manager.write().await;
        for (receipt_id, queue) in queue.signature_bins.entry(self.epoch).or_default() {
            let mut leftover_messages = Vec::new();
            while let Some(message) = queue.pop_front() {
                // Skip message if it already timed out
                if is_elapsed_longer_than_timeout(message.timestamp, PROTOCOL_SIGNATURE_TIMEOUT) {
                    continue;
                }

                // TODO: make consistent with presignature manager AlreadyGenerated.
                if signature_manager.has_completed(&message.presignature_id) {
                    continue;
                }

                match signature_manager.get_or_generate(
                    participants,
                    receipt_id.clone(),
                    message.proposer,
                    message.presignature_id,
                    message.msg_hash,
                    message.epsilon,
                    message.delta,
                    &mut presignature_manager,
                )? {
                    Some(protocol) => protocol.message(message.from, message.data),
                    None => {
                        // Store the message until we are ready to process it
                        leftover_messages.push(message)
                    }
                }
            }
            if !leftover_messages.is_empty() {
                queue.extend(leftover_messages);
            }
        }
        triple_manager.clear_failed_triples();
        triple_manager.clear_taken();
        presignature_manager.clear_taken();
        Ok(())
    }
}

#[async_trait]
impl<
        AccountId: Send + Sync + Clone + Encode + Decode + Eq + Ord + std::fmt::Debug,
        Hash: Clone + Send + Sync + Eq + std::fmt::Debug + std::fmt::Display + std::hash::Hash,
    > MessageHandler<AccountId, Hash> for NodeState<AccountId, Hash>
{
    async fn handle<C: MessageCtx<AccountId> + Send + Sync>(
        &mut self,
        ctx: C,
        queue: &mut MpcMessageQueue<Hash>,
    ) -> Result<(), MessageHandleError> {
        match self {
            NodeState::Generating(state) => state.handle(ctx, queue).await,
            NodeState::Resharing(state) => state.handle(ctx, queue).await,
            NodeState::Running(state) => state.handle(ctx, queue).await,
            _ => Ok(()),
        }
    }
}

/// A signed message that can be encrypted. Note that the message's signature is included
/// in the encrypted message to avoid from it being tampered with without first decrypting.
#[derive(Serialize, Deserialize)]
pub struct SignedMessage<T> {
    /// The message with all it's related info.
    pub msg: T,
    /// The signature used to verify the authenticity of the encrypted message.
    pub sig: Signature,
    /// From which particpant the message was sent.
    pub from: Participant,
}

impl<T> SignedMessage<T> {
    pub const ASSOCIATED_DATA: &'static [u8] = b"";
}

impl<T> SignedMessage<T>
where
    T: Serialize,
{
    pub fn encrypt(
        msg: &T,
        from: Participant,
        sign_sk: &sp_core::sr25519::Pair,
        cipher_pk: &hpke::PublicKey,
    ) -> Result<Ciphered, CryptographicError> {
        let msg = serde_json::to_vec(msg)?;
        let sig = sign_sk.sign(&msg);
        let msg = SignedMessage { msg, sig, from };
        let msg = serde_json::to_vec(&msg)?;
        let ciphered = cipher_pk
            .encrypt(&msg, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|e| CryptographicError::Encryption(e.to_string()))?;
        Ok(ciphered)
    }
}

impl<T> SignedMessage<T>
where
    T: for<'a> Deserialize<'a>,
{
    pub async fn decrypt<AccountId: Clone + PartialEq, Hash: Clone>(
        cipher_sk: &hpke::SecretKey,
        protocol_state: &Arc<RwLock<NodeState<AccountId, Hash>>>,
        encrypted: Ciphered,
    ) -> Result<T, CryptographicError> {
        let message = cipher_sk
            .decrypt(&encrypted, SignedMessage::<T>::ASSOCIATED_DATA)
            .map_err(|err| CryptographicError::Encryption(err.to_string()))?;
        let SignedMessage::<Vec<u8>> { msg, sig, from } = serde_json::from_slice(&message)?;
        if !sig.verify(
            msg.as_slice(),
            &protocol_state
                .read()
                .await
                .fetch_participant(&from)?
                .sign_pk,
        ) {
            tracing::error!(from = ?from, "signed message erred out with invalid signature");
            return Err(CryptographicError::Encryption(
                "invalid signature while verifying authenticity of encrypted protocol message"
                    .to_string(),
            ));
        }

        Ok(serde_json::from_slice(&msg)?)
    }
}
