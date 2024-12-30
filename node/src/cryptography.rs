use crate::types::TransactionCreator;

use super::{
    communication::Peers,
    message::{GeneratingMessage, MpcMessage, ResharingMessage},
    state::{
        GeneratingState, NodeState, PersistentNodeData, ResharingState, RunningState,
        WaitingForConsensusState,
    },
    storage::NodeStorageBox,
    Config,
};
use async_trait::async_trait;
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use codec::{Decode, Encode};
use frame_system::offchain::{AppCrypto, Signer, SigningTypes};
use k256::elliptic_curve::group::GroupEncoding;
use sc_network::{NotificationService, PeerId};
use serde::Serialize;
use sp_application_crypto::{app_crypto, sr25519, KeyTypeId};
use sp_runtime::{
    traits::{Block as BlockT, Extrinsic as ExtrinsicT},
    MultiSignature, MultiSigner,
};
use std::sync::{Arc, PoisonError};
use tokio::sync::{mpsc::Sender, Mutex, RwLock};

pub mod ac {
    use sp_application_crypto::{app_crypto, sr25519, KeyTypeId};
    app_crypto!(sr25519, KeyTypeId(*b"ctss"));
}

pub struct AppCryptoT;
impl AppCrypto<MultiSigner, MultiSignature> for AppCryptoT {
    type RuntimeAppPublic = ac::Public;
    type GenericPublic = sp_core::sr25519::Public;
    type GenericSignature = sp_core::sr25519::Signature;
}

#[async_trait::async_trait]
pub trait CryptographicCtx<TxPool, ChainClient, AccountId> {
    async fn me(&self) -> Participant;
    fn signer(&self) -> String;
    fn node_storage(&mut self) -> &mut NodeStorageBox;
    fn cfg(&self) -> &Config;
    fn tx_pool(&self) -> Arc<TxPool>;
    fn client(&self) -> Arc<ChainClient>;

    fn peers(&self) -> Arc<RwLock<Peers<AccountId>>>;

    fn notif_handle(&self) -> Sender<(PeerId, Vec<u8>)>;
}

#[derive(thiserror::Error, Debug)]
pub enum CryptographicError {
    #[error("failed to send a message: {0}")]
    SendError(String),
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Participant),
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("cait-sith protocol error: {0}")]
    CaitSithProtocolError(#[from] ProtocolError),
    #[error("sync failed: {0}")]
    SyncError(String),
    #[error(transparent)]
    DataConversion(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("more than one writing to state: {0}")]
    InvalidStateHandle(String),
    #[error("secret storage error: {0}")]
    SecretStorageError(String),
}

impl<T> From<PoisonError<T>> for CryptographicError {
    fn from(_: PoisonError<T>) -> Self {
        let typename = std::any::type_name::<T>();
        Self::SyncError(format!("PoisonError: {typename}"))
    }
}

#[async_trait]
pub trait CryptographicProtocol<
    Runtime,
    Block,
    AccountId,
    Hash: Clone,
    TxPool,
    ChainClient,
    TxCreator,
>
{
    async fn progress<C: CryptographicCtx<TxPool, ChainClient, AccountId> + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<NodeState<AccountId, Hash>, CryptographicError>;
}

#[async_trait]
impl<
        Runtime,
        Block: BlockT,
        AccountId: Clone + Encode + Decode + Eq + Ord + std::fmt::Debug + Send + Sync,
        Hash: Clone + Serialize + Send + Sync,
        TxPool: Send + Sync,
        ChainClient: Send + Sync,
        TxCreator,
    > CryptographicProtocol<Runtime, Block, AccountId, Hash, TxPool, ChainClient, TxCreator>
    for GeneratingState<AccountId, Hash>
{
    async fn progress<C: CryptographicCtx<TxPool, ChainClient, AccountId> + Send + Sync>(
        mut self,
        mut ctx: C,
    ) -> Result<NodeState<AccountId, Hash>, CryptographicError> {
        let unlocked = ctx.peers();
        let peers = unlocked.read().await;

        let active_participants = peers.active_participants().clone();

        drop(peers);

        tracing::info!(active = ?active_participants.keys_vec(), "generating: progressing key generation");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh keygen protocol");
                    }
                    return Err(err)?;
                }
            };

            tracing::debug!("poking Keygen Protocol resulted in: {:?}", action);

            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("generating: waiting");

                    let me = ctx.me().await;

                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            me,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.notif_handle().clone(),
                            &active_participants,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active_participants.keys_vec(),
                            "generating(wait): failed to send encrypted message; {failures:?}"
                        );
                    }

                    return Ok(NodeState::Generating(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("generating: sending a message to many participants");
                    let mut messages = self.messages.write().await;
                    for (p, info) in active_participants.iter() {
                        if Participant::from(*p) == ctx.me().await {
                            // Skip yourself, cait-sith never sends messages to oneself
                            tracing::debug!("Skipping ourselves");
                            continue;
                        }
                        messages.push(
                            info.clone(),
                            MpcMessage::Generating(GeneratingMessage {
                                from: ctx.me().await,
                                data: data.clone(),
                            }),
                        );
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("generating: sending a private message to {to:?}");
                    let info = self.fetch_participant(&to)?;
                    self.messages.write().await.push(
                        info.clone(),
                        MpcMessage::Generating(GeneratingMessage {
                            from: ctx.me().await,
                            data,
                        }),
                    );
                }
                Action::Return(r) => {
                    tracing::info!(
                        public_key = hex::encode(r.public_key.to_bytes()),
                        "generating: successfully completed key generation"
                    );
                    ctx.node_storage()
                        .store(&PersistentNodeData {
                            epoch: 0,
                            private_share: r.private_share,
                            public_key: r.public_key,
                        })
                        .await
                        .map_err(|e| CryptographicError::SecretStorageError(e.to_string()))?;

                    let me = ctx.me().await;

                    // Send any leftover messages
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            me,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.notif_handle().clone(),
                            &active_participants,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active_participants.keys_vec(),
                            "generating(return): failed to send encrypted message; {failures:?}"
                        );
                    }
                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: 0,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: r.private_share,
                        public_key: r.public_key,
                        messages: self.messages,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl<
        Runtime,
        Block: BlockT,
        AccountId: Clone + Encode + Decode + Eq + Ord + std::fmt::Debug + Send + Sync,
        Hash: Clone + Serialize + Send + Sync,
        TxPool: Send + Sync,
        ChainClient: Send + Sync,
        TxCreator,
    > CryptographicProtocol<Runtime, Block, AccountId, Hash, TxPool, ChainClient, TxCreator>
    for WaitingForConsensusState<AccountId, Hash>
{
    async fn progress<C: CryptographicCtx<TxPool, ChainClient, AccountId> + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState<AccountId, Hash>, CryptographicError> {
        let unlocked = ctx.peers();
        let peers = unlocked.read().await;

        let active_participants = peers.active_participants().clone();

        drop(peers);

        let me = ctx.me().await;

        let failures = self
            .messages
            .write()
            .await
            .send_encrypted(
                me,
                &ctx.cfg().network_cfg.sign_sk,
                ctx.notif_handle().clone(),
                &active_participants,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?active_participants.keys_vec(),
                "waitingForConsensus: failed to send encrypted message; {failures:?}"
            );
        }

        // Wait for ConsensusProtocol step to advance state
        Ok(NodeState::WaitingForConsensus(self))
    }
}

#[async_trait]
impl<
        Runtime,
        Block: BlockT,
        AccountId: Clone + Encode + Decode + Eq + Ord + std::fmt::Debug + Send + Sync,
        Hash: Clone + Serialize + Send + Sync,
        TxPool: Send + Sync,
        ChainClient: Send + Sync,
        TxCreator,
    > CryptographicProtocol<Runtime, Block, AccountId, Hash, TxPool, ChainClient, TxCreator>
    for ResharingState<AccountId, Hash>
{
    async fn progress<C: CryptographicCtx<TxPool, ChainClient, AccountId> + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState<AccountId, Hash>, CryptographicError> {
        let unlocked = ctx.peers();
        let peers = unlocked.read().await;

        // TODO: we are not using active potential participants here, but we should in the future.
        // Currently resharing protocol does not timeout and restart with new set of participants.
        // So if it picks up a participant that is not active, it will never be able to send a message to it.
        let active = peers.active_participants().clone();

        //.and(&ctx.peers().potential_participants().await);

        drop(peers);

        tracing::info!(active = ?active.keys().collect::<Vec<_>>(), "progressing key reshare");
        let mut protocol = self.protocol.write().await;
        loop {
            let action = match protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    drop(protocol);
                    if let Err(refresh_err) = self.protocol.refresh().await {
                        tracing::warn!(?refresh_err, "unable to refresh reshare protocol");
                    }
                    return Err(err)?;
                }
            };
            match action {
                Action::Wait => {
                    drop(protocol);
                    tracing::debug!("resharing: waiting");
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.notif_handle().clone(),
                            &active,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(wait): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::Resharing(self));
                }
                Action::SendMany(data) => {
                    tracing::debug!("resharing: sending a message to all participants");
                    let me = ctx.me().await;
                    let mut messages = self.messages.write().await;
                    for (p, info) in self.new_participants.iter() {
                        if Participant::from(*p) == me {
                            // Skip yourself, cait-sith never sends messages to oneself
                            continue;
                        }

                        messages.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: me,
                                data: data.clone(),
                            }),
                        )
                    }
                }
                Action::SendPrivate(to, data) => {
                    tracing::debug!("resharing: sending a private message to {to:?}");
                    match self.new_participants.get(&to.into()) {
                        Some(info) => self.messages.write().await.push(
                            info.clone(),
                            MpcMessage::Resharing(ResharingMessage {
                                epoch: self.old_epoch,
                                from: ctx.me().await,
                                data,
                            }),
                        ),
                        None => return Err(CryptographicError::UnknownParticipant(to)),
                    }
                }
                Action::Return(private_share) => {
                    tracing::debug!("resharing: successfully completed key reshare");

                    // Send any leftover messages.
                    let failures = self
                        .messages
                        .write()
                        .await
                        .send_encrypted(
                            ctx.me().await,
                            &ctx.cfg().network_cfg.sign_sk,
                            ctx.notif_handle().clone(),
                            &active,
                        )
                        .await;
                    if !failures.is_empty() {
                        tracing::warn!(
                            active = ?active.keys_vec(),
                            new = ?self.new_participants,
                            old = ?self.old_participants,
                            "resharing(return): failed to send encrypted message; {failures:?}",
                        );
                    }

                    return Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                        epoch: self.old_epoch + 1,
                        participants: self.new_participants,
                        threshold: self.threshold,
                        private_share,
                        public_key: self.public_key,
                        messages: self.messages,
                    }));
                }
            }
        }
    }
}

#[async_trait]
impl<
        Runtime: pallet_mpc_manager::Config,
        Block: BlockT,
        AccountId: Clone + Encode + Decode + Eq + Ord + std::fmt::Debug + Send + Sync,
        Hash: Clone
            + Serialize
            + Send
            + Sync
            + std::fmt::Debug
            + std::fmt::Display
            + Eq
            + std::hash::Hash
            + Default,
        TxPool: sc_transaction_pool_api::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash>
            + Send
            + Sync,
        ChainClient: Send + Sync,
        TxCreator: TransactionCreator<Block, ChainClient, pallet_mpc_manager::Call<Runtime>>,
    > CryptographicProtocol<Runtime, Block, AccountId, Hash, TxPool, ChainClient, TxCreator>
    for RunningState<AccountId, Hash>
{
    async fn progress<C: CryptographicCtx<TxPool, ChainClient, AccountId> + Send + Sync>(
        mut self,
        ctx: C,
    ) -> Result<NodeState<AccountId, Hash>, CryptographicError> {
        let unlocked = ctx.peers();
        let peers = unlocked.read().await;

        let all_participants = peers.all_participants().clone();
        let active_participants = peers.active_participants().clone();

        drop(peers);

        if all_participants.len() < self.threshold {
            tracing::info!(
                active = ?all_participants.keys_vec(),
                "running: not enough participants to progress"
            );
            return Ok(NodeState::Running(self));
        }

        let mut messages = self.messages.write().await;
        let mut triple_manager = self.triple_manager.write().await;
        let my_account_id = triple_manager.my_account_id.clone();

        triple_manager.stockpile(&all_participants)?;
        for (p, msg) in triple_manager.poke().await? {
            if p == ctx.me().await {
                // Skip yourself, cait-sith never sends messages to oneself
                tracing::debug!("Skipping ourselves");
                continue;
            }

            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Triple(msg));
        }

        let mut presignature_manager = self.presignature_manager.write().await;
        presignature_manager
            .stockpile(
                &all_participants,
                &self.public_key,
                &self.private_share,
                &mut triple_manager,
            )
            .await?;
        drop(triple_manager);
        for (p, msg) in presignature_manager.poke()? {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Presignature(msg));
        }

        let mut sign_queue = self.sign_queue.write().await;

        let mut signature_manager = self.signature_manager.write().await;
        sign_queue.organize(
            self.threshold,
            &all_participants,
            ctx.me().await,
            &my_account_id,
        );
        let my_requests = sign_queue.my_requests(ctx.me().await);

        let mut failed_presigs = Vec::new();
        while presignature_manager.my_len() > 0 {
            if let Some((receipt_id, failed_generator)) = signature_manager.take_failed_generator()
            {
                // only retry the failed signature generator if the proposer of the signature is me
                if failed_generator.proposer == signature_manager.me() {
                    let Some(presignature) = presignature_manager.take_mine() else {
                        break;
                    };
                    let sig_participants = all_participants.intersection(&[&presignature
                        .participants
                        .clone()
                        .into_iter()
                        .map(|p| p.into())
                        .collect::<Vec<super::on_chain::ParticipantEnc>>()]);
                    if sig_participants.len() < self.threshold {
                        tracing::debug!(
                            participants = ?sig_participants.keys_vec(),
                            "running: we don't have enough participants to generate a failed signature"
                        );
                        failed_presigs.push(presignature);
                        continue;
                    }

                    signature_manager.retry_failed_generation(
                        receipt_id,
                        &failed_generator,
                        presignature,
                        &sig_participants,
                    );
                }
            }

            let Some((receipt_id, _)) = my_requests.iter().next() else {
                break;
            };

            let Some(presignature) = presignature_manager.take_mine() else {
                break;
            };

            let receipt_id = receipt_id.clone();
            let sig_participants = all_participants.intersection(&[&presignature
                .participants
                .clone()
                .into_iter()
                .map(|p| p.into())
                .collect::<Vec<super::on_chain::ParticipantEnc>>()]);
            if sig_participants.len() < self.threshold {
                tracing::debug!(
                    participants = ?sig_participants.keys_vec(),
                    "running: we don't have enough participants to generate a signature"
                );
                failed_presigs.push(presignature);
                continue;
            }

            let my_request = my_requests.remove(&receipt_id).unwrap();
            signature_manager.generate(
                &sig_participants,
                receipt_id,
                presignature,
                self.public_key,
                my_request.msg_hash,
                my_request.epsilon,
                my_request.delta,
                my_request.time_added,
            )?;
        }
        drop(sign_queue);
        for presignature in failed_presigs {
            presignature_manager.insert_mine(presignature);
        }
        drop(presignature_manager);
        for (p, msg) in signature_manager.poke() {
            let info = self.fetch_participant(&p)?;
            messages.push(info.clone(), MpcMessage::Signature(msg));
        }

        let pair = ctx.cfg().network_cfg.sign_sk.clone();
        let client = ctx.client();
        let tx_pool = ctx.tx_pool();

        signature_manager
            .publish::<Block, ChainClient, TxPool, Runtime, TxCreator>(pair, client, tx_pool)
            .await
            .map_err(|e| CryptographicError::SendError(e))?;

        drop(signature_manager);
        let failures = messages
            .send_encrypted(
                ctx.me().await,
                &ctx.cfg().network_cfg.sign_sk,
                ctx.notif_handle().clone(),
                &active_participants,
            )
            .await;
        if !failures.is_empty() {
            tracing::warn!(
                active = ?active_participants.keys_vec(),
                "running: failed to send encrypted message; {failures:?}"
            );
        }
        drop(messages);

        Ok(NodeState::Running(self))
    }
}

#[async_trait]
impl<
        Runtime: pallet_mpc_manager::Config,
        Block: BlockT,
        AccountId: Clone + Encode + Decode + Eq + Ord + std::fmt::Debug + Send + Sync,
        Hash: Clone
            + Serialize
            + Send
            + Sync
            + std::fmt::Debug
            + std::fmt::Display
            + Eq
            + std::hash::Hash
            + Default,
        TxPool: sc_transaction_pool_api::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash>
            + Send
            + Sync,
        ChainClient: Send + Sync,
        TxCreator: TransactionCreator<Block, ChainClient, pallet_mpc_manager::Call<Runtime>>,
    > CryptographicProtocol<Runtime, Block, AccountId, Hash, TxPool, ChainClient, TxCreator>
    for NodeState<AccountId, Hash>
{
    async fn progress<C: CryptographicCtx<TxPool, ChainClient, AccountId> + Send + Sync>(
        self,
        ctx: C,
    ) -> Result<NodeState<AccountId, Hash>, CryptographicError> {
        match self {
            NodeState::Generating(state) => {
                <GeneratingState<AccountId, Hash> as CryptographicProtocol<
                    Runtime,
                    Block,
                    AccountId,
                    Hash,
                    TxPool,
                    ChainClient,
                    TxCreator,
                >>::progress::<'_, C>(state, ctx)
                .await
            }
            NodeState::Resharing(state) => {
                <ResharingState<AccountId, Hash> as CryptographicProtocol<
                    Runtime,
                    Block,
                    AccountId,
                    Hash,
                    TxPool,
                    ChainClient,
                    TxCreator,
                >>::progress::<'_, C>(state, ctx)
                .await
            }
            NodeState::Running(state) => {
                <RunningState<AccountId, Hash> as CryptographicProtocol<
                    Runtime,
                    Block,
                    AccountId,
                    Hash,
                    TxPool,
                    ChainClient,
                    TxCreator,
                >>::progress::<'_, C>(state, ctx)
                .await
            }
            NodeState::WaitingForConsensus(state) => {
                <WaitingForConsensusState<AccountId, Hash> as CryptographicProtocol<
                    Runtime,
                    Block,
                    AccountId,
                    Hash,
                    TxPool,
                    ChainClient,
                    TxCreator,
                >>::progress::<'_, C>(state, ctx)
                .await
            }
            _ => Ok(self),
        }
    }
}
