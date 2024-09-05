use crate::types::TransactionCreator;

use super::{
    cryptography::AppCryptoT,
    on_chain::{
        MpcKeysPublicKey, Participants, PeerIdEnc, ProtocolState, PublicKey, ResharingChainState,
    },
    presignature::PresignatureManager,
    signature::{SignQueue, SignatureManager},
    state::{
        GeneratingState, JoiningState, NodeState, PersistentNodeData, ResharingState, RunningState,
        StartedState, WaitingForConsensusState,
    },
    storage::{LockTripleNodeStorageBox, NodeStorageBox, TripleData},
    triple::TripleManager,
    types::{KeygenProtocol, ReshareProtocol, SecretKeyShare, TxPool},
    util::AffinePointExt,
    Config,
};
use async_trait::async_trait;
use cait_sith::protocol::{InitializationError, Participant};
use codec::{Decode, Encode};
use frame_system::offchain::{SendSignedTransaction, Signer};
use futures::{task::Poll, StreamExt};
use sc_keystore::LocalKeystore;
use sc_network::PeerId;
use sc_transaction_pool_api::{TransactionPool, TransactionSource, TransactionStatus};
use sp_api::ProvideRuntimeApi;
use sp_core::Pair;
use sp_runtime::{
    traits::{Block as BlockT, Extrinsic as ExtrinsicT, Verify},
    MultiSignature, MultiSigner,
};
use std::{cmp::Ordering, sync::Arc};
use substrate_frame_rpc_system::AccountNonceApi;
use tokio::sync::RwLock;

pub trait ConsensusCtx<AccountId, Block: BlockT, ChainClientT, TxPoolT> {
    fn my_account_id(&self) -> &AccountId;
    fn signer(&self) -> String;
    fn my_peer_id(&self) -> &PeerId;
    fn sign_queue(&self) -> Arc<RwLock<SignQueue<<Block as BlockT>::Hash>>>;
    fn secret_storage(&self) -> &NodeStorageBox;
    fn triple_storage(&self) -> LockTripleNodeStorageBox<AccountId>;
    fn cfg(&self) -> &Config;
    fn tx_pool(&self) -> Arc<TxPoolT>;
    fn client(&self) -> Arc<ChainClientT>;
    fn keystore(&self) -> Arc<LocalKeystore>;
}

#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("chain state has been rolled back")]
    ChainStateRollback,
    #[error("chain epoch has been rolled back")]
    EpochRollback,
    #[error("mismatched public key between chain state and local state")]
    MismatchedPublicKey,
    #[error("mismatched threshold between chain state and local state")]
    MismatchedThreshold,
    #[error("mismatched participant set between chain state and local state")]
    MismatchedParticipants,
    #[error("this node has been unexpectedly kicked from the participant set")]
    HasBeenKicked,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("secret storage error: {0}")]
    SecretStorageError(String),
    #[error("datastore storage error: {0}")]
    DatastoreStorageError(String),
    #[error("pre initialization")]
    PreInitializationState,
}

#[async_trait]
pub trait ConsensusProtocol<AccountId: Ord + Encode + Decode, Block: BlockT, ChainClientT, TxPoolT>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError>;
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Clone + Send + Sync + std::fmt::Debug,
        Block: BlockT,
        TxPoolT: sc_service::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash> + Send + Sync,
        ChainClientT: Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT> for StartedState<AccountId>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match self.persistent_node_data {
            Some(PersistentNodeData {
                epoch,
                private_share,
                public_key,
            }) => match chain_state {
                ProtocolState::Initializing(chain_state) => {
                    // TODO: Testing only, remove later

                    let participants: Participants<AccountId> =
                        chain_state.candidates.clone().try_into().unwrap();
                    match participants.find_participant(ctx.my_account_id()) {
                        Some(me) => {
                            tracing::info!(
                                "started(initializing) with loaded dump: In participant set, skipping key generation"
                            );
                            Ok(NodeState::WaitingForConsensus(WaitingForConsensusState {
                                epoch,
                                participants,
                                threshold: chain_state.threshold as usize,
                                private_share,
                                public_key,
                                messages: Default::default(),
                            }))
                        }
                        None => {
                            tracing::info!("started(initializing) with loaded dump: [TEST] forcing our entry in the set");

                            let pair = ctx.cfg().network_cfg.sign_sk.clone();
                            let public = pair.public();

                            let call = pallet_mpc_manager::pallet::Call::force_join {
                                peer_id: PeerIdEnc::from(*ctx.my_peer_id()),
                                cipher_pk: MpcKeysPublicKey::from_mpc_public_key(
                                    ctx.cfg().network_cfg.cipher_pk.clone().0,
                                ),
                                sign_pk: public,
                                threshold: 2,
                            };

                            let (xt, hash) =
                                TxCreator::create_transaction(ctx.client().clone(), pair, call);

                            let mut maybe_status = ctx
                                .tx_pool()
                                .submit_and_watch(hash, TransactionSource::External, xt.into())
                                .await
                                .expect("Failed to submit to tx pool.");

                            while let Some(status) = maybe_status.next().await {
                                match status {
                                    TransactionStatus::InBlock(_) => {
                                        return Ok(NodeState::Started(self));
                                    }
                                    TransactionStatus::Finalized(_) => {
                                        tracing::info!("Transaction finalized!");
                                    }

                                    TransactionStatus::Dropped => {
                                        tracing::info!("Transaction dropped.");
                                    }

                                    TransactionStatus::Invalid => {
                                        tracing::info!("Transaction invalid.");
                                    }

                                    _ => {}
                                }
                            }

                            Ok(NodeState::Started(self))
                        }
                    }
                }
                ProtocolState::Running(chain_state) => {
                    if chain_state.public_key.into_affine() != public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    match chain_state.epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                "started(running): our current epoch is {} while chain state's is {}, trying to rejoin as a new participant",
                                epoch,
                                chain_state.epoch
                            );
                            Ok(NodeState::Joining(JoiningState {
                                participants: chain_state.participants,
                                public_key,
                            }))
                        }
                        Ordering::Less => Err(ConsensusError::EpochRollback),
                        Ordering::Equal => {
                            let sign_queue = ctx.sign_queue();
                            match chain_state
                                .participants
                                .find_participant(ctx.my_account_id())
                            {
                                Some(me) => {
                                    tracing::info!(
                                        "started: chain state is running and we are already a participant"
                                    );
                                    let presignature_manager = PresignatureManager::new(
                                        me.into(),
                                        chain_state.threshold as usize,
                                        epoch,
                                        ctx.my_account_id(),
                                        &ctx.cfg().presig_cfg,
                                    );
                                    let triple_manager = TripleManager::new(
                                        me.into(),
                                        chain_state.threshold as usize,
                                        epoch,
                                        &ctx.cfg().triple_cfg,
                                        self.triple_data,
                                        ctx.triple_storage(),
                                        ctx.my_account_id(),
                                    );
                                    Ok(NodeState::Running(RunningState {
                                        epoch,
                                        participants: chain_state.participants,
                                        threshold: chain_state.threshold as usize,
                                        private_share,
                                        public_key,
                                        sign_queue,
                                        triple_manager: Arc::new(RwLock::new(triple_manager)),
                                        presignature_manager: Arc::new(RwLock::new(
                                            presignature_manager,
                                        )),
                                        signature_manager: Arc::new(RwLock::new(
                                            SignatureManager::new(
                                                me.into(),
                                                chain_state.public_key.into_affine(),
                                                epoch,
                                            ),
                                        )),
                                        messages: Default::default(),
                                    }))
                                }
                                None => Ok(NodeState::Joining(JoiningState {
                                    participants: chain_state.participants,
                                    public_key,
                                })),
                            }
                        }
                    }
                }
                ProtocolState::Resharing(chain_state) => {
                    if chain_state.public_key.into_affine() != public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    match chain_state.old_epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                "started(resharing): our current epoch is {} while chain state's is {}, trying to rejoin as a new participant",
                                epoch,
                                chain_state.old_epoch
                            );
                            Ok(NodeState::Joining(JoiningState {
                                participants: chain_state.old_participants,
                                public_key,
                            }))
                        }
                        Ordering::Less => Err(ConsensusError::EpochRollback),
                        Ordering::Equal => {
                            tracing::info!(
                                "started(resharing): chain state is resharing with us, joining as a participant"
                            );
                            start_resharing(Some(private_share), ctx, chain_state).await
                        }
                    }
                }
            },
            None => match chain_state {
                ProtocolState::Initializing(chain_state) => {
                    let participants: Participants<AccountId> =
                        chain_state.candidates.clone().try_into().unwrap();
                    match participants.find_participant(ctx.my_account_id()) {
                        Some(me) => {
                            tracing::info!(
                                "started(initializing): starting key generation as a part of the participant set"
                            );
                            let protocol = KeygenProtocol::new(
                                &participants
                                    .keys()
                                    .cloned()
                                    .map(|p| p.into())
                                    .collect::<Vec<Participant>>(),
                                me.into(),
                                chain_state.threshold as usize,
                            )?;
                            Ok(NodeState::Generating(GeneratingState {
                                participants,
                                threshold: chain_state.threshold as usize,
                                protocol,
                                messages: Default::default(),
                            }))
                        }
                        None => {
                            tracing::info!("started(initializing): we are not a part of the initial participant set, waiting for key generation to complete");

                            // TODO: Testing only, remove later

                            tracing::info!(
                                "started(initializing): [TEST] forcing our entry in the set"
                            );

                            let pair = ctx.cfg().network_cfg.sign_sk.clone();
                            let public = pair.public();

                            let call = pallet_mpc_manager::pallet::Call::force_join {
                                peer_id: PeerIdEnc::from(*ctx.my_peer_id()),
                                cipher_pk: MpcKeysPublicKey::from_mpc_public_key(
                                    ctx.cfg().network_cfg.cipher_pk.clone().0,
                                ),
                                sign_pk: public,
                                threshold: 2,
                            };

                            let (xt, hash) =
                                TxCreator::create_transaction(ctx.client().clone(), pair, call);

                            let mut maybe_status = ctx
                                .tx_pool()
                                .submit_and_watch(hash, TransactionSource::External, xt.into())
                                .await
                                .expect("Failed to submit to tx pool.");

                            while let Some(status) = maybe_status.next().await {
                                match status {
                                    TransactionStatus::InBlock(_) => {
                                        return Ok(NodeState::Started(self));
                                    }
                                    TransactionStatus::Finalized(_) => {
                                        tracing::info!("Transaction finalized!");
                                    }

                                    TransactionStatus::Dropped => {
                                        tracing::info!("Transaction dropped.");
                                    }

                                    TransactionStatus::Invalid => {
                                        tracing::info!("Transaction invalid.");
                                    }

                                    _ => {}
                                }
                            }

                            Ok(NodeState::Started(self))
                        }
                    }
                }
                ProtocolState::Running(chain_state) => Ok(NodeState::Joining(JoiningState {
                    participants: chain_state.participants,
                    public_key: chain_state.public_key.into_affine(),
                })),
                ProtocolState::Resharing(chain_state) => Ok(NodeState::Joining(JoiningState {
                    participants: chain_state.old_participants,
                    public_key: chain_state.public_key.into_affine(),
                })),
            },
        }
    }
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Send + Sync,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT>
    for GeneratingState<AccountId, <Block as BlockT>::Hash>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        _ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match chain_state {
            ProtocolState::Initializing(_) => {
                tracing::debug!("generating(initializing): continuing generation, chain state has not been finalized yet");

                Ok(NodeState::Generating(self))
            }
            ProtocolState::Running(chain_state) => {
                if chain_state.epoch > 0 {
                    tracing::warn!("generating(running): chain has already changed epochs, trying to rejoin as a new participant");
                    return Ok(NodeState::Joining(JoiningState {
                        participants: chain_state.participants,
                        public_key: chain_state.public_key.into_affine(),
                    }));
                }
                tracing::info!("generating(running): chain state has finished key generation, trying to catch up");
                if self.participants != chain_state.participants {
                    return Err(ConsensusError::MismatchedParticipants);
                }
                if self.threshold != chain_state.threshold as usize {
                    return Err(ConsensusError::MismatchedThreshold);
                }
                Ok(NodeState::Generating(self))
            }
            ProtocolState::Resharing(chain_state) => {
                if chain_state.old_epoch > 0 {
                    tracing::warn!("generating(resharing): chain has already changed epochs, trying to rejoin as a new participant");
                    return Ok(NodeState::Joining(JoiningState {
                        participants: chain_state.old_participants,
                        public_key: chain_state.public_key.into_affine(),
                    }));
                }
                tracing::warn!("generating(resharing): chain state is resharing without us, trying to catch up");
                if self.participants != chain_state.old_participants {
                    return Err(ConsensusError::MismatchedParticipants);
                }
                if self.threshold != chain_state.threshold as usize {
                    return Err(ConsensusError::MismatchedThreshold);
                }
                Ok(NodeState::Generating(self))
            }
        }
    }
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Clone + Send + Sync + std::fmt::Debug,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: sc_service::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash> + Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT>
    for WaitingForConsensusState<AccountId, <Block as BlockT>::Hash>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match chain_state {
            ProtocolState::Initializing(chain_state) => {
                tracing::debug!("waiting(initializing): waiting for consensus, chain state has not been finalized yet");
                let public_key = self.public_key.into_public_key();
                let has_voted = chain_state
                    .pk_votes
                    .get(&public_key)
                    .map(|ps| ps.contains(ctx.my_account_id()))
                    .unwrap_or_default();
                if !has_voted {
                    tracing::info!("waiting(initializing): we haven't voted yet, voting for the generated public key");

                    let pair = ctx.cfg().network_cfg.sign_sk.clone();

                    let call = pallet_mpc_manager::pallet::Call::vote_public_key {
                        public_key: PublicKey::from_affine(self.public_key),
                    };

                    let (xt, hash) =
                        TxCreator::create_transaction(ctx.client().clone(), pair, call);

                    let mut maybe_status = ctx
                        .tx_pool()
                        .submit_and_watch(hash, TransactionSource::External, xt.into())
                        .await
                        .expect("Failed to submit to tx pool.");

                    while let Some(status) = maybe_status.next().await {
                        match status {
                            TransactionStatus::InBlock(_) => {
                                return Ok(NodeState::WaitingForConsensus(self));
                            }
                            TransactionStatus::Finalized(_) => {
                                tracing::info!("Transaction finalized!");
                            }

                            TransactionStatus::Dropped => {
                                tracing::info!("Transaction dropped.");
                            }

                            TransactionStatus::Invalid => {
                                tracing::info!("Transaction invalid.");
                            }

                            _ => {}
                        }
                    }
                }
                Ok(NodeState::WaitingForConsensus(self))
            }
            ProtocolState::Running(chain_state) => match chain_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                            "waiting(running): our current epoch is {} while chain state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            chain_state.epoch
                        );

                    Ok(NodeState::Joining(JoiningState {
                        participants: chain_state.participants,
                        public_key: chain_state.public_key.into_affine(),
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::info!("waiting(running): chain state has reached consensus");

                    if chain_state.participants != self.participants {
                        return Err(ConsensusError::MismatchedParticipants);
                    }
                    if chain_state.threshold as usize != self.threshold {
                        return Err(ConsensusError::MismatchedThreshold);
                    }
                    if chain_state.public_key.into_affine() != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }

                    let me = chain_state
                        .participants
                        .find_participant(ctx.my_account_id())
                        .unwrap()
                        .into();

                    let triple_manager = TripleManager::new(
                        me,
                        self.threshold,
                        self.epoch,
                        &ctx.cfg().triple_cfg,
                        vec![],
                        ctx.triple_storage(),
                        ctx.my_account_id(),
                    );

                    // For testing purposes.
                    // tracing::debug!("dumping node data");
                    // PersistentNodeData {
                    //     epoch: self.epoch,
                    //     private_share: self.private_share,
                    //     public_key: self.public_key,
                    // }
                    // .dump(ctx.my_account_id().to_string());

                    Ok(NodeState::Running(RunningState {
                        epoch: self.epoch,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: self.private_share,
                        public_key: self.public_key,
                        sign_queue: ctx.sign_queue(),
                        triple_manager: Arc::new(RwLock::new(triple_manager)),
                        presignature_manager: Arc::new(RwLock::new(PresignatureManager::new(
                            me,
                            self.threshold,
                            self.epoch,
                            ctx.my_account_id(),
                            &ctx.cfg().presig_cfg,
                        ))),
                        signature_manager: Arc::new(RwLock::new(SignatureManager::new(
                            me,
                            self.public_key,
                            self.epoch,
                        ))),
                        messages: self.messages,
                    }))
                }
            },
            ProtocolState::Resharing(chain_state) => {
                match (chain_state.old_epoch + 1).cmp(&self.epoch) {
                    Ordering::Greater if chain_state.old_epoch + 2 == self.epoch => {
                        tracing::info!("waiting(resharing): chain state is resharing, joining");
                        if chain_state.old_participants != self.participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if chain_state.threshold as usize != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if chain_state.public_key.into_affine() != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        start_resharing(Some(self.private_share), ctx, chain_state).await
                    }
                    Ordering::Greater => {
                        tracing::warn!(
                            "waiting(resharing): our current epoch is {} while chain state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            chain_state.old_epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: chain_state.old_participants,
                            public_key: chain_state.public_key.into_affine(),
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::debug!(
                            "waiting(resharing): waiting for resharing consensus, chain state has not been finalized yet"
                        );
                        let has_voted = chain_state.finished_votes.contains(ctx.my_account_id());
                        match chain_state
                            .old_participants
                            .find_participant(ctx.my_account_id())
                        {
                            Some(_) => {
                                if !has_voted {
                                    tracing::info!(
                                        epoch = self.epoch,
                                        "waiting(resharing): we haven't voted yet, voting for resharing to complete"
                                    );

                                    // TODO: Send transaction to chain. Vote Reshared.
                                } else {
                                    tracing::info!(
                                        epoch = self.epoch,
                                        "waiting(resharing): we have voted for resharing to complete"
                                    );
                                }
                            }
                            None => {
                                tracing::info!("waiting(resharing): we are not a part of the old participant set");
                            }
                        }
                        Ok(NodeState::WaitingForConsensus(self))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Clone + Send + Sync,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT>
    for RunningState<AccountId, <Block as BlockT>::Hash>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match chain_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ChainStateRollback),
            ProtocolState::Running(chain_state) => match chain_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                            "running(running): our current epoch is {} while chain state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            chain_state.epoch
                        );

                    Ok(NodeState::Joining(JoiningState {
                        participants: chain_state.participants,
                        public_key: chain_state.public_key.into_affine(),
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::debug!("running(running): continuing to run as normal");
                    if chain_state.participants != self.participants {
                        return Err(ConsensusError::MismatchedParticipants);
                    }
                    if chain_state.threshold as usize != self.threshold {
                        return Err(ConsensusError::MismatchedThreshold);
                    }
                    if chain_state.public_key.into_affine() != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    Ok(NodeState::Running(self))
                }
            },
            ProtocolState::Resharing(chain_state) => match chain_state.old_epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                            "running(resharing): our current epoch is {} while chain state's is {}, trying to rejoin as a new participant",
                            self.epoch,
                            chain_state.old_epoch
                        );

                    Ok(NodeState::Joining(JoiningState {
                        participants: chain_state.old_participants,
                        public_key: chain_state.public_key.into_affine(),
                    }))
                }
                Ordering::Less => Err(ConsensusError::EpochRollback),
                Ordering::Equal => {
                    tracing::info!("running(resharing): chain is resharing");
                    let is_in_old_participant_set = chain_state
                        .old_participants
                        .contains_account_id(ctx.my_account_id());
                    let is_in_new_participant_set = chain_state
                        .new_participants
                        .contains_account_id(ctx.my_account_id());
                    if !is_in_old_participant_set || !is_in_new_participant_set {
                        return Err(ConsensusError::HasBeenKicked);
                    }
                    if chain_state.public_key.into_affine() != self.public_key {
                        return Err(ConsensusError::MismatchedPublicKey);
                    }
                    start_resharing(Some(self.private_share), ctx, chain_state).await
                }
            },
        }
    }
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Clone + Send + Sync,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT>
    for ResharingState<AccountId, <Block as BlockT>::Hash>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        _ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match chain_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ChainStateRollback),
            ProtocolState::Running(chain_state) => {
                match chain_state.epoch.cmp(&(self.old_epoch + 1)) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "resharing(running): expected epoch {} while chain state's is {}, trying to rejoin as a new participant",
                            self.old_epoch + 1,
                            chain_state.epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: chain_state.participants,
                            public_key: chain_state.public_key.into_affine(),
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::info!("resharing(running): chain state has finished resharing, trying to catch up");
                        if chain_state.participants != self.new_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if chain_state.threshold as usize != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if chain_state.public_key.into_affine() != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        Ok(NodeState::Resharing(self))
                    }
                }
            }
            ProtocolState::Resharing(chain_state) => {
                match chain_state.old_epoch.cmp(&self.old_epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            "resharing(resharing): expected resharing from epoch {} while chain is resharing from {}, trying to rejoin as a new participant",
                            self.old_epoch,
                            chain_state.old_epoch
                        );

                        Ok(NodeState::Joining(JoiningState {
                            participants: chain_state.old_participants,
                            public_key: chain_state.public_key.into_affine(),
                        }))
                    }
                    Ordering::Less => Err(ConsensusError::EpochRollback),
                    Ordering::Equal => {
                        tracing::debug!("resharing(resharing): continue to reshare as normal");
                        if chain_state.old_participants != self.old_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if chain_state.new_participants != self.new_participants {
                            return Err(ConsensusError::MismatchedParticipants);
                        }
                        if chain_state.threshold as usize != self.threshold {
                            return Err(ConsensusError::MismatchedThreshold);
                        }
                        if chain_state.public_key.into_affine() != self.public_key {
                            return Err(ConsensusError::MismatchedPublicKey);
                        }
                        Ok(NodeState::Resharing(self))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Clone + Send + Sync + std::fmt::Debug,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT> for JoiningState<AccountId>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match chain_state {
            ProtocolState::Initializing(_) => Err(ConsensusError::ChainStateRollback),
            ProtocolState::Running(chain_state) => {
                match chain_state.candidates.find_candidate(ctx.my_account_id()) {
                    Some(_) => {
                        let votes = chain_state
                            .join_votes
                            .get(ctx.my_account_id())
                            .unwrap_or_default();
                        let participant_account_ids_to_vote = chain_state
                            .participants
                            .iter()
                            .map(|(_, info)| &info.account_id)
                            .filter(|id| !votes.contains(*id))
                            .collect::<Vec<_>>();
                        if !participant_account_ids_to_vote.is_empty() {
                            tracing::info!(
                                ?participant_account_ids_to_vote,
                                "Some participants have not voted for you to join"
                            );
                        }
                        Ok(NodeState::Joining(self))
                    }
                    None => {
                        tracing::info!(
                            "joining(running): sending a transaction to join the participant set"
                        );

                        // TODO: Send transaction to chain. Join participant set.
                        Ok(NodeState::Joining(self))
                    }
                }
            }
            ProtocolState::Resharing(chain_state) => {
                if chain_state
                    .new_participants
                    .contains_account_id(ctx.my_account_id())
                {
                    tracing::info!("joining(resharing): joining as a new participant");
                    start_resharing(None, ctx, chain_state).await
                } else {
                    tracing::debug!("joining(resharing): network is resharing without us, waiting for them to finish");
                    Ok(NodeState::Joining(self))
                }
            }
        }
    }
}

#[async_trait]
impl<
        AccountId: Ord + Encode + Decode + Clone + Send + Sync + std::fmt::Debug,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: sc_service::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash> + Send + Sync,
    > ConsensusProtocol<AccountId, Block, ChainClientT, TxPoolT>
    for NodeState<AccountId, <Block as BlockT>::Hash>
{
    async fn advance<
        C: ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT> + Send + Sync,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
        ctx: C,
        chain_state: ProtocolState<AccountId>,
    ) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
        match self {
            NodeState::Starting => {
                let persistent_node_data = ctx
                    .secret_storage()
                    .load()
                    .await
                    .map_err(|e| ConsensusError::SecretStorageError(e.to_string()))?;
                let triple_data = load_triples(ctx).await?;
                Ok(NodeState::Started(StartedState {
                    persistent_node_data,
                    triple_data,
                }))
            }

            NodeState::Started(state) => {
                state
                    .advance::<C, Runtime, TxCreator>(ctx, chain_state)
                    .await
            }
            NodeState::Generating(state) => {
                state
                    .advance::<C, Runtime, TxCreator>(ctx, chain_state)
                    .await
            }
            NodeState::WaitingForConsensus(state) => {
                state
                    .advance::<C, Runtime, TxCreator>(ctx, chain_state)
                    .await
            }
            NodeState::Running(state) => {
                state
                    .advance::<C, Runtime, TxCreator>(ctx, chain_state)
                    .await
            }
            NodeState::Resharing(state) => {
                state
                    .advance::<C, Runtime, TxCreator>(ctx, chain_state)
                    .await
            }
            NodeState::Joining(state) => {
                state
                    .advance::<C, Runtime, TxCreator>(ctx, chain_state)
                    .await
            }
        }
    }
}

async fn load_triples<
    AccountId,
    Block: BlockT,
    TxPool,
    ChainClient,
    C: ConsensusCtx<AccountId, Block, TxPool, ChainClient> + Send + Sync,
>(
    ctx: C,
) -> Result<Vec<TripleData<AccountId>>, ConsensusError> {
    let triple_storage = ctx.triple_storage();
    let mut retries = 3;
    let mut error = None;
    while retries > 0 {
        let read_lock = triple_storage.read().await;
        match read_lock.load().await {
            //Err(DatastoreStorageError::FetchEntitiesError(_)) => {
            //    tracing::info!("There are no triples persisted.");
            //    return Ok(vec![]);
            //}
            Err(e) => {
                retries -= 1;
                tracing::warn!(?e, "triple load failed.");
                error = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Ok(loaded_triples) => return Ok(loaded_triples),
        }
    }
    Err(ConsensusError::DatastoreStorageError(error.unwrap()))
}

async fn start_resharing<
    AccountId: Eq + Encode + Decode + Clone,
    Block: BlockT,
    TxPool,
    ChainClient,
    C: ConsensusCtx<AccountId, Block, TxPool, ChainClient>,
>(
    private_share: Option<SecretKeyShare>,
    ctx: C,
    chain_state: ResharingChainState<AccountId>,
) -> Result<NodeState<AccountId, <Block as BlockT>::Hash>, ConsensusError> {
    let me = chain_state
        .new_participants
        .find_participant(ctx.my_account_id())
        .unwrap()
        .into();
    let protocol = ReshareProtocol::new(private_share, me, &chain_state)?;
    Ok(NodeState::Resharing(ResharingState {
        old_epoch: chain_state.old_epoch,
        old_participants: chain_state.old_participants,
        new_participants: chain_state.new_participants,
        threshold: chain_state.threshold as usize,
        public_key: chain_state.public_key.into_affine(),
        protocol,
        messages: Default::default(),
    }))
}
