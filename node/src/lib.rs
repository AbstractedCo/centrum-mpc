mod communication;
mod cryptography;
mod error;
mod kdf;
mod message;
mod mpc_keys;
mod on_chain;
mod presignature;
mod protocol;
mod signature;
mod state;
mod storage;
mod triple;
pub mod types;
mod util;

use crate::{
    cryptography::{CryptographicError, CryptographicProtocol},
    message::{MessageHandler, SignedMessage},
    mpc_keys::Ciphered,
    on_chain::{ProtocolState, RunningChainState},
    protocol::ConsensusProtocol,
    signature::SignRequest,
    storage::{MemoryNodeStorage, MemoryTripleNodeStorage, OffchainNodeStorage},
    types::{NetServ, TxPool, TxPoolNoArc},
    util::ScalarExt,
};
use cait_sith::protocol::Participant;
use codec::{Decode, Encode};
use frame_system::offchain::{SendSignedTransaction, Signer};
use futures::{channel::mpsc::Receiver, FutureExt};
use k256::Scalar;
use log::error;
use pallet_mpc_manager_runtime_api::MpcManagerApi;
use sc_client_api::Backend;
use sc_client_db::offchain::LocalStorage;
use sc_keystore::{Keystore, LocalKeystore};
use sc_network::{
    network_state::Peer,
    peer_store::{PeerStoreHandle, PeerStoreProvider},
    service::traits::{NetworkService, NotificationEvent},
    NetworkEventStream, NetworkStateInfo, NotificationService, PeerId,
};
use sc_service::{NativeExecutionDispatch, TaskManager};
use sc_transaction_pool::BasicPool;
use sp_api::{ApiExt, CallApiAt, CallApiAtParams, ProvideRuntimeApi};
use sp_application_crypto::KeyTypeId;
use sp_core::Pair;
use sp_keystore::{KeystoreExt, KeystorePtr};
use sp_runtime::traits::{Block as BlockT, Extrinsic as ExtrinsicT};
use state::NodeState;
use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use threadpool::ThreadPool;
use tokio::{
    sync::{
        mpsc::{self, error::TryRecvError, Sender},
        Mutex, RwLock,
    },
    task::JoinHandle,
};
use types::{ChainClient, TransactionCreator};

use self::{
    communication::{NetworkConfig, Peers},
    cryptography::{AppCryptoT, CryptographicCtx},
    message::{MessageCtx, MpcMessage, MpcMessageQueue},
    on_chain::{ParticipantInfo, Participants},
    presignature::PresignatureConfig,
    protocol::ConsensusCtx,
    signature::SignQueue,
    storage::{LockTripleNodeStorageBox, NodeStorageBox},
    triple::TripleConfig,
};

pub struct TSSContext {
    pub seed_phrase: String,
}

pub struct TSSProtocol<
    AccountId: std::fmt::Display + std::fmt::Debug + Clone + Send + Sync,
    Block: BlockT,
    ChainClientT,
    TxPoolT,
> {
    context: TSSContext,
    notif_handle: Box<dyn NotificationService>,
    network: Arc<dyn NetworkService>,
    state: Arc<RwLock<NodeState<AccountId, <Block as BlockT>::Hash>>>,
    client: Arc<ChainClientT>,
    keystore: KeystorePtr,
    transaction_pool: Arc<TxPoolT>,
    offchain_storage: LocalStorage,
}

impl<
        AccountId: std::fmt::Display
            + std::fmt::Debug
            + Clone
            + From<sp_core::sr25519::Public>
            + Ord
            + Encode
            + Decode
            + Send
            + Sync
            + 'static,
        Block: BlockT,
        ChainClientT: sc_client_api::HeaderBackend<Block>
            + sp_api::ProvideRuntimeApi<Block>
            + Send
            + Sync
            + 'static,
        TxPoolT: sc_transaction_pool_api::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash>
            + Send
            + Sync
            + 'static,
    > TSSProtocol<AccountId, Block, ChainClientT, TxPoolT>
{
    fn new(
        context: TSSContext,
        notif_handle: Box<dyn NotificationService>,
        network: Arc<dyn NetworkService>,
        client: Arc<ChainClientT>,
        keystore: KeystorePtr,
        transaction_pool: Arc<TxPoolT>,
        offchain_storage: LocalStorage,
    ) -> Self {
        Self {
            context,
            notif_handle,
            network,
            state: Arc::new(RwLock::new(NodeState::Starting)),
            client,
            keystore,
            transaction_pool,
            offchain_storage,
        }
    }

    async fn run<
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        self,
    ) where
        <ChainClientT as sp_api::ProvideRuntimeApi<Block>>::Api: MpcManagerApi<Block, AccountId>,
        <Block as BlockT>::Hash: From<[u8; 32]>,
    {
        let sign_queue = Arc::new(RwLock::new(SignQueue::new()));

        let my_peer_id = self.network.local_peer_id();
        let my_seed = self.context.seed_phrase;
        let pair = sp_core::sr25519::Pair::from_phrase(&my_seed, None)
            .unwrap()
            .0;
        let public = pair.public();
        let my_account_id: AccountId = public.into();

        // let node_data_storage = OffchainNodeStorage::new(self.offchain_storage.clone());
        // let triple_storage =
        //     OffchainTripleStorage::new(self.offchain_storage.clone(), my_account_id.clone());

        let node_data_storage =
            MemoryNodeStorage::from_file(format!("./node_data_dump_{}", my_account_id.to_string()));

        // let node_data_storage = MemoryNodeStorage::default();

        let triple_storage = MemoryTripleNodeStorage::new(my_account_id.clone());

        let (cipher_secret_key, cipher_public_key) = mpc_keys::derive(my_seed.as_bytes());

        let client = self.client;

        let (sender, receiver) = mpsc::channel(16384);

        let (notif_sender, notif_receiver) = mpsc::channel(16384);

        let transaction_pool = self.transaction_pool;

        let keystore = LocalKeystore::in_memory();

        let network = self.network;

        let peers = Arc::new(RwLock::new(Peers::default()));

        keystore
            .sr25519_generate_new(KeyTypeId(*b"itss"), Some(&my_seed))
            .expect("Failed to add tss signing key to keystore");

        let offchain_storage = self.offchain_storage;

        let (protocol, protocol_state) = MpcSignProtocol::init(
            my_peer_id,
            my_account_id.clone(),
            my_seed,
            receiver,
            sign_queue.clone(),
            Box::new(node_data_storage),
            Arc::new(RwLock::new(Box::new(triple_storage))),
            Config {
                triple_cfg: TripleConfig {
                    //  min_triples: 20,
                    //  max_triples: 640,
                    min_triples: 10,
                    max_triples: 40,
                    max_concurrent_introduction: 2,
                    max_concurrent_generation: 16,
                },
                presig_cfg: PresignatureConfig {
                    // min_presignatures: 10,
                    // max_presignatures: 320,
                    min_presignatures: 5,
                    max_presignatures: 60,
                },
                network_cfg: NetworkConfig {
                    cipher_pk: cipher_public_key.clone(),
                    sign_sk: pair,
                },
            },
            notif_sender.clone(),
            client,
            Arc::new(keystore),
            transaction_pool,
            network,
            peers.clone(),
            offchain_storage,
        );

        tracing::debug!("protocol initialized");

        let display_cipher_pk = hex::encode(cipher_public_key.to_bytes());

        tracing::info!("\nMY PEER ID: {my_peer_id}\nMY ACCOUNT ID: {my_account_id}\nMY SIGN PUBLIC KEY: {public}\nMY CIPHER PUBLIC KEY: 0x{display_cipher_pk}");

        let protocol_handle =
            tokio::spawn(async move { protocol.run::<Runtime, TxCreator>().await });

        let message_handle: JoinHandle<Result<(), CryptographicError>> = tokio::spawn(async move {
            let mut notif_receiver = notif_receiver;
            let mut notif_handle = self.notif_handle;
            let sender = sender;
            let cipher_secret_key = cipher_secret_key;
            let protocol_state = protocol_state;

            let peers_clone = peers.clone();

            loop {
                // tracing::debug!("checking notif receiver");

                while let Ok(message) = notif_receiver.try_recv() {
                    // tracing::debug!("notif receiver wants to send a message");

                    notif_handle
                        .send_async_notification(&message.0, message.1)
                        .await
                        .unwrap();

                    tracing::debug!("sent a message");
                }

                // tracing::debug!("checking notif events");

                if let Some(Some(event)) = notif_handle.next_event().now_or_never() {
                    match event {
                        NotificationEvent::NotificationReceived { peer, notification } => {
                            tracing::debug!("notif event");

                            let encrypted_messages: Vec<Ciphered> =
                                bincode::deserialize(&mut notification.as_slice()).unwrap();

                            for encrypted in encrypted_messages {
                                tracing::debug!(
                                    "Decrypting a message with the following pk: {}",
                                    hex::encode(cipher_secret_key.public_key().to_bytes())
                                );

                                match SignedMessage::decrypt(
                                    &cipher_secret_key,
                                    &protocol_state,
                                    encrypted,
                                )
                                .await
                                {
                                    Ok(msg) => {
                                        if let Err(err) = sender.send(msg).await {
                                            tracing::error!(
                                                ?err,
                                                "failed to forward an encrypted protocol message"
                                            );
                                            // return Err(CryptographicError::SendError(
                                            //     err.to_string(),
                                            // ));
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!(
                                            ?err,
                                            from = PeerId::from(peer).to_string(),
                                            "failed to decrypt or verify an encrypted message\nconnected_peers: {:?}",
                                            peers_clone
                                                .read()
                                                .await
                                                .active_participants()
                                                .participants.clone()
                                                .into_inner()
                                                .into_values()
                                                .collect::<Vec<ParticipantInfo<AccountId>>>()
                                        );
                                        // return Err(err);
                                    }
                                };
                            }
                        }

                        NotificationEvent::NotificationStreamOpened { peer, .. } => {
                            let mut lock = peers_clone.write().await;
                            lock.add_connected_peer(peer);
                            drop(lock);
                        }

                        NotificationEvent::NotificationStreamClosed { peer } => {
                            let mut lock = peers_clone.write().await;
                            lock.remove_connected_peer(peer);
                            drop(lock);
                        }

                        _ => {
                            tracing::debug!("another event: {:?}", event);
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // tracing::debug!("await handles.");

        protocol_handle.await.unwrap().unwrap();
        message_handle.await.unwrap().unwrap();
        tracing::debug!("spinning down.");
    }
}

pub struct StartTSSTasksParams<'a> {
    pub task_manager: &'a mut TaskManager,
}

pub fn start_tss_tasks<
    AccountId: Ord + Encode + Decode + std::fmt::Display + std::fmt::Debug + Clone + Send + Sync + 'static,
    Block: BlockT,
    ChainClientT: sc_client_api::HeaderBackend<Block> + sp_api::ProvideRuntimeApi<Block> + 'static,
    TxPoolT: sc_transaction_pool_api::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash>
        + Send
        + Sync
        + 'static,
    Runtime: pallet_mpc_manager::Config,
    TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>> + 'static,
>(
    params: StartTSSTasksParams,
    context: TSSContext,
    notif_handle: Box<dyn NotificationService>,
    network: Arc<dyn NetworkService>,
    client: Arc<ChainClientT>,
    keystore: KeystorePtr,
    transaction_pool: Arc<TxPoolT>,
    offchain_storage: LocalStorage,
) where
    <ChainClientT as sp_api::ProvideRuntimeApi<Block>>::Api: MpcManagerApi<Block, AccountId>,
    <Block as BlockT>::Hash: From<[u8; 32]>,
    AccountId: From<sp_core::sr25519::Public>,
{
    let protocol = TSSProtocol::new(
        context,
        notif_handle,
        network,
        client,
        keystore,
        transaction_pool,
        offchain_storage,
    );

    params.task_manager.spawn_handle().spawn(
        "tss-task",
        Some("networking"),
        protocol.run::<Runtime, TxCreator>(),
    );
}

#[derive(Clone)]
pub struct Config {
    pub triple_cfg: TripleConfig,
    pub presig_cfg: PresignatureConfig,
    pub network_cfg: NetworkConfig,
}

struct Ctx<AccountId, Block: BlockT, ChainClientT, TxPoolT> {
    my_peer_id: PeerId,
    account_id: AccountId,
    signer: String,
    sign_queue: Arc<RwLock<SignQueue<<Block as BlockT>::Hash>>>,
    secret_storage: NodeStorageBox,
    triple_storage: LockTripleNodeStorageBox<AccountId>,
    cfg: Config,
    peers: Arc<RwLock<Peers<AccountId>>>,
    notif_handle: Sender<(PeerId, Vec<u8>)>,
    client: Arc<ChainClientT>,
    keystore: Arc<LocalKeystore>,
    transaction_pool: Arc<TxPoolT>,
    network: Arc<dyn NetworkService>,
    offchain_storage: LocalStorage,
}

impl<AccountId, Block: BlockT, ChainClientT, TxPoolT>
    ConsensusCtx<AccountId, Block, ChainClientT, TxPoolT>
    for &mut MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>
{
    fn my_account_id(&self) -> &AccountId {
        &self.ctx.account_id
    }

    fn signer(&self) -> String {
        self.ctx.signer.clone()
    }

    fn my_peer_id(&self) -> &PeerId {
        &self.ctx.my_peer_id
    }

    fn sign_queue(&self) -> Arc<RwLock<SignQueue<<Block as BlockT>::Hash>>> {
        self.ctx.sign_queue.clone()
    }

    fn secret_storage(&self) -> &NodeStorageBox {
        &self.ctx.secret_storage
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }

    fn triple_storage(&self) -> LockTripleNodeStorageBox<AccountId> {
        self.ctx.triple_storage.clone()
    }

    fn tx_pool(&self) -> Arc<TxPoolT> {
        self.ctx.transaction_pool.clone()
    }

    fn client(&self) -> Arc<ChainClientT> {
        self.ctx.client.clone()
    }

    fn keystore(&self) -> Arc<LocalKeystore> {
        self.ctx.keystore.clone()
    }
}

#[async_trait::async_trait]
impl<
        Block: BlockT,
        AccountId: std::fmt::Display + Send + Sync + Clone + PartialEq,
        ChainClientT: Send + Sync,
        TxPoolT: Send + Sync,
    > CryptographicCtx<TxPoolT, ChainClientT, AccountId>
    for &mut MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>
{
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn signer(&self) -> String {
        self.ctx.signer.clone()
    }

    fn node_storage(&mut self) -> &mut NodeStorageBox {
        &mut self.ctx.secret_storage
    }

    fn cfg(&self) -> &Config {
        &self.ctx.cfg
    }

    fn peers(&self) -> Arc<RwLock<Peers<AccountId>>> {
        self.ctx.peers.clone()
    }

    fn notif_handle(&self) -> Sender<(PeerId, Vec<u8>)> {
        self.ctx.notif_handle.clone()
    }

    fn tx_pool(&self) -> Arc<TxPoolT> {
        self.ctx.transaction_pool.clone()
    }

    fn client(&self) -> Arc<ChainClientT> {
        self.ctx.client.clone()
    }
}

#[async_trait::async_trait]
impl<
        AccountId: std::fmt::Display + Send + Sync + Clone + PartialEq,
        Block: BlockT,
        ChainClientT: Send + Sync,
        TxPoolT: Send + Sync,
    > MessageCtx<AccountId> for &MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>
{
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn peers(&self) -> Arc<RwLock<Peers<AccountId>>> {
        self.ctx.peers.clone()
    }
}

pub struct MpcSignProtocol<AccountId, Block: BlockT, ChainClientT, TxPoolT> {
    ctx: Ctx<AccountId, Block, ChainClientT, TxPoolT>,
    receiver: mpsc::Receiver<MpcMessage<<Block as BlockT>::Hash>>,
    state: Arc<RwLock<NodeState<AccountId, <Block as BlockT>::Hash>>>,
}

impl<
        AccountId: Clone
            + ToString
            + Encode
            + Decode
            + Ord
            + Send
            + Sync
            + std::fmt::Display
            + std::fmt::Debug,
        Block: BlockT,
        ChainClientT: sc_client_api::HeaderBackend<Block> + sp_api::ProvideRuntimeApi<Block> + Send + Sync,
        TxPoolT: sc_service::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash> + Send + Sync,
    > MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>
where
    <ChainClientT as sp_api::ProvideRuntimeApi<Block>>::Api: MpcManagerApi<Block, AccountId>,
    <Block as BlockT>::Hash: From<[u8; 32]>,
{
    #![allow(clippy::too_many_arguments)]
    pub fn init(
        my_peer_id: PeerId,
        account_id: AccountId,
        signer: String,
        receiver: mpsc::Receiver<MpcMessage<<Block as BlockT>::Hash>>,
        sign_queue: Arc<RwLock<SignQueue<<Block as BlockT>::Hash>>>,
        secret_storage: NodeStorageBox,
        triple_storage: LockTripleNodeStorageBox<AccountId>,
        cfg: Config,
        notif_handle: Sender<(PeerId, Vec<u8>)>,
        client: Arc<ChainClientT>,
        keystore: Arc<LocalKeystore>,
        transaction_pool: Arc<TxPoolT>,
        network: Arc<dyn NetworkService>,
        peers: Arc<RwLock<Peers<AccountId>>>,
        offchain_storage: LocalStorage,
    ) -> (
        Self,
        Arc<RwLock<NodeState<AccountId, <Block as BlockT>::Hash>>>,
    ) {
        let state = Arc::new(RwLock::new(NodeState::Starting));

        let ctx = Ctx {
            my_peer_id,
            account_id,
            sign_queue,
            signer,
            secret_storage,
            triple_storage,
            cfg,
            peers,
            notif_handle,
            client,
            keystore,
            transaction_pool,
            network,
            offchain_storage,
        };

        let protocol = MpcSignProtocol {
            ctx,
            receiver,
            state: state.clone(),
        };

        (protocol, state)
    }

    pub async fn run<
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        mut self,
    ) -> anyhow::Result<()> {
        let my_account_id = self.ctx.account_id.clone();
        let _span = tracing::info_span!("running", "{}", my_account_id.to_string());

        let mut queue = MpcMessageQueue::default();

        let mut last_state_update = Instant::now();
        //let mut last_pinged = Instant::now();

        loop {
            //let protocol_time = Instant::now();

            tracing::debug!("trying to advance mpc recovery protocol");

            loop {
                let msg_result = self.receiver.try_recv();

                match msg_result {
                    Ok(msg) => {
                        tracing::debug!("received a new message");
                        queue.push(msg);
                    }
                    Err(TryRecvError::Empty) => {
                        tracing::debug!("no new messages received");
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        tracing::debug!("communication was disconnected, no more messages will be received, spinning down");
                        return Ok(());
                    }
                }
            }

            let protocol_state = if last_state_update.elapsed() > Duration::from_secs(1) {
                // tracing::debug!("attempting to get protocol state from pallet storage");

                let client = self.ctx.client.clone();

                let latest = client.info().best_hash;

                let protocol_state = match client.runtime_api().protocol_state(latest) {
                    Ok(state) => state,
                    Err(e) => {
                        tracing::error!("Could not call protocol_state runtime api: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                // tracing::debug!(?protocol_state);

                // Establish the participants for this current iteration of the protocol loop. This will
                // set which participants are currently active in the protocol and determines who will be
                // receiving messages.
                let mut lock = self.ctx.peers.write().await;
                lock.establish_participants(&protocol_state).await;
                drop(lock);

                last_state_update = Instant::now();

                Some(protocol_state)
            } else {
                None
            };

            if let Some(ProtocolState::Running(RunningChainState {
                ref participants, ..
            })) = protocol_state
            {
                let client = self.ctx.client.clone();

                let latest = client.info().best_hash;

                let signature_requests = match client.runtime_api().signature_requests(latest) {
                    Ok(state) => state,
                    Err(e) => {
                        tracing::error!("Could not call signature_requests runtime api: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                let mut sign_queue = self.ctx.sign_queue.write().await;

                // let me = get_my_participant(&self).await;
                let me = get_my_participant_from_list(&my_account_id, &participants);

                let existing_requests = sign_queue.my_requests(me).clone();

                for (payload, epsilon) in signature_requests {
                    // TODO: Unique hash for each request (perhaps the transaction hash).
                    let transaction_id = <Block as BlockT>::Hash::from(epsilon);
                    let entropy = epsilon;

                    if !existing_requests.contains_key(&transaction_id) {
                        let delta = kdf::derive_delta(transaction_id, entropy);

                        tracing::info!(
                            transaction_id = %transaction_id,
                            our_account = self.ctx.account_id.to_string(),
                            payload = hex::encode(payload),
                            entropy = hex::encode(entropy),
                            "New signature request found"
                        );

                        sign_queue.add(SignRequest {
                            receipt_id: transaction_id,
                            msg_hash: payload,
                            epsilon: Scalar::from_bytes(&epsilon),
                            delta,
                            entropy,
                            time_added: Instant::now(),
                        });
                    }
                }

                drop(sign_queue);
            }

            // if last_pinged.elapsed() > Duration::from_millis(300) {
            //     self.ctx.mesh.ping().await;
            //     last_pinged = Instant::now();
            // }

            let state = {
                let guard = self.state.read().await;
                guard.clone()
            };

            //let crypto_time = Instant::now();

            tracing::debug!("attempting to progress protocol");

            let mut state =
                match <NodeState<AccountId, <Block as BlockT>::Hash> as CryptographicProtocol<
                    Runtime,
                    Block,
                    AccountId,
                    <Block as BlockT>::Hash,
                    TxPoolT,
                    ChainClientT,
                    TxCreator,
                >>::progress::<'_, &mut MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>>(
                    state, &mut self,
                )
                .await
                {
                    Ok(state) => state,
                    Err(err) => {
                        tracing::info!("protocol unable to progress: {err:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

            //let consensus_time = Instant::now();

            tracing::debug!("attempting to advance protocol");

            if let Some(protocol_state) = protocol_state {
                state = match state
                    .advance::<&mut MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>, Runtime, TxCreator>(
                        &mut self,
                        protocol_state,
                    )
                    .await
                {
                    Ok(state) => state,
                    Err(err) => {
                        tracing::info!("protocol unable to advance: {err:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
            }

            //let message_time = Instant::now();

            tracing::debug!("attempting to handle messages");

            if let Err(err) = state.handle(&self, &mut queue).await {
                tracing::info!("protocol unable to handle messages: {err:?}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            let sleep_ms = match state {
                NodeState::Generating(_) => 500,
                NodeState::Resharing(_) => 500,
                NodeState::Running(_) => 100,

                NodeState::Starting => 1000,
                NodeState::Started(_) => 1000,
                NodeState::WaitingForConsensus(_) => 1000,
                NodeState::Joining(_) => 1000,
            };

            let mut guard = self.state.write().await;
            *guard = state;
            drop(guard);

            tracing::debug!("sleeping");

            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }
}

async fn get_my_participant<
    AccountId: std::fmt::Display + Clone + PartialEq,
    Block: BlockT,
    ChainClientT,
    TxPoolT,
>(
    protocol: &MpcSignProtocol<AccountId, Block, ChainClientT, TxPoolT>,
) -> Participant {
    let my_acc_id = &protocol.ctx.account_id;
    let state = protocol.state.read().await;

    // tracing::debug!("state: {:#?}", state);

    let participant_info = state.find_participant_info(my_acc_id).unwrap_or_else(|| {
        tracing::error!("could not find participant info for {my_acc_id}");
        panic!("could not find participant info for {my_acc_id}");
    });
    participant_info.id.into()
}

fn get_my_participant_from_list<AccountId: std::fmt::Display + PartialEq + Clone>(
    account_id: &AccountId,
    participants: &Participants<AccountId>,
) -> Participant {
    let participant_info = participants
        .find_participant_info(account_id)
        .unwrap_or_else(|| {
            tracing::error!("could not find participant info for {account_id}");
            panic!("could not find participant info for {account_id}");
        });

    participant_info.id.into()
}
