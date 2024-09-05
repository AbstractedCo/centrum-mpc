use cait_sith::{
    protocol::{InitializationError, Participant, Protocol},
    triples::TripleGenerationOutput,
    FullSignature, KeygenOutput, PresignOutput,
};
use codec::{Decode, Encode};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, CurveArithmetic},
    AffinePoint, Secp256k1,
};
use sc_network::NetworkService;
use serde::{Deserialize, Serialize};
use sp_runtime::traits::{Block as BlockT, Extrinsic as ExtrinsicT};
use std::{collections::BTreeMap, fmt::Display, sync::Arc, time::Duration};
use tokio::sync::{RwLock, RwLockWriteGuard};

use super::on_chain::ResharingChainState;

pub use pallet_mpc_manager::Secp256K1PublicKey;

pub const PROTOCOL_PRESIG_TIMEOUT: Duration = Duration::from_secs(60);
pub const PROTOCOL_SIGNATURE_TIMEOUT: Duration = Duration::from_secs(60);
pub const PROTOCOL_TRIPLE_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Default invalidation time for taken triples and presignatures. 120 mins
pub const TAKEN_TIMEOUT: Duration = Duration::from_secs(120 * 60);

pub trait TransactionCreator<Block: BlockT, ChainClientT, Call> {
    fn create_transaction(
        client: Arc<ChainClientT>,
        pair: sp_core::sr25519::Pair,
        call: Call,
    ) -> (<Block as BlockT>::Extrinsic, <Block as BlockT>::Hash);
}

pub type NetServ<Block, Hash> = Arc<NetworkService<Block, Hash>>;
pub type TxPool<Block, RuntimeApi, Executor> =
    Arc<sc_transaction_pool::FullPool<Block, ChainClient<Block, RuntimeApi, Executor>>>;
pub type TxPoolNoArc<Block, FullClient> = sc_transaction_pool::FullPool<Block, FullClient>;
pub type ChainClient<Block, RuntimeApi, Executor> =
    sc_service::TFullClient<Block, RuntimeApi, sc_executor::NativeElseWasmExecutor<Executor>>;

pub type SecretKeyShare = <Secp256k1 as CurveArithmetic>::Scalar;
pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
pub type TripleProtocol =
    Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>> + Send + Sync>;
pub type PresignatureProtocol = Box<dyn Protocol<Output = PresignOutput<Secp256k1>> + Send + Sync>;
pub type SignatureProtocol = Box<dyn Protocol<Output = FullSignature<Secp256k1>> + Send + Sync>;

#[derive(Clone)]
pub struct KeygenProtocol {
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    protocol: Arc<RwLock<Box<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>>>,
}

impl KeygenProtocol {
    pub fn new(
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Self, InitializationError> {
        Ok(Self {
            threshold,
            me,
            participants: participants.into(),
            protocol: Arc::new(RwLock::new(Box::new(cait_sith::keygen::<Secp256k1>(
                participants,
                me,
                threshold,
            )?))),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        *self.write().await = Box::new(cait_sith::keygen::<Secp256k1>(
            &self.participants,
            self.me,
            self.threshold,
        )?);
        Ok(())
    }

    pub async fn write(
        &self,
    ) -> RwLockWriteGuard<'_, Box<dyn Protocol<Output = KeygenOutput<Secp256k1>> + Send + Sync>>
    {
        self.protocol.write().await
    }
}

#[derive(Clone)]
pub struct ReshareProtocol {
    old_participants: Vec<Participant>,
    new_participants: Vec<Participant>,
    me: Participant,
    threshold: usize,
    private_share: Option<SecretKeyShare>,
    protocol: Arc<RwLock<Box<dyn Protocol<Output = SecretKeyShare> + Send + Sync>>>,
    root_pk: PublicKey,
}

impl ReshareProtocol {
    pub fn new<AccountId: Encode + Decode + Eq + Clone>(
        private_share: Option<SecretKeyShare>,
        me: Participant,
        chain_state: &ResharingChainState<AccountId>,
    ) -> Result<Self, InitializationError> {
        let old_participants: Vec<Participant> = chain_state
            .old_participants
            .keys()
            .map(|p| (*p).into())
            .collect();
        let new_participants: Vec<Participant> = chain_state
            .new_participants
            .keys()
            .map(|p| (*p).into())
            .collect();

        Ok(Self {
            protocol: Arc::new(RwLock::new(Box::new(cait_sith::reshare::<Secp256k1>(
                &old_participants,
                chain_state.threshold as usize,
                &new_participants,
                chain_state.threshold as usize,
                me,
                private_share,
                chain_state.public_key.into_affine(),
            )?))),
            private_share,
            me,
            threshold: chain_state.threshold as usize,
            old_participants,
            new_participants,
            root_pk: chain_state.public_key.into_affine(),
        })
    }

    pub async fn refresh(&mut self) -> Result<(), InitializationError> {
        *self.write().await = Box::new(cait_sith::reshare::<Secp256k1>(
            &self.old_participants,
            self.threshold,
            &self.new_participants,
            self.threshold,
            self.me,
            self.private_share,
            self.root_pk,
        )?);
        Ok(())
    }

    pub async fn write(
        &self,
    ) -> RwLockWriteGuard<'_, Box<dyn Protocol<Output = SecretKeyShare> + Send + Sync>> {
        self.protocol.write().await
    }
}
