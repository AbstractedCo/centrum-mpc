use crate::types::TransactionCreator;

use super::{
    cryptography::AppCryptoT,
    kdf,
    message::SignatureMessage,
    on_chain::Participants,
    presignature::{Presignature, PresignatureId, PresignatureManager},
    types::{PublicKey, SignatureProtocol, TxPool},
    util::ScalarExt,
};
use cait_sith::{
    protocol::{Action, InitializationError, Participant, ProtocolError},
    FullSignature, PresignOutput,
};
use chrono::Utc;
use frame_system::offchain::Signer;
use futures::StreamExt;
use k256::{
    elliptic_curve::{scalar::FromUintUnchecked, sec1::ToEncodedPoint},
    Scalar, Secp256k1, U256,
};
use rand::{
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
    SeedableRng,
};
use sc_transaction_pool_api::{TransactionPool, TransactionSource, TransactionStatus};
use sp_core::{sr25519::Pair, Pair as _};
use sp_runtime::traits::{Block as BlockT, Extrinsic as ExtrinsicT, SignedExtension};
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

/// Duration for which completed signatures are retained.
pub const COMPLETION_EXISTENCE_TIMEOUT: Duration = Duration::from_secs(120 * 60);

#[derive(Clone)]
pub struct SignRequest<Hash: Clone> {
    pub receipt_id: Hash,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub entropy: [u8; 32],
    pub time_added: Instant,
}

#[derive(Default)]
pub struct SignQueue<Hash: Clone> {
    unorganized_requests: Vec<SignRequest<Hash>>,
    requests: HashMap<Participant, HashMap<Hash, SignRequest<Hash>>>,
}

impl<Hash: Clone + Default + std::fmt::Display + Eq + std::hash::Hash> SignQueue<Hash> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.unorganized_requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add(&mut self, request: SignRequest<Hash>) {
        self.unorganized_requests.push(request);
    }

    pub fn organize<AccountId: PartialEq + Clone>(
        &mut self,
        threshold: usize,
        active: &Participants<AccountId>,
        me: Participant,
        my_account_id: &AccountId,
    ) {
        for request in self.unorganized_requests.drain(..) {
            let mut rng = StdRng::from_seed(request.entropy);
            let subset = active.keys().choose_multiple(&mut rng, threshold);
            let proposer = **subset.choose(&mut rng).unwrap();
            if subset.contains(&&me.into()) {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?me,
                    ?subset,
                    ?proposer,
                    "saving sign request: node is in the signer subset"
                );

                let proposer_requests = self.requests.entry(proposer.into()).or_default();
                proposer_requests.insert(request.receipt_id.clone(), request);
            } else {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?me,
                    ?subset,
                    ?proposer,
                    "skipping sign request: node is NOT in the signer subset"
                );
            }
        }
    }

    pub fn contains(&self, participant: Participant, receipt_id: Hash) -> bool {
        let Some(participant_requests) = self.requests.get(&participant) else {
            return false;
        };
        participant_requests.contains_key(&receipt_id)
    }

    pub fn my_requests(&mut self, me: Participant) -> &mut HashMap<Hash, SignRequest<Hash>> {
        self.requests.entry(me).or_default()
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    pub protocol: SignatureProtocol,
    pub participants: Vec<Participant>,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub sign_request_timestamp: Instant,
    pub generator_timestamp: Instant,
}

impl SignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: SignatureProtocol,
        participants: Vec<Participant>,
        proposer: Participant,
        presignature_id: PresignatureId,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
    ) -> Self {
        Self {
            protocol,
            participants,
            proposer,
            presignature_id,
            msg_hash,
            epsilon,
            delta,
            sign_request_timestamp,
            generator_timestamp: Instant::now(),
        }
    }

    pub fn poke(&mut self) -> Result<Action<FullSignature<Secp256k1>>, ProtocolError> {
        if self.generator_timestamp.elapsed() > super::types::PROTOCOL_SIGNATURE_TIMEOUT {
            tracing::info!(self.presignature_id, "signature protocol timed out");

            return Err(ProtocolError::Other("signature protocol timed out".into()).into());
        }

        self.protocol.poke()
    }
}

/// Generator for signature thas has failed. Only retains essential information
/// for starting up this failed signature once again.
pub struct FailedGenerator {
    pub proposer: Participant,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub sign_request_timestamp: Instant,
}

pub struct SignatureManager<Hash> {
    /// Ongoing signature generation protocols.
    generators: HashMap<Hash, SignatureGenerator>,
    /// Failed signatures awaiting to be retried.
    failed_generators: VecDeque<(Hash, FailedGenerator)>,
    /// Set of completed signatures
    completed: HashMap<PresignatureId, Instant>,
    /// Generated signatures assigned to the current node that are yet to be published.
    /// Vec<(receipt_id, msg_hash, timestamp, output)>
    signatures: Vec<(Hash, [u8; 32], Scalar, Instant, FullSignature<Secp256k1>)>,
    me: Participant,
    public_key: PublicKey,
    epoch: u64,
}

impl<Hash: std::fmt::Debug + std::fmt::Display + Eq + std::hash::Hash + Clone>
    SignatureManager<Hash>
{
    pub fn new(me: Participant, public_key: PublicKey, epoch: u64) -> Self {
        Self {
            generators: HashMap::new(),
            failed_generators: VecDeque::new(),
            completed: HashMap::new(),
            signatures: Vec::new(),
            me,
            public_key,
            epoch,
        }
    }

    pub fn failed_len(&self) -> usize {
        self.failed_generators.len()
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_internal<AccountId: PartialEq + Clone>(
        participants: &Participants<AccountId>,
        me: Participant,
        public_key: PublicKey,
        proposer: Participant,
        presignature: Presignature,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
    ) -> Result<SignatureGenerator, InitializationError> {
        let participants: Vec<Participant> =
            participants.keys().cloned().map(|p| p.into()).collect();
        let PresignOutput { big_r, k, sigma } = presignature.output;
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            &participants,
            me,
            kdf::derive_key(public_key, epsilon),
            output,
            Scalar::from_bytes(&msg_hash),
        )?);
        Ok(SignatureGenerator::new(
            protocol,
            participants,
            proposer,
            presignature.id,
            msg_hash,
            epsilon,
            delta,
            sign_request_timestamp,
        ))
    }

    pub fn take_failed_generator(&mut self) -> Option<(Hash, FailedGenerator)> {
        self.failed_generators.pop_front()
    }

    pub fn retry_failed_generation<AccountId: PartialEq + Clone>(
        &mut self,
        receipt_id: Hash,
        failed_generator: &FailedGenerator,
        presignature: Presignature,
        participants: &Participants<AccountId>,
    ) -> Option<()> {
        tracing::info!(receipt_id = %receipt_id, participants = ?participants.keys().collect::<Vec<_>>(), "restarting failed protocol to generate signature");

        let generator = Self::generate_internal(
            participants,
            self.me,
            self.public_key,
            failed_generator.proposer,
            presignature,
            failed_generator.msg_hash,
            failed_generator.epsilon,
            failed_generator.delta,
            failed_generator.sign_request_timestamp,
        )
        .unwrap();
        self.generators.insert(receipt_id, generator);
        Some(())
    }

    /// Starts a new presignature generation protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn generate<AccountId: PartialEq + Clone>(
        &mut self,
        participants: &Participants<AccountId>,
        receipt_id: Hash,
        presignature: Presignature,
        public_key: PublicKey,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
    ) -> Result<(), InitializationError> {
        tracing::info!(
            %receipt_id,
            me = ?self.me,
            presignature_id = presignature.id,
            participants = ?participants.keys_vec(),
            "starting protocol to generate a new signature",
        );

        let generator = Self::generate_internal(
            participants,
            self.me,
            public_key,
            self.me,
            presignature,
            msg_hash,
            epsilon,
            delta,
            sign_request_timestamp,
        )?;
        self.generators.insert(receipt_id, generator);
        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    #[allow(clippy::too_many_arguments)]
    pub fn get_or_generate<AccountId: PartialEq + Clone + std::fmt::Debug>(
        &mut self,
        participants: &Participants<AccountId>,
        receipt_id: Hash,
        proposer: Participant,
        presignature_id: PresignatureId,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
        presignature_manager: &mut PresignatureManager<AccountId>,
    ) -> Result<Option<&mut SignatureProtocol>, InitializationError> {
        match self.generators.entry(receipt_id.clone()) {
            Entry::Vacant(entry) => {
                tracing::info!(%receipt_id, me = ?self.me, presignature_id, "joining protocol to generate a new signature");

                let Some(presignature) = presignature_manager.take(presignature_id) else {
                    tracing::warn!(me = ?self.me, presignature_id, "presignature is missing, can't join");

                    return Ok(None);
                };

                tracing::info!(me = ?self.me, presignature_id, "found presignature: ready to start signature generation");

                let generator = Self::generate_internal(
                    participants,
                    self.me,
                    self.public_key,
                    proposer,
                    presignature,
                    msg_hash,
                    epsilon,
                    delta,
                    Instant::now(),
                )?;
                let generator = entry.insert(generator);
                Ok(Some(&mut generator.protocol))
            }
            Entry::Occupied(entry) => Ok(Some(&mut entry.into_mut().protocol)),
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub fn poke(&mut self) -> Vec<(Participant, SignatureMessage<Hash>)> {
        let mut messages = Vec::new();
        self.generators.retain(|receipt_id, generator| {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        tracing::warn!(?err, "signature failed to be produced; pushing request back into failed queue");

                        self.failed_generators.push_back((
                            receipt_id.clone(),
                            FailedGenerator {
                                proposer: generator.proposer,
                                msg_hash: generator.msg_hash,
                                epsilon: generator.epsilon,
                                delta: generator.delta,
                                sign_request_timestamp: generator.sign_request_timestamp,
                            },
                        ));
                        break false;
                    }
                };
                match action {
                    Action::Wait => {
                        tracing::debug!("waiting");

                        // Retain protocol until we are finished
                        return true;
                    }
                    Action::SendMany(data) => {
                        for p in generator.participants.iter() {
                            messages.push((
                                *p,
                                SignatureMessage {
                                    receipt_id: receipt_id.clone(),
                                    proposer: generator.proposer,
                                    presignature_id: generator.presignature_id,
                                    msg_hash: generator.msg_hash,
                                    epsilon: generator.epsilon,
                                    delta: generator.delta,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        SignatureMessage {
                            receipt_id: receipt_id.clone(),
                            proposer: generator.proposer,
                            presignature_id: generator.presignature_id,
                            msg_hash: generator.msg_hash,
                            epsilon: generator.epsilon,
                            delta: generator.delta,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc ::now().timestamp() as u64,
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            ?receipt_id,
                            me = ?self.me,
                            presignature_id = generator.presignature_id,
                            big_r = ?output.big_r,//.to_base58(),
                            s = ?output.s,
                            "completed signature generation"
                        );

                        self.completed
                            .insert(generator.presignature_id, Instant::now());

                        if generator.proposer == self.me {
                            self.signatures.push((
                                receipt_id.clone(),
                                generator.msg_hash,
                                generator.epsilon,
                                generator.sign_request_timestamp,
                                output,
                            ));
                        }
                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });
        messages
    }

    pub async fn publish<
        Block: BlockT,
        ChainClientT,
        TxPoolT: sc_service::TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash>,
        Runtime: pallet_mpc_manager::Config,
        TxCreator: TransactionCreator<Block, ChainClientT, pallet_mpc_manager::Call<Runtime>>,
    >(
        &mut self,
        pair: Pair,
        client: Arc<ChainClientT>,
        tx_pool: Arc<TxPoolT>,
    ) -> Result<(), String> {
        for (receipt_id, payload, epsilon, time_added, signature) in self.signatures.drain(..) {
            // TODO: Figure out how to properly serialize the signature
            // let r_s = signature.big_r.x().concat(signature.s.to_bytes());
            // let tag =
            //     ConditionallySelectable::conditional_select(&2u8, &3u8, signature.big_r.y_is_odd());
            // let signature = r_s.append(tag);
            // let signature = Secp256K1Signature::try_from(signature.as_slice()).unwrap();
            // let signature = Signature::SECP256K1(signature);

            tracing::info!(id = ?receipt_id, "Attempting to publish finalized signature!");

            let call = pallet_mpc_manager::pallet::Call::deliver_signature {
                payload,
                epsilon: epsilon.to_bytes().to_vec().try_into().unwrap(),
                big_r: signature.big_r.to_encoded_point(false).as_bytes().to_vec(),
                s: signature.s.to_bytes().to_vec(),
            };

            let (xt, hash) = TxCreator::create_transaction(client.clone(), pair.clone(), call);

            let mut maybe_status = tx_pool
                .submit_and_watch(hash, TransactionSource::External, xt)
                .await
                .expect("Failed to submit to tx pool.");

            while let Some(status) = maybe_status.next().await {
                match status {
                    TransactionStatus::InBlock(_) => {
                        // tracing::debug!(s = ?signature.s,
                        //                 s_to_bytes = ?signature.s.to_bytes(),
                        //                 s_from_bytes = ?Scalar::from_uint_unchecked(U256::from_be_slice(&signature.s.to_bytes())),
                        //                 s_from_bytes_to_bytes_again = ?Scalar::from_uint_unchecked(U256::from_be_slice(&signature.s.to_bytes())).to_bytes()
                        // );

                        tracing::info!(%receipt_id, ?payload, epsilon = ?epsilon.to_bytes(), big_r = ?signature.big_r.to_encoded_point(true).as_bytes(), s = ?signature.s.to_bytes(), "published signature response");

                        return Ok(());
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

            tracing::info!(%receipt_id, big_r = ?signature.big_r.to_encoded_point(true).as_bytes(), s = ?signature.s.to_bytes(), "published signature response");
        }
        Ok(())
    }

    /// Check whether or not the signature has been completed with this presignature_id.
    pub fn has_completed(&mut self, presignature_id: &PresignatureId) -> bool {
        self.completed
            .retain(|_, timestamp| timestamp.elapsed() < COMPLETION_EXISTENCE_TIMEOUT);

        self.completed.contains_key(presignature_id)
    }
}
