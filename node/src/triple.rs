use super::{
    cryptography::CryptographicError,
    message::TripleMessage,
    on_chain::Participants,
    presignature::GenerationError,
    storage::{LockTripleNodeStorageBox, TripleData},
    types::TripleProtocol,
};
use cait_sith::{
    protocol::{Action, InitializationError, Participant, ProtocolError},
    triples::{TripleGenerationOutput, TriplePub, TripleShare},
};
use chrono::Utc;
use codec::{Decode, Encode};
use highway::{HighwayHash, HighwayHasher};
use k256::{elliptic_curve::group::GroupEncoding, Secp256k1};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

pub const PROTOCOL_TRIPLE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
pub const FAILED_TRIPLES_TIMEOUT: Duration = Duration::from_secs(120 * 60);
pub const TAKEN_TIMEOUT: Duration = Duration::from_secs(120 * 60);

/// Unique number used to identify a specific ongoing triple generation protocol.
/// Without `TripleId` it would be unclear where to route incoming cait-sith triple generation
/// messages.
pub type TripleId = u64;

/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Triple {
    pub id: TripleId,
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

impl PartialEq for Triple {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }

    fn ne(&self, other: &Self) -> bool {
        self.id != other.id
    }
}

impl Eq for Triple {}

impl PartialOrd for Triple {
    fn gt(&self, other: &Self) -> bool {
        self.id > other.id
    }

    fn lt(&self, other: &Self) -> bool {
        self.id < other.id
    }

    fn ge(&self, other: &Self) -> bool {
        self.id >= other.id
    }

    fn le(&self, other: &Self) -> bool {
        self.id <= other.id
    }

    fn partial_cmp(&self, other: &Self) -> Option<scale_info::prelude::cmp::Ordering> {
        self.id.partial_cmp(&other.id)
    }
}

impl Ord for Triple {
    fn cmp(&self, other: &Self) -> scale_info::prelude::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

pub struct TripleGenerator {
    pub id: TripleId,
    pub participants: Vec<Participant>,
    pub protocol: TripleProtocol,
    pub timestamp: Option<Instant>,
}

impl TripleGenerator {
    pub fn new(id: TripleId, participants: Vec<Participant>, protocol: TripleProtocol) -> Self {
        Self {
            id,
            participants,
            protocol,
            timestamp: None,
        }
    }

    pub fn poke(&mut self) -> Result<Action<TripleGenerationOutput<Secp256k1>>, ProtocolError> {
        let timestamp = self.timestamp.get_or_insert_with(Instant::now);
        if timestamp.elapsed() > PROTOCOL_TRIPLE_TIMEOUT {
            return Err(ProtocolError::Other(
                anyhow::anyhow!("triple protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

// TODO: easy way to deserialize human readable string for CLI passable args
#[derive(Copy, Clone, Debug)]
pub struct TripleConfig {
    /// Minimum amount of triples that is owned by each node.
    pub min_triples: usize,
    /// Maximum amount of triples that is owned by each node.
    pub max_triples: usize,
    /// Maximum amount of concurrent triple generation that can be introduce by this node.
    pub max_concurrent_introduction: usize,
    /// Maximum amount of concurrent triple generation that can be done per node.
    pub max_concurrent_generation: usize,
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct TripleManager<AccountId> {
    /// Completed unspent triples
    pub triples: HashMap<TripleId, Triple>,

    /// The pool of triple protocols that have yet to be completed.
    pub generators: HashMap<TripleId, TripleGenerator>,

    /// Triples that are queued to be poked. If these generators sit for too long in
    /// the queue, they will be removed due to triple generation timeout.
    pub queued: VecDeque<TripleId>,

    /// Ongoing triple generation protocols. Once added here, they will not be removed until
    /// they are completed or timed out.
    pub ongoing: HashSet<TripleId>,

    /// The set of triples that were introduced to the system by the current node.
    pub introduced: HashSet<TripleId>,

    /// List of triple ids generation of which was initiated by the current node.
    pub mine: VecDeque<TripleId>,

    /// The set of triple ids that were already taken. This will be maintained for at most
    /// triple timeout period just so messages are cycled through the system.
    pub taken: HashMap<TripleId, Instant>,

    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub triple_cfg: TripleConfig,
    pub triple_storage: LockTripleNodeStorageBox<AccountId>,
    /// triple generation protocols that failed.
    pub failed_triples: HashMap<TripleId, Instant>,
    pub my_account_id: AccountId,
}

impl<AccountId: std::fmt::Debug + Clone + PartialEq> TripleManager<AccountId> {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        triple_cfg: &TripleConfig,
        triple_data: Vec<TripleData<AccountId>>,
        triple_storage: LockTripleNodeStorageBox<AccountId>,
        my_account_id: &AccountId,
    ) -> Self {
        let mut mine: VecDeque<TripleId> = VecDeque::new();
        let mut all_triples = HashMap::new();
        for entry in triple_data {
            tracing::debug!("the triple data loaded is {:?}", entry);
            if entry.mine {
                tracing::debug!("pushed tripleId = {} into mine.", entry.triple.id);
                mine.push_back(entry.triple.id);
            }
            all_triples.insert(entry.triple.id, entry.triple);
        }
        Self {
            triples: all_triples,
            generators: HashMap::new(),
            queued: VecDeque::new(),
            ongoing: HashSet::new(),
            introduced: HashSet::new(),
            taken: HashMap::new(),
            mine,
            me,
            threshold,
            epoch,
            triple_cfg: *triple_cfg,
            triple_storage,
            failed_triples: HashMap::new(),
            my_account_id: my_account_id.clone(),
        }
    }

    /// Returns the number of unspent triples available in the manager.
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Returns if there's any unspent triple in the manager.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of unspent triples assigned to this node.
    pub fn my_len(&self) -> usize {
        self.mine.len()
    }

    /// Returns the number of unspent triples we will have in the manager once
    /// all ongoing generation protocols complete.
    pub fn potential_len(&self) -> usize {
        self.len() + self.generators.len()
    }

    /// Clears an entry from failed triples if that triple protocol was created more than 2 hrs ago
    pub fn clear_failed_triples(&mut self) {
        self.failed_triples
            .retain(|_, timestamp| timestamp.elapsed() < FAILED_TRIPLES_TIMEOUT)
    }

    pub fn clear_taken(&mut self) {
        self.taken
            .retain(|_, timestamp| timestamp.elapsed() < TAKEN_TIMEOUT)
    }

    /// Starts a new Beaver triple generation protocol.
    pub fn generate(
        &mut self,
        participants: &Participants<AccountId>,
    ) -> Result<(), InitializationError> {
        let id = rand::random();

        tracing::debug!(id, "starting protocol to generate a new triple");

        let participants: Vec<Participant> =
            participants.keys().cloned().map(|p| p.into()).collect();
        let protocol: TripleProtocol = Box::new(cait_sith::triples::generate_triple::<Secp256k1>(
            &participants,
            self.me,
            self.threshold,
        )?);
        self.generators
            .insert(id, TripleGenerator::new(id, participants, protocol));
        self.queued.push_back(id);
        self.introduced.insert(id);

        Ok(())
    }

    /// Stockpile triples if the amount of unspent triples is below the minimum
    /// and the maximum number of all ongoing generation protocols is below the maximum.
    pub fn stockpile(
        &mut self,
        participants: &Participants<AccountId>,
    ) -> Result<(), InitializationError> {
        let TripleConfig {
            min_triples,
            max_triples,
            max_concurrent_introduction,
            max_concurrent_generation,
        } = self.triple_cfg;

        let not_enough_triples = {
            // Stopgap to prevent too many triples in the system. This should be around min_triple*nodes*2
            // for good measure so that we have enough triples to do presig generation while also maintain
            // the minimum number of triples where a single node can't flood the system.
            if self.potential_len() >= max_triples {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.my_len() < min_triples
                    && self.introduced.len() < max_concurrent_introduction
                    && self.generators.len() < max_concurrent_generation
            }
        };

        if not_enough_triples {
            self.generate(participants)?;
        }
        Ok(())
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(
        &mut self,
        id0: TripleId,
        id1: TripleId,
    ) -> Result<(Triple, Triple), GenerationError> {
        if !self.triples.contains_key(&id0) {
            Err(GenerationError::TripleIsMissing(id0))
        } else if !self.triples.contains_key(&id1) {
            Err(GenerationError::TripleIsMissing(id1))
        } else {
            self.delete_triple_from_storage(id0).await?;
            self.delete_triple_from_storage(id1).await?;
            self.taken.insert(id0, Instant::now());
            self.taken.insert(id1, Instant::now());

            // only remove the triples locally when the datastore removal was successful
            Ok((
                self.triples.remove(&id0).unwrap(),
                self.triples.remove(&id1).unwrap(),
            ))
        }
    }

    async fn delete_triple_from_storage(&mut self, id: TripleId) -> Result<(), GenerationError> {
        let action = || async {
            let mut triple_storage = self.triple_storage.write().await;
            if let Err(err) = triple_storage.delete(id).await {
                tracing::warn!(?err, id, "triple deletion failed.");

                return Err(GenerationError::DatastoreStorageError(err));
            }
            Ok(())
        };

        // Retry the action 3x with 500ms delay between each retry
        //let retry_strategy = std::iter::repeat_with(|| Duration::from_millis(500)).take(3);
        //tokio_retry::Retry::spawn(retry_strategy, action).await

        action().await.unwrap();

        Ok(())
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&mut self) -> Option<(Triple, Triple)> {
        tracing::debug!(me = ?self.me, mine = ?self.mine, "take two mine");

        if self.mine.len() < 2 {
            return None;
        }
        let id0 = self.mine.pop_front()?;
        let id1 = self.mine.pop_front()?;

        tracing::info!(id0, id1, me = ?self.me, "trying to take two triples");

        let take_two_result = self.take_two(id0, id1).await;
        match take_two_result {
            Err(error) => {
                tracing::warn!(?error, "take_two failed in take_two_mine.");

                self.mine.push_front(id1);
                self.mine.push_front(id0);
                None
            }
            Ok(val) => Some(val),
        }
    }

    pub async fn insert_mine(&mut self, triple: Triple) {
        self.mine.push_back(triple.id);
        self.triples.insert(triple.id, triple.clone());
        self.taken.remove(&triple.id);
        self.insert_triples_to_storage(vec![triple]).await;
    }

    /// Ensures that the triple with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`
    // TODO: What if the triple completed generation and is already spent?
    pub fn get_or_generate(
        &mut self,
        id: TripleId,
        participants: &Participants<AccountId>,
    ) -> Result<Option<&mut TripleProtocol>, CryptographicError> {
        if self.triples.contains_key(&id) || self.taken.contains_key(&id) {
            Ok(None)
        } else {
            let potential_len = self.potential_len();
            match self.generators.entry(id) {
                Entry::Vacant(e) => {
                    if potential_len >= self.triple_cfg.max_triples {
                        // We are at the maximum amount of triples, we cannot generate more. So just in case a node
                        // sends more triple generation requests, reject them and have them tiemout.
                        return Ok(None);
                    }

                    tracing::debug!(id, "joining protocol to generate a new triple");

                    let participants: Vec<Participant> =
                        participants.keys().map(|p| (*p).into()).collect();
                    let protocol = Box::new(cait_sith::triples::generate_triple::<Secp256k1>(
                        &participants,
                        self.me,
                        self.threshold,
                    )?);
                    let generator = e.insert(TripleGenerator::new(id, participants, protocol));
                    self.queued.push_back(id);

                    Ok(Some(&mut generator.protocol))
                }
                Entry::Occupied(e) => Ok(Some(&mut e.into_mut().protocol)),
            }
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub async fn poke(&mut self) -> Result<Vec<(Participant, TripleMessage)>, ProtocolError> {
        // Add more protocols to the ongoing pool if there is space.
        let to_generate_len = self.triple_cfg.max_concurrent_generation - self.ongoing.len();
        if !self.queued.is_empty() && to_generate_len > 0 {
            for _ in 0..to_generate_len {
                self.queued.pop_front().map(|id| self.ongoing.insert(id));
            }
        }

        let mut messages = Vec::new();
        let mut result = Ok(());
        let mut triples_to_insert = Vec::new();
        self.generators.retain(|id, generator| {
            if !self.ongoing.contains(id) {
                // If the protocol is not ongoing, we should retain it for the next time
                // it is in the ongoing pool.
                return true;
            }

            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        result = Err(e);
                        self.failed_triples.insert(*id, Instant::now());
                        self.ongoing.remove(id);
                        self.introduced.remove(id);

                        tracing::info!(
                           elapsed = ?generator.timestamp.unwrap().elapsed(),
                           "added {id} to failed triples"
                        );

                        break false;
                    }
                };

                match action {
                    Action::Wait => {
                        tracing::debug!("waiting");

                        // Retain protocol until we are finished
                        break true;
                    }
                    Action::SendMany(data) => {
                        for p in &generator.participants {
                            messages.push((
                                *p,
                                TripleMessage {
                                    id: *id,
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
                        TripleMessage {
                            id: *id,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc::now().timestamp() as u64,
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                           id,
                           me = ?self.me,
                           elapsed = ?generator.timestamp.unwrap().elapsed(),
                           big_a = ?output.1.big_a,//.to_base58(),
                           big_b = ?output.1.big_b,//.to_base58(),
                           big_c = ?output.1.big_c,//.to_base58(),
                           "completed triple generation"
                        );

                        let triple = Triple {
                            id: *id,
                            share: output.0,
                            public: output.1,
                        };

                        // After creation the triple is assigned to a random node, which is NOT necessarily the one that initiated it's creation
                        let triple_is_mine = {
                            // This is an entirely unpredictable value to all participants because it's a combination of big_c_i
                            // It is the same value across all participants
                            let big_c = triple.public.big_c;

                            // We turn this into a u64 in a way not biased to the structure of the byte serialisation so we hash it
                            // We use Highway Hash because the DefaultHasher doesn't guarantee a consistent output across versions
                            let entropy =
                                HighwayHasher::default().hash64(&big_c.to_bytes()) as usize;

                            let num_participants = generator.participants.len();
                            // This has a *tiny* bias towards lower indexed participants, they're up to (1 + num_participants / u64::MAX)^2 times more likely to be selected
                            // This is acceptably small that it will likely never result in a biased selection happening
                            let triple_owner = generator.participants[entropy % num_participants];

                            triple_owner == self.me
                        };

                        if triple_is_mine {
                            self.mine.push_back(*id);
                        }

                        self.triples.insert(*id, triple.clone());
                        triples_to_insert.push(triple);

                        // Protocol done, remove it from the ongoing pool.
                        self.ongoing.remove(id);
                        self.introduced.remove(id);
                        // Do not retain the protocol
                        break false;
                    }
                }
            }
        });
        self.insert_triples_to_storage(triples_to_insert).await;
        result.map(|_| messages)
    }

    async fn insert_triples_to_storage(&mut self, triples_to_insert: Vec<Triple>) {
        for triple in triples_to_insert {
            let mine = self.mine.contains(&triple.id);
            let action = || async {
                let mut triple_storage = self.triple_storage.write().await;
                if let Err(e) = triple_storage.insert(triple.clone(), mine).await {
                    tracing::warn!(?e, id = triple.id, "triple insertion failed.");

                    return Err(e);
                }
                Ok(())
            };

            // Retry the action 3x with 500ms delay between each retry
            //let retry_strategy = std::iter::repeat_with(|| Duration::from_millis(500)).take(3);
            //let _ = tokio_retry::Retry::spawn(retry_strategy, action).await;

            action().await.unwrap();
        }
    }
}
