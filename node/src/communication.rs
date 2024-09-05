use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use cait_sith::protocol::Participant;
use codec::{Decode, Encode};
use sc_network::{Multiaddr, NetworkPeers, NotificationService, PeerId};
use serde::Serialize;
use tokio::sync::{mpsc::Sender, Mutex};

use super::{
    message::{MpcMessage, SignedMessage},
    mpc_keys::Ciphered,
    on_chain::{
        CandidateInfo, Candidates, ParticipantEnc, ParticipantInfo, Participants, PeerIdEnc,
        ProtocolState,
    },
};

#[derive(Clone)]
pub struct NetworkConfig {
    pub sign_sk: sp_core::sr25519::Pair,
    pub cipher_pk: super::mpc_keys::PublicKey,
}

pub struct Peers<AccountId> {
    pub connected_peers: HashSet<PeerId>,

    pub active_participants: Participants<AccountId>,

    pub all_participants: Participants<AccountId>,

    pub active_potential_participants: Participants<AccountId>,
}

impl<AccountId> Default for Peers<AccountId> {
    fn default() -> Self {
        Self {
            connected_peers: Default::default(),
            active_participants: Participants {
                participants: Default::default(),
            },
            active_potential_participants: Participants {
                participants: Default::default(),
            },
            all_participants: Participants {
                participants: Default::default(),
            },
        }
    }
}

impl<AccountId: Encode + Decode + Eq + Ord + Clone> Peers<AccountId> {
    pub fn active_participants(&self) -> &Participants<AccountId> {
        &self.active_participants
    }

    pub fn active_participants_and_me(
        &self,
        me: &ParticipantInfo<AccountId>,
    ) -> Participants<AccountId> {
        let mut participants = self.active_participants.participants.clone().into_inner();

        participants.insert(Participant::from(me.id).into(), me.clone());

        Participants {
            participants: participants.try_into().unwrap(),
        }
    }

    pub fn active_participants_without_me(&self, me: Participant) -> Participants<AccountId> {
        Participants {
            participants: self
                .active_participants
                .participants
                .clone()
                .into_inner()
                .into_iter()
                .filter(|(p, _)| *p != ParticipantEnc::from(me))
                .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>()
                .try_into()
                .unwrap(),
        }
    }

    pub fn all_participants(&self) -> &Participants<AccountId> {
        &self.all_participants
    }

    pub fn active_potential_participants(&self) -> &Participants<AccountId> {
        &self.active_potential_participants
    }

    pub fn all_active_participants(&self) -> Participants<AccountId> {
        let mut participants = self.active_participants.clone();
        let active = self
            .active_potential_participants
            .keys()
            .collect::<Vec<_>>();
        tracing::info!(?active, "Getting potentially active participants");
        for (participant, info) in self.active_potential_participants.iter() {
            if !participants.contains_key(participant) {
                participants.insert(participant, info.clone());
            }
        }
        participants
    }

    // pub async fn potential_participants(&self) -> Participants {
    //     self.connections.potential_participants().await
    // }

    pub fn add_connected_peer(&mut self, peer_id: PeerId) {
        self.connected_peers.insert(peer_id);
    }

    pub fn remove_connected_peer(&mut self, peer_id: PeerId) {
        self.connected_peers.remove(&peer_id);

        let peer_id = PeerIdEnc::from(peer_id);

        self.active_participants = Participants {
            participants: self
                .active_participants
                .participants
                .clone()
                .into_inner()
                .into_iter()
                .filter(|(_, info)| info.peer_id != peer_id)
                .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>()
                .try_into()
                .unwrap(),
        };

        self.active_potential_participants = Participants {
            participants: self
                .active_potential_participants
                .participants
                .clone()
                .into_inner()
                .into_iter()
                .filter(|(_, info)| info.peer_id != peer_id)
                .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>()
                .try_into()
                .unwrap(),
        };
    }

    pub async fn establish_participants(&mut self, protocol_state: &ProtocolState<AccountId>) {
        let connected_peers = self.connected_peers.clone();

        match protocol_state {
            ProtocolState::Initializing(protocol_state) => {
                let unfiltered = Participants::try_from(protocol_state.candidates.clone()).unwrap();

                let filtered = unfiltered
                    .participants
                    .clone()
                    .into_inner()
                    .into_iter()
                    .filter(|(_, info)| connected_peers.contains(&info.peer_id.clone().into()))
                    .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>();

                self.all_participants = unfiltered;

                self.active_participants = Participants {
                    participants: filtered.try_into().unwrap(),
                };
            }
            ProtocolState::Running(protocol_state) => {
                let unfiltered = protocol_state.participants.clone();

                let filtered = unfiltered
                    .participants
                    .clone()
                    .into_inner()
                    .into_iter()
                    .filter(|(_, info)| connected_peers.contains(&info.peer_id.clone().into()))
                    .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>();

                self.all_participants = unfiltered;

                self.active_participants = Participants {
                    participants: filtered.try_into().unwrap(),
                };
            }
            ProtocolState::Resharing(protocol_state) => {
                let unfiltered_new = protocol_state.new_participants.clone();

                let filtered_old = protocol_state
                    .old_participants
                    .participants
                    .clone()
                    .into_inner()
                    .into_iter()
                    .filter(|(_, info)| connected_peers.contains(&info.peer_id.clone().into()))
                    .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>();

                let filtered_new = unfiltered_new
                    .participants
                    .clone()
                    .into_inner()
                    .into_iter()
                    .filter(|(_, info)| connected_peers.contains(&info.peer_id.clone().into()))
                    .collect::<BTreeMap<ParticipantEnc, ParticipantInfo<AccountId>>>();

                self.all_participants = unfiltered_new;

                self.active_participants = Participants {
                    participants: filtered_old.try_into().unwrap(),
                };

                self.active_potential_participants = Participants {
                    participants: filtered_new.try_into().unwrap(),
                };
            }
        }
    }

    // pub async fn ping(&mut self) {
    //     self.active_participants = self.connections.ping().await;
    //     self.active_potential_participants = self.connections.ping_potential().await;
    // }
}

async fn send_encrypted(
    _from: Participant,
    notif_handle: Sender<(PeerId, Vec<u8>)>,
    peer_id: &PeerId,
    message: Vec<Ciphered>,
) -> Result<(), SendError> {
    let _span = tracing::info_span!("message_request");

    let action = || async {
        let res = notif_handle
            .send((*peer_id, bincode::serialize(&message).unwrap()))
            .await;

        if let Err(e) = res {
            tracing::error!("failed to send a message to {} with error: {}", peer_id, e);

            Err(SendError::Unsuccessful(e.to_string()))
        } else {
            Ok(())
        }
    };

    // let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
    // Retry::spawn(retry_strategy, action).await

    action().await
}

// #[derive(Default)]
pub struct MessageQueue<AccountId, Hash> {
    deque: VecDeque<(ParticipantInfo<AccountId>, MpcMessage<Hash>, Instant)>,
    seen_counts: HashSet<String>,
}

impl<AccountId, Hash> Default for MessageQueue<AccountId, Hash> {
    fn default() -> Self {
        Self {
            deque: VecDeque::default(),
            seen_counts: HashSet::default(),
        }
    }
}

impl<AccountId: Encode + Decode + Eq + Ord + Clone + std::fmt::Debug, Hash: Serialize>
    MessageQueue<AccountId, Hash>
{
    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn push(&mut self, info: ParticipantInfo<AccountId>, msg: MpcMessage<Hash>) {
        self.deque.push_back((info, msg, Instant::now()));
    }

    pub async fn send_encrypted(
        &mut self,
        from: Participant,
        sign_sk: &sp_core::sr25519::Pair,
        notif_handle: Sender<(PeerId, Vec<u8>)>,
        participants: &Participants<AccountId>,
    ) -> Vec<SendError> {
        let mut failed = VecDeque::new();
        let mut errors = Vec::new();
        let mut participant_counter = HashMap::new();

        let outer = Instant::now();
        let uncompacted = self.deque.len();
        let mut encrypted = HashMap::new();
        while let Some((info, msg, instant)) = self.deque.pop_front() {
            if instant.elapsed() > message_type_to_timeout(&msg) {
                errors.push(SendError::Timeout(format!(
                    "{} message has timed out: {info:?}",
                    msg.typename(),
                )));
                continue;
            }

            if !participants.contains_key(&Participant::from(info.id).into()) {
                let counter = participant_counter.entry(info.id).or_insert(0);
                *counter += 1;
                failed.push_back((info, msg, instant));
                continue;
            }

            tracing::debug!(
                "Encrypting a message for the following pk: {}",
                hex::encode(super::mpc_keys::PublicKey::from(info.cipher_pk.clone()).to_bytes())
            );

            let encrypted_msg =
                match SignedMessage::encrypt(&msg, from, sign_sk, &info.cipher_pk.clone().into()) {
                    Ok(encrypted) => encrypted,
                    Err(err) => {
                        errors.push(SendError::EncryptionError(err.to_string()));
                        continue;
                    }
                };
            let encrypted = encrypted.entry(info.id).or_insert_with(Vec::new);
            encrypted.push((encrypted_msg, (info, msg, instant)));
        }

        let mut compacted = 0;
        for (id, encrypted) in encrypted {
            for partition in partition_ciphered_256kb(encrypted) {
                let (encrypted_partition, msgs): (Vec<_>, Vec<_>) = partition.into_iter().unzip();
                // guaranteed to unwrap due to our previous loop check:
                let info = participants.get(&Participant::from(id).into()).unwrap();
                // let account_id = &info.account_id;

                // let start = Instant::now();

                //let notif_handle_locked = notif_handle.lock().await.clone().unwrap();

                if let Err(err) = send_encrypted(
                    from,
                    notif_handle.clone(),
                    &info.peer_id.clone().into(),
                    encrypted_partition,
                )
                .await
                {
                    // since we failed, put back all the messages related to this
                    failed.extend(msgs);
                    errors.push(err);
                } else {
                    compacted += msgs.len();
                }
            }
        }

        if uncompacted > 0 {
            tracing::debug!(
                uncompacted,
                compacted,
                "{from:?} sent messages in {:?};",
                outer.elapsed()
            );
        }
        // only add the participant count if it hasn't been seen before.
        let counts = format!("{participant_counter:?}");
        if !participant_counter.is_empty() && self.seen_counts.insert(counts.clone()) {
            errors.push(SendError::ParticipantNotAlive(format!(
                "participants not responding: {counts:?}",
            )));
        }

        // Add back the failed attempts for next time.
        self.deque = failed;
        errors
    }
}

/// Encrypted message with a reference to the old message. Only the ciphered portion of this
/// type will be sent over the wire, while the original message is kept just in case things
/// go wrong somewhere and the message needs to be requeued to be sent later.
type EncryptedMessage<AccountId, Hash> = (
    Ciphered,
    (ParticipantInfo<AccountId>, MpcMessage<Hash>, Instant),
);

fn partition_ciphered_256kb<AccountId, Hash>(
    encrypted: Vec<EncryptedMessage<AccountId, Hash>>,
) -> Vec<Vec<EncryptedMessage<AccountId, Hash>>> {
    let mut result = Vec::new();
    let mut current_partition = Vec::new();
    let mut current_size: usize = 0;

    for ciphered in encrypted {
        let bytesize = ciphered.0.text.len();
        if current_size + bytesize > 256 * 1024 {
            // If adding this byte vector exceeds 256kb, start a new partition
            result.push(current_partition);
            current_partition = Vec::new();
            current_size = 0;
        }
        current_partition.push(ciphered);
        current_size += bytesize;
    }

    if !current_partition.is_empty() {
        // Add the last partition
        result.push(current_partition);
    }

    result
}

fn message_type_to_timeout<Hash>(msg: &MpcMessage<Hash>) -> Duration {
    match msg {
        MpcMessage::Generating(_) => MESSAGE_TIMEOUT,
        MpcMessage::Resharing(_) => MESSAGE_TIMEOUT,
        MpcMessage::Triple(_) => super::util::get_triple_timeout(),
        MpcMessage::Presignature(_) => super::types::PROTOCOL_PRESIG_TIMEOUT,
        MpcMessage::Signature(_) => super::types::PROTOCOL_SIGNATURE_TIMEOUT,
    }
}

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("http request was unsuccessful: {0}")]
    Unsuccessful(String),
    #[error("serialization unsuccessful: {0}")]
    DataConversionError(serde_json::Error),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("http request timeout: {0}")]
    Timeout(String),
    #[error("participant is not alive: {0}")]
    ParticipantNotAlive(String),
}
