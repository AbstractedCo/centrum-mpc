use cait_sith::protocol::Participant;
use sc_network::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub use centrum_mpc_common::{MpcKeysPublicKey, ParticipantEnc, PeerIdEnc};
pub use pallet_mpc_manager::PublicKey;

pub type Participants<AccountId> = pallet_mpc_manager::Participants<AccountId>;
pub type ProtocolState<AccountId> = pallet_mpc_manager::ProtocolState<AccountId>;
pub type Candidates<AccountId> = pallet_mpc_manager::Candidates<AccountId>;
pub type RunningChainState<AccountId> = pallet_mpc_manager::RunningChainState<AccountId>;
pub type ResharingChainState<AccountId> = pallet_mpc_manager::ResharingChainState<AccountId>;
pub type Votes<AccountId> = pallet_mpc_manager::Votes<AccountId>;
pub type PkVotes<AccountId> = pallet_mpc_manager::PkVotes<AccountId>;
pub type ParticipantInfo<AccountId> = pallet_mpc_manager::ParticipantInfo<AccountId>;
pub type CandidateInfo<AccountId> = pallet_mpc_manager::CandidateInfo<AccountId>;
