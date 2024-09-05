#![cfg_attr(not(feature = "std"), no_std)]

use pallet_mpc_manager::{ProtocolState, PublicKey, Request};

sp_api::decl_runtime_apis! {
    pub trait MpcManagerApi<AccountId> where
        AccountId: codec::Codec + Ord
    {
        fn protocol_state() -> ProtocolState<AccountId>;
        fn signature_requests() -> sp_std::vec::Vec<Request>;
        fn derive_account(account_id: AccountId, path: sp_std::vec::Vec<u8>) -> PublicKey;
    }
}
