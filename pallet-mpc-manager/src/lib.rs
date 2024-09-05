#![cfg_attr(not(feature = "std"), no_std)]

use elliptic_curve::{scalar::FromUintUnchecked, CurveArithmetic};
use frame_support::traits::Get;
use k256::{
    ecdsa::{self, VerifyingKey},
    elliptic_curve::{
        ops::{Invert, Reduce},
        point::AffineCoordinates,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        ProjectivePoint,
    },
    AffinePoint, EncodedPoint, Scalar, Secp256k1, U256,
};
use parity_scale_codec::{Decode, Encode, WrapperTypeDecode};
use sp_core::H160;
use sp_std::{convert::TryInto, str::FromStr};

use centrum_mpc_common::{MpcKeysPublicKey, ParticipantEnc, PeerIdEnc};

mod types;

pub use pallet::*;
pub use types::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use sp_core::H160;
    use sp_runtime::offchain::storage::StorageValueRef;
    use sp_std::hash::Hash;

    use super::*;
    use frame_support::{
        pallet_prelude::{ValueQuery, *},
        traits::IsType,
    };
    use frame_system::{
        ensure_signed,
        pallet_prelude::{BlockNumberFor, OriginFor},
    };
    //use pallet_inv4::origin::{ensure_multisig, INV4Origin};
    use sp_std::{vec, vec::Vec};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::storage]
    #[pallet::getter(fn protocol_state)]
    pub type CurrentProtocolState<T: Config> =
        StorageValue<_, ProtocolState<T::AccountId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn signature_requests)]
    pub type SignatureRequests<T: Config> =
        StorageMap<_, Blake2_128Concat, Request, Option<(Vec<u8>, Vec<u8>)>>;

    #[pallet::storage]
    #[pallet::getter(fn next_participant_id)]
    pub type NextParticipantId<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::error]
    pub enum Error<T> {
        AlreadyStartedInitializing,
        NotInitializing,
        NotACandidate,
        SignatureAlreadyRequested,
        SignatureNotRequested,
        InvalidSignature,
        Unknown,
    }

    #[pallet::event]
    #[pallet::generate_deposit(fn deposit_event)]
    pub enum Event<T: Config> {
        Test,

        ProtocolInitialized {
            participants: Vec<T::AccountId>,
            threshold: u32,
            public_key: H160,
        },

        SignatureRequested {
            requested_by: T::AccountId,
            path: Vec<u8>,
            payload: [u8; 32],
            epsilon: [u8; 32],
        },

        SignatureDelivered {
            delivered_by: T::AccountId,
            payload: [u8; 32],
            epsilon: [u8; 32],
            big_r: Vec<u8>,
            s: Vec<u8>,
        },

        ThisIsYourAddress {
            requester: T::AccountId,
            address: H160,
        },
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(_block_number: BlockNumberFor<T>) {
            // let parent_hash = <frame_system::Pallet<T>>::block_hash(block_number - 1u32.into());

            let requests = SignatureRequests::<T>::iter()
                .filter_map(|(l, r)| if r.is_some() { None } else { Some(l) })
                .collect::<Vec<([u8; 32], [u8; 32])>>();

            let requests_storage = StorageValueRef::persistent(b"mpc_manager_ocw::requests");

            requests_storage.set(&requests);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight((0, Pays::No))]
        pub fn force_join(
            origin: OriginFor<T>,
            peer_id: PeerIdEnc,
            cipher_pk: MpcKeysPublicKey,
            sign_pk: sp_core::sr25519::Public,
            threshold: u32,
        ) -> DispatchResult {
            let account_id = ensure_signed(origin)?;

            match Self::protocol_state() {
                ProtocolState::Initializing(InitializingChainState {
                    candidates,
                    pk_votes,
                    ..
                }) => {
                    let id = Self::next_participant_id();

                    let mut new_candidates = candidates.candidates.clone().into_inner();

                    new_candidates.insert(
                        account_id.clone(),
                        CandidateInfo {
                            id,
                            account_id,
                            peer_id,
                            cipher_pk,
                            sign_pk,
                        },
                    );

                    CurrentProtocolState::<T>::set(ProtocolState::Initializing(
                        InitializingChainState {
                            candidates: Candidates {
                                candidates: new_candidates
                                    .try_into()
                                    .map_err(|_| Error::<T>::Unknown)?,
                            },
                            threshold,
                            pk_votes,
                        },
                    ));

                    NextParticipantId::<T>::set(id + 1);

                    Ok(())
                }

                _ => Err(Error::<T>::NotInitializing.into()),
            }
        }

        #[pallet::call_index(1)]
        #[pallet::weight((0, Pays::No))]
        pub fn vote_public_key(origin: OriginFor<T>, public_key: PublicKey) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            if let ProtocolState::Initializing(InitializingChainState {
                candidates,
                threshold,
                pk_votes,
            }) = Self::protocol_state()
            {
                ensure!(candidates.contains_key(&caller), Error::<T>::NotACandidate);

                let mut votes = pk_votes.get(&public_key.clone().into()).unwrap_or_default();

                votes.insert(caller);

                if votes.len() >= threshold as usize {
                    let participants: Participants<T::AccountId> = candidates
                        .clone()
                        .try_into()
                        .map_err(|_| Error::<T>::Unknown)?;

                    CurrentProtocolState::<T>::set(ProtocolState::Running(RunningChainState {
                        epoch: 0,
                        participants: participants.clone(),
                        threshold,
                        public_key: public_key.clone(),
                        candidates: Candidates {
                            candidates: Default::default(),
                        },
                        join_votes: Votes {
                            votes: Default::default(),
                        },
                        leave_votes: Votes {
                            votes: Default::default(),
                        },
                    }));

                    Self::deposit_event(Event::<T>::ProtocolInitialized {
                        participants: participants
                            .participants
                            .into_inner()
                            .into_values()
                            .map(|p| p.account_id)
                            .collect::<Vec<T::AccountId>>(),
                        threshold,
                        public_key: public_key.to_eth_address(),
                    });
                } else {
                    let mut new_pk_votes = pk_votes.pk_votes.into_inner();
                    new_pk_votes.insert(public_key.clone().into(), votes.try_into().unwrap());

                    CurrentProtocolState::<T>::set(ProtocolState::Initializing(
                        InitializingChainState {
                            candidates,
                            threshold,
                            pk_votes: PkVotes {
                                pk_votes: new_pk_votes.try_into().unwrap(),
                            },
                        },
                    ))
                }

                Ok(())
            } else {
                Err(Error::<T>::NotInitializing.into())
            }
        }

        #[pallet::call_index(2)]
        #[pallet::weight((0, Pays::No))]
        pub fn request_signature(
            origin: OriginFor<T>,
            payload: [u8; 32],
            path: Vec<u8>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let epsilon = derive_epsilon::<T::AccountId>(&caller, path.clone());

            if Self::signature_requests((payload, epsilon)).is_none() {
                SignatureRequests::<T>::insert((payload, epsilon), None::<(Vec<u8>, Vec<u8>)>);

                Self::deposit_event(Event::<T>::SignatureRequested {
                    requested_by: caller,
                    path,
                    payload,
                    epsilon,
                });

                Ok(())
            } else {
                Err(Error::<T>::SignatureAlreadyRequested.into())
            }
        }

        #[pallet::call_index(3)]
        #[pallet::weight((0, Pays::No))]
        pub fn deliver_signature(
            origin: OriginFor<T>,
            payload: [u8; 32],
            epsilon: [u8; 32],
            big_r: Vec<u8>,
            s: Vec<u8>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            SignatureRequests::<T>::try_mutate((payload, epsilon), |value| {
                if let Some(None) = value {
                    if Self::verify_signature_2_2(payload, epsilon, &big_r, &s) {
                        *value = None;

                        Self::deposit_event(Event::<T>::SignatureDelivered {
                            delivered_by: caller,
                            payload,
                            epsilon,
                            big_r,
                            s,
                        });

                        Ok(())
                    } else {
                        Err(Error::<T>::InvalidSignature.into())
                    }
                } else {
                    Err(Error::<T>::SignatureNotRequested.into())
                }
            })
        }

        #[pallet::call_index(99)]
        #[pallet::weight((0, Pays::No))]
        pub fn whats_my_address(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            path: Vec<u8>,
        ) -> DispatchResult {
            Self::deposit_event(Event::<T>::ThisIsYourAddress {
                requester: account_id.clone(),
                address: Self::derive_ethereum_address(&account_id, path),
            });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn get_protocol_state() -> ProtocolState<T::AccountId> {
            Self::protocol_state()
        }

        pub fn get_signature_requests() -> Vec<Request> {
            SignatureRequests::<T>::iter_keys().collect()
        }

        pub fn root_public_key() -> PublicKey {
            match Self::protocol_state() {
                ProtocolState::Running(state) => state.public_key.clone(),
                ProtocolState::Resharing(state) => state.public_key.clone(),
                _ => panic!("TODO: Write better code."),
            }
        }

        pub fn derive_account(account_id: &T::AccountId, path: Vec<u8>) -> PublicKey {
            let root_public_key = Self::root_public_key();

            inner_derive_account(root_public_key.0, account_id, path)
        }

        pub fn derive_ethereum_address(account_id: &T::AccountId, path: Vec<u8>) -> H160 {
            let root_public_key = Self::root_public_key();

            inner_derive_account(root_public_key.0, account_id, path).to_eth_address()
        }

        // fn verify_signature(
        //     payload_hash: [u8; 32],
        //     epsilon: [u8; 32],
        //     big_r: &Vec<u8>,
        //     s: &Vec<u8>,
        // ) -> Result<(), Error<T>> {
        //     let root_key = Self::derive_key(&epsilon)
        //         .into_affine()
        //         .to_encoded_point(false)
        //         .to_bytes();

        //     let expected_key = Self::derive_key_2(root_key.to_vec(), &epsilon).into_affine();

        //     // Prepare R ans s signature values
        //     let big_r = hex::decode(big_r).unwrap();
        //     let big_r = EncodedPoint::from_bytes(big_r).unwrap();
        //     let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();
        //     let big_r_y_parity = big_r.y_is_odd().unwrap_u8() as i32;
        //     assert!(big_r_y_parity == 0 || big_r_y_parity == 1);

        //     let s = hex::decode(s).unwrap();
        //     let s = k256::Scalar::from_uint_unchecked(k256::U256::from_be_slice(s.as_slice()));
        //     let r = x_coordinate(&big_r);

        //     let k256_sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        //     let mut payload_hash = payload_hash.to_vec();
        //     payload_hash.reverse();

        //     let user_pk_k256: k256::elliptic_curve::PublicKey<Secp256k1> =
        //         k256::PublicKey::from_affine(expected_key).unwrap();

        //     verify(
        //         &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
        //         &payload_hash,
        //         &k256_sig,
        //     )
        //     .map_err(|_| Error::<T>::WrongSignature)
        // }

        // pub fn derive_key(epsilon: &[u8; 32]) -> PublicKey {
        //     let root_public_key: Vec<u8> =
        //         Secp256K1PublicKey::from(Self::root_public_key()).0[..].to_vec();

        //     Self::derive_key_2(root_public_key, epsilon)
        // }

        // pub fn derive_key_2(mut root_public_key: Vec<u8>, epsilon: &[u8; 32]) -> PublicKey {
        //     let epsilon = scalar_from_bytes(epsilon);
        //     // This will always succeed because the underlying type is [u8;64]

        //     // Remove the first element which is the curve type
        //     root_public_key[0] = 0x04;
        //     let point = EncodedPoint::from_bytes(root_public_key).unwrap();
        //     let public_key = AffinePoint::from_encoded_point(&point).unwrap();

        //     let affine = (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon
        //         + public_key)
        //         .to_affine();

        //     PublicKey::from_affine(affine)
        // }

        pub fn derive_key(epsilon: &[u8; 32]) -> Affine {
            let root_public_key = Self::root_public_key().0;

            derive_key_2(root_public_key, epsilon)
        }

        fn verify_signature(
            &self,
            payload_hash: [u8; 32],
            epsilon: [u8; 32],
            big_r: &str,
            s: &str,
        ) {
            let expected_key = Self::derive_key(&epsilon)
                .to_encoded_point(false)
                .to_bytes();
            verify_signature_2(expected_key, payload_hash, epsilon, big_r, s);
        }

        fn verify_signature_2_2(
            payload_hash: [u8; 32],
            epsilon: [u8; 32],
            big_r: &[u8],
            s: &[u8],
        ) -> bool {
            let root_public_key = Self::root_public_key().0;

            let derived_key = derive_key_2_3(root_public_key, &epsilon);

            let big_r =
                AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(big_r).unwrap()).unwrap();

            let s = scalar_from_bytes(&s);

            let payload_scalar = scalar_from_bytes(&payload_hash);

            verifyy(&big_r, &s, &derived_key, &payload_scalar)
        }
    }
}

pub fn inner_derive_account<AccountId: Encode>(
    root_public_key: sp_std::vec::Vec<u8>,
    account_id: AccountId,
    path: sp_std::vec::Vec<u8>,
) -> PublicKey {
    let epsilon = derive_epsilon(&account_id, path);

    let affine = derive_key_2_3(root_public_key, &epsilon);

    PublicKey::from_affine(affine)
}

fn derive_epsilon<AccountId: Encode>(account: &AccountId, path: sp_std::vec::Vec<u8>) -> [u8; 32] {
    // Constant prefix that ensures epsilon derivation values are used specifically for
    // invarch-tss-node with key derivation protocol vX.Y.Z.
    // TODO put this somewhere shared
    const EPSILON_DERIVATION_PREFIX: &str = "centrum-tss-node v0.0.1 epsilon derivation:";

    let mut derivation_path = EPSILON_DERIVATION_PREFIX.as_bytes().to_vec();
    derivation_path.extend_from_slice(&account.encode());
    derivation_path.push(b',');
    derivation_path.extend_from_slice(&path);

    let res = sp_core::hashing::sha2_256(&derivation_path);
    // Our key derivation algorithm is backwards for reasons of historical mistake
    // res.reverse();

    res.try_into().expect("That sha256 is 32 bytes long")
}

pub fn derive_key_2(mut root_public_key: sp_std::vec::Vec<u8>, epsilon: &[u8; 32]) -> Affine {
    let epsilon = scalar_from_bytes(epsilon);
    // This will always succeed because the underlying type is [u8;64]

    // Remove the first element which is the curve type
    root_public_key[0] = 0x04;
    let point = EncodedPoint::from_bytes(root_public_key).unwrap();
    let public_key = AffinePoint::from_encoded_point(&point).unwrap();

    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

pub fn derive_key_2_2(root_public_key: Affine, epsilon: &[u8; 32]) -> Affine {
    let epsilon = scalar_from_bytes(epsilon);
    // This will always succeed because the underlying type is [u8;64]

    let mut root_public_key = root_public_key.to_encoded_point(false).to_bytes();

    // Remove the first element which is the curve type
    root_public_key[0] = 0x04;
    let point = EncodedPoint::from_bytes(root_public_key).unwrap();
    let public_key = AffinePoint::from_encoded_point(&point).unwrap();

    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

pub fn derive_key_2_3(root_public_key: sp_std::vec::Vec<u8>, epsilon: &[u8; 32]) -> Affine {
    let epsilon = scalar_from_bytes(epsilon);
    // This will always succeed because the underlying type is [u8;64]

    let point = EncodedPoint::from_bytes(root_public_key).unwrap();
    let public_key = AffinePoint::from_encoded_point(&point).unwrap();

    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

pub fn verify_signature_2(
    root_key: sp_std::boxed::Box<[u8]>,
    payload_hash: [u8; 32],
    epsilon: [u8; 32],
    big_r: &str,
    s: &str,
) {
    let expected_key = derive_key_2(root_key.to_vec(), &epsilon);

    // Prepare R ans s signature values
    let big_r = hex::decode(big_r).unwrap();
    let big_r = EncodedPoint::from_bytes(big_r).unwrap();
    let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();
    let big_r_y_parity = big_r.y_is_odd().unwrap_u8() as i32;
    assert!(big_r_y_parity == 0 || big_r_y_parity == 1);

    let s = hex::decode(s).unwrap();
    let s = k256::Scalar::from_uint_unchecked(k256::U256::from_be_slice(s.as_slice()));
    let r = x_coordinate(&big_r);

    let k256_sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

    let mut payload_hash = payload_hash.to_vec();
    payload_hash.reverse();

    let user_pk_k256: k256::elliptic_curve::PublicKey<Secp256k1> =
        k256::PublicKey::from_affine(expected_key).unwrap();

    let ecdsa_local_verify_result = verify(
        &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
        &payload_hash,
        &k256_sig,
    )
    .unwrap();

    // let s = hex::decode(s).unwrap();
    // let s = k256::Scalar::from_uint_unchecked(k256::U256::from_be_slice(s.as_slice()));
    // let r = x_coordinate(&big_r);

    // let signature: [u8; 64] = {
    //     let mut signature = [0u8; 64]; // TODO: is there a better way to get these bytes?
    //     signature[..32].copy_from_slice(&r.to_bytes());
    //     signature[32..].copy_from_slice(&s.to_bytes());
    //     signature
    // };

    // TODO switch to this more efficient implementation
    // Try with a recovery ID of 0
    // let recovered_key_1 = ecrecover(&payload_hash, &signature, 0, false);
    // If that doesn't work with a recovery ID of 1
    // let recovered_key_2 = ecrecover(&payload_hash, &signature, 1, false);

    // assert_eq!(
    //     Some(&expected_key.to_bytes()[..]),
    //     recovered_key_1.as_ref().map(|k| &k[..]),
    //     "{:?}",
    //     recovered_key_2.unwrap().to_vec()
    // );
}

fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    Scalar::from_uint_unchecked(U256::from_be_slice(bytes))
}

fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

fn verify(key: &VerifyingKey, msg: &[u8], sig: &k256::ecdsa::Signature) -> Result<(), ()> {
    let q = ProjectivePoint::<Secp256k1>::from(key.as_affine());
    let z = ecdsa::hazmat::bits2field::<Secp256k1>(msg).unwrap();

    // &k256::FieldBytes::from_slice(&k256::Scalar::from_bytes(msg).to_bytes()),
    verify_prehashed(&q, &z, sig)
}

fn verify_prehashed(
    q: &ProjectivePoint<Secp256k1>,
    z: &k256::FieldBytes,
    sig: &k256::ecdsa::Signature,
) -> Result<(), ()> {
    // let z: Scalar = Scalar::reduce_bytes(z);
    let z =
        <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(z);
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let reproduced = lincomb(&ProjectivePoint::<Secp256k1>::GENERATOR, &u1, q, &u2).to_affine();
    let x = reproduced.x();

    let reduced =
        <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &x,
        );

    if *r == reduced {
        Ok(())
    } else {
        // TODO stop this leaking data
        Err(())
    }
}

pub fn verifyy(big_r: &Affine, s: &Scalar, public_key: &Affine, msg_hash: &Scalar) -> bool {
    let r: Scalar = x_coordinate(big_r);

    if r.is_zero().into() || s.is_zero().into() {
        return false;
    }

    let s_inv = s.invert_vartime().unwrap();

    let reproduced = (ProjectivePoint::<Secp256k1>::generator() * (*msg_hash * s_inv))
        + (ProjectivePoint::<Secp256k1>::from(*public_key) * (r * s_inv));

    x_coordinate(&reproduced.into()) == r
}

fn lincomb(
    x: &ProjectivePoint<Secp256k1>,
    k: &Scalar,
    y: &ProjectivePoint<Secp256k1>,
    l: &Scalar,
) -> ProjectivePoint<Secp256k1> {
    (*x * k) + (*y * l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_account() {
        let alice_derived_address = "5b34b7ad1ce9f20a274cf0671fe17eba1b8db40e";

        let root_key = "02a7a6692959ccfbc7a72a5db030373c8662744603f153c91b6595528c41106a7b";
        let alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let path = "123456";

        assert_eq!(
            alice_derived_address,
            hex::encode(
                inner_derive_account(
                    hex::decode(root_key).unwrap(),
                    String::from(alice),
                    hex::decode(path).unwrap(),
                )
                .0
            )
        );
    }

    #[test]
    fn test_verify_signature_higher_level() {
        let payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path = "123456";
        let alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let root_key = "02a7a6692959ccfbc7a72a5db030373c8662744603f153c91b6595528c41106a7b";
        let (big_r, s) = (
            [
                2, 55, 87, 110, 208, 212, 83, 251, 171, 111, 26, 114, 249, 127, 76, 244, 142, 98,
                207, 243, 144, 175, 201, 107, 107, 158, 210, 111, 7, 64, 58, 136, 78,
            ],
            [
                36, 204, 199, 107, 125, 147, 110, 230, 35, 158, 209, 189, 118, 15, 150, 168, 168,
                250, 5, 155, 26, 194, 45, 143, 39, 223, 86, 236, 70, 102, 230, 22,
            ],
        );

        let root_public_key = AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&mut hex::decode(root_key).unwrap().as_slice()).unwrap(),
        )
        .unwrap();

        let epsilon = derive_epsilon(&String::from(alice), hex::decode(path).unwrap());

        //let alice_derived_key = derive_key_2_2(root_public_key, &epsilon);

        let alice_derived_key = derive_key_2_3(hex::decode(root_key).unwrap(), &epsilon);

        let big_r =
            AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(big_r).unwrap()).unwrap();

        let s = scalar_from_bytes(&s);

        let payload_hash = hex::decode(&payload).unwrap();

        let payload_scalar = scalar_from_bytes(&payload_hash);

        assert!(verifyy(&big_r, &s, &alice_derived_key, &payload_scalar));

        // Same path but with Bob

        let bob_epsilon = derive_epsilon(
            &String::from("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"),
            hex::decode(&path).unwrap().to_vec(),
        );

        let bob_derived_key = derive_key_2_2(root_public_key, &bob_epsilon);

        assert_eq!(
            verifyy(&big_r, &s, &bob_derived_key, &payload_scalar),
            false
        );

        // Wrong path

        let wrong_path_epsilon =
            derive_epsilon(&String::from(alice), hex::decode("123457").unwrap());

        let wrong_path_derived_key = derive_key_2_2(root_public_key, &wrong_path_epsilon);

        assert_eq!(
            verifyy(&big_r, &s, &wrong_path_derived_key, &payload_scalar),
            false
        );

        // Wrong payload

        let wrong_payload_hash =
            hex::decode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let wrong_payload_scalar = scalar_from_bytes(&wrong_payload_hash);

        assert_eq!(
            verifyy(&big_r, &s, &alice_derived_key, &wrong_payload_scalar),
            false
        );

        // Wrong big_r

        let wrong_big_r = AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes([
                3, 27, 108, 181, 86, 160, 129, 83, 72, 242, 228, 127, 23, 0, 194, 158, 105, 215,
                62, 162, 39, 253, 105, 213, 184, 234, 29, 62, 231, 140, 161, 207, 253,
            ])
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            verifyy(&wrong_big_r, &s, &alice_derived_key, &payload_scalar),
            false
        );

        // Wrong s

        let wrong_s = scalar_from_bytes(&[
            94, 90, 227, 92, 229, 151, 6, 1, 166, 11, 211, 160, 23, 103, 242, 229, 209, 41, 96, 22,
            155, 174, 215, 106, 16, 107, 88, 112, 4, 151, 153, 183,
        ]);

        assert_eq!(
            verifyy(&big_r, &wrong_s, &alice_derived_key, &payload_scalar),
            false
        );
    }

    #[test]
    fn test_verify_signature() {
        let (payload_hash, epsilon, root_key, big_r, s) = (
            [
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            ],
            [
                204, 179, 187, 156, 160, 73, 208, 169, 52, 245, 170, 243, 154, 64, 13, 8, 140, 78,
                222, 73, 194, 228, 121, 183, 223, 206, 208, 35, 254, 252, 14, 88,
            ],
            "02a7a6692959ccfbc7a72a5db030373c8662744603f153c91b6595528c41106a7b",
            [
                2, 55, 87, 110, 208, 212, 83, 251, 171, 111, 26, 114, 249, 127, 76, 244, 142, 98,
                207, 243, 144, 175, 201, 107, 107, 158, 210, 111, 7, 64, 58, 136, 78,
            ],
            [
                36, 204, 199, 107, 125, 147, 110, 230, 35, 158, 209, 189, 118, 15, 150, 168, 168,
                250, 5, 155, 26, 194, 45, 143, 39, 223, 86, 236, 70, 102, 230, 22,
            ],
        );

        let epsilon_2 = "ccb3bb9ca049d0a934f5aaf39a400d088c4ede49c2e479b7dfced023fefc0e58";

        assert_eq!(&epsilon, hex::decode(epsilon_2).unwrap().as_slice());

        let root_public_key = AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&mut hex::decode(root_key).unwrap().as_slice()).unwrap(),
        )
        .unwrap();

        let key = derive_key_2_2(root_public_key, &epsilon);

        let big_r =
            AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(big_r).unwrap()).unwrap();

        let s = scalar_from_bytes(&s);

        let payload_scalar = scalar_from_bytes(&payload_hash);

        assert!(verifyy(&big_r, &s, &key, &payload_scalar));
    }

    #[test]
    fn test_derive_key() {
        let root_public_key = [
            1, 212, 91, 86, 124, 226, 155, 141, 152, 35, 173, 104, 63, 123, 77, 166, 138, 244, 53,
            67, 175, 24, 203, 45, 178, 118, 50, 112, 245, 4, 241, 220, 239, 75, 233, 25, 119, 123,
            116, 206, 218, 48, 149, 172, 10, 148, 1, 160, 9, 169, 237, 9, 73, 100, 176, 33, 116,
            94, 194, 202, 195, 62, 179, 222, 50,
        ];
        let epsilon = [
            153, 65, 75, 154, 139, 193, 79, 187, 144, 250, 176, 243, 43, 73, 237, 200, 161, 189,
            29, 152, 16, 249, 238, 165, 1, 196, 137, 125, 85, 18, 68, 47,
        ];
        derive_key_2(root_public_key.to_vec(), &epsilon);
    }
}
