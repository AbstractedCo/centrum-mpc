use crate::{
    error::StorageError,
    state::PersistentNodeData,
    triple::{Triple, TripleId},
    types::{PublicKey, SecretKeyShare},
};
use async_trait::async_trait;
use codec::{Decode, Encode};
use sc_client_db::offchain::LocalStorage;
use serde::{Deserialize, Serialize};
use sp_core::offchain::OffchainStorage;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    sync::Arc,
};
use tokio::sync::RwLock;

const NODE_DATA_PREFIX: &[u8] = b"tss-node-data";
const TRIPLES_PREFIX: &[u8] = b"tss-triples";
const TRIPLES_MINE_PREFIX: &[u8] = b"tss-triples-mine";

#[async_trait]
pub trait NodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<(), StorageError>;
    async fn load(&self) -> Result<Option<PersistentNodeData>, StorageError>;
}

#[derive(Default)]
pub struct MemoryNodeStorage {
    node_data: Option<PersistentNodeData>,
}

#[async_trait]
impl NodeStorage for MemoryNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<(), StorageError> {
        tracing::info!("storing NodeData using memory");
        self.node_data = Some(data.clone());
        Ok(())
    }

    async fn load(&self) -> Result<Option<PersistentNodeData>, StorageError> {
        tracing::info!("loading NodeData using memory");
        Ok(self.node_data.clone())
    }
}

impl MemoryNodeStorage {
    pub fn from_file(path: String) -> Self {
        Self {
            node_data: Some(serde_json::from_slice(fs::read(path).unwrap().as_slice()).unwrap()),
        }
    }
}

pub struct OffchainNodeStorage {
    handle: LocalStorage,
}

impl OffchainNodeStorage {
    pub fn new(handle: LocalStorage) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl NodeStorage for OffchainNodeStorage {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<(), StorageError> {
        tracing::info!("storing NodeData using offchain storage");

        self.handle
            .set(NODE_DATA_PREFIX, b" ", &serde_json::to_vec(data)?);

        Ok(())
    }

    async fn load(&self) -> Result<Option<PersistentNodeData>, StorageError> {
        tracing::info!("loading NodeData using offchain storage");

        let maybe_data = self
            .handle
            .get(NODE_DATA_PREFIX, b" ")
            .map(|data| serde_json::from_slice(data.as_slice()).unwrap());

        Ok(maybe_data)
    }
}

pub struct LocalStoragee;

#[async_trait]
impl NodeStorage for LocalStoragee {
    async fn store(&mut self, data: &PersistentNodeData) -> Result<(), StorageError> {
        fs::write("./node_data", &serde_json::to_vec(data)?).map_err(|e| StorageError::IoError(e))
    }

    async fn load(&self) -> Result<Option<PersistentNodeData>, StorageError> {
        match fs::read("./node_data") {
            Ok(data) => Ok(Some(
                serde_json::from_slice(data.as_slice()).map_err(|e| StorageError::SerdeError(e))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::IoError(e)),
        }
    }
}

pub type NodeStorageBox = Box<dyn NodeStorage + Send + Sync>;

pub struct TripleKey {
    pub account_id: String,
    pub triple_id: TripleId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TripleData<AccountId> {
    pub account_id: AccountId,
    pub triple: Triple,
    pub mine: bool,
}

#[async_trait]
pub trait TripleNodeStorage<AccountId> {
    async fn insert(&mut self, triple: Triple, mine: bool) -> Result<(), String>;
    async fn delete(&mut self, id: TripleId) -> Result<(), String>;
    async fn load(&self) -> Result<Vec<TripleData<AccountId>>, String>;
    fn account_id(&self) -> &AccountId;
}

#[derive(Clone)]
pub struct MemoryTripleNodeStorage<AccountId> {
    triples: HashMap<TripleId, Triple>,
    mine: HashSet<TripleId>,
    account_id: AccountId,
}

impl<AccountId> MemoryTripleNodeStorage<AccountId> {
    pub fn new(account_id: AccountId) -> Self {
        Self {
            triples: Default::default(),
            mine: Default::default(),
            account_id,
        }
    }
}

#[async_trait]
impl<AccountId: Send + Sync + Clone> TripleNodeStorage<AccountId>
    for MemoryTripleNodeStorage<AccountId>
{
    async fn insert(&mut self, triple: Triple, mine: bool) -> Result<(), String> {
        if mine {
            self.mine.insert(triple.id);
        }
        self.triples.insert(triple.id, triple);
        Ok(())
    }

    async fn delete(&mut self, id: TripleId) -> Result<(), String> {
        self.triples.remove(&id);
        self.mine.remove(&id);
        Ok(())
    }

    async fn load(&self) -> Result<Vec<TripleData<AccountId>>, String> {
        let mut res: Vec<TripleData<AccountId>> = vec![];
        for (triple_id, triple) in self.triples.clone() {
            let mine = self.mine.contains(&triple_id);
            res.push(TripleData {
                account_id: self.account_id().clone(),
                triple,
                mine,
            });
        }
        Ok(res)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[derive(Clone)]
pub struct OffchainTripleStorage<AccountId> {
    handle: LocalStorage,
    account_id: AccountId,
}

impl<AccountId> OffchainTripleStorage<AccountId> {
    pub fn new(handle: LocalStorage, account_id: AccountId) -> Self {
        Self { handle, account_id }
    }
}

#[async_trait]
impl<'a, AccountId: Clone + Ord + Serialize + serde::de::DeserializeOwned + Send + Sync>
    TripleNodeStorage<AccountId> for OffchainTripleStorage<AccountId>
{
    async fn insert(&mut self, triple: Triple, mine: bool) -> Result<(), String> {
        let mut triples_set: BTreeSet<TripleData<AccountId>> = self
            .handle
            .get(TRIPLES_PREFIX, b" ")
            .map(|data| bincode::deserialize(&data).unwrap())
            .unwrap_or_default();

        triples_set.insert(TripleData {
            account_id: self.account_id().clone(),
            triple,
            mine,
        });

        self.handle.set(
            TRIPLES_PREFIX,
            b" ",
            &bincode::serialize(&triples_set).unwrap(),
        );

        Ok(())
    }

    async fn delete(&mut self, id: TripleId) -> Result<(), String> {
        let mut maybe_triples_set: Option<BTreeSet<TripleData<AccountId>>> = self
            .handle
            .get(TRIPLES_PREFIX, b" ")
            .map(|data| bincode::deserialize(&data).unwrap());

        if let Some(mut triples_set) = maybe_triples_set {
            triples_set.retain(|e| e.triple.id != id);

            self.handle.set(
                TRIPLES_PREFIX,
                b" ",
                &bincode::serialize(&triples_set).unwrap(),
            );
        }

        Ok(())
    }

    async fn load(&self) -> Result<Vec<TripleData<AccountId>>, String> {
        let triples_set: BTreeSet<TripleData<AccountId>> = self
            .handle
            .get(TRIPLES_PREFIX, b" ")
            .map(|data| bincode::deserialize(&data).unwrap())
            .unwrap_or_default();

        Ok(triples_set.into_iter().collect())
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[derive(Clone)]
struct TripleLocalStorage<AccountId> {
    account_id: AccountId,
}

impl<AccountId: Clone> TripleLocalStorage<AccountId> {
    fn new(account_id: &AccountId) -> Self {
        Self {
            account_id: account_id.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TripleLocalData<AccountId> {
    triples: Vec<(TripleId, TripleData<AccountId>)>,
    mine: Vec<TripleId>,
}

#[async_trait]
impl<AccountId: Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + PartialEq>
    TripleNodeStorage<AccountId> for TripleLocalStorage<AccountId>
{
    async fn insert(&mut self, triple: Triple, mine: bool) -> Result<(), String> {
        let mut data: TripleLocalData<AccountId> =
            bincode::deserialize(&fs::read("./triple_storage").unwrap()).unwrap();

        if mine {
            data.mine = {
                let mut hs: HashSet<TripleId> = HashSet::from_iter(data.mine.into_iter());
                hs.insert(triple.id);
                hs
            }
            .into_iter()
            .collect::<Vec<TripleId>>();
        }

        data.triples = {
            let mut hm: HashMap<TripleId, TripleData<AccountId>> =
                HashMap::from_iter(data.triples.into_iter());
            hm.insert(
                triple.id,
                TripleData {
                    account_id: self.account_id().clone(),
                    triple,
                    mine,
                },
            );
            hm
        }
        .into_iter()
        .collect::<Vec<(TripleId, TripleData<AccountId>)>>();

        fs::write("./triple_storage", bincode::serialize(&data).unwrap()).unwrap();

        Ok(())
    }

    async fn delete(&mut self, id: TripleId) -> Result<(), String> {
        let mut data: TripleLocalData<AccountId> =
            bincode::deserialize(&fs::read("./triple_storage").unwrap().as_slice()).unwrap();

        data.mine = {
            let mut hs: HashSet<TripleId> = HashSet::from_iter(data.mine.into_iter());
            hs.remove(&id);
            hs
        }
        .into_iter()
        .collect::<Vec<TripleId>>();

        data.triples = {
            let mut hm: HashMap<TripleId, TripleData<AccountId>> =
                HashMap::from_iter(data.triples.into_iter());
            hm.remove(&id);
            hm
        }
        .into_iter()
        .collect::<Vec<(TripleId, TripleData<AccountId>)>>();

        fs::write("./triple_storage", bincode::serialize(&data).unwrap()).unwrap();

        Ok(())
    }

    async fn load(&self) -> Result<Vec<TripleData<AccountId>>, String> {
        let data: TripleLocalData<AccountId> =
            bincode::deserialize(&fs::read("./triple_storage").unwrap().as_slice()).unwrap();

        let triples = data
            .triples
            .into_iter()
            .map(|(_, d)| d)
            .filter(|triple_data| triple_data.account_id == self.account_id().clone())
            .collect();

        Ok(triples)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

pub type TripleNodeStorageBox<AccountId> = Box<dyn TripleNodeStorage<AccountId> + Send + Sync>;

pub struct TripleStorage<AccountId> {
    pub storage: TripleNodeStorageBox<AccountId>,
}

pub type LockTripleNodeStorageBox<AccountId> = Arc<RwLock<TripleNodeStorageBox<AccountId>>>;
