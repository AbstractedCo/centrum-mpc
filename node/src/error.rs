#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("Local public key doesn't match on-chain public key")]
    WrongPublicKey,
    #[error("Local threshold doesn't match on-chain threshold")]
    WrongThreshold,
    #[error("Local participant set doesn't match on-chain participant set")]
    WrongParticipantSet,
    #[error("This participant has been removed from the set")]
    RemovedFromSet,
    #[error("Cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] cait_sith::protocol::InitializationError),
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),

    #[error("Other error: {0}")]
    Other(String),
}

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
}
