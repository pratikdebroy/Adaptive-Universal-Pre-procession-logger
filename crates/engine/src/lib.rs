pub mod bdpt;
pub mod merkle;
pub mod models;
pub mod ocsf;
pub mod pipeline;
pub mod preprocessor;
pub mod quarantine;
pub mod registry;
pub mod trust_gate;

// Re-exports for convenient use across crates
pub use bdpt::{BidirectionalPatternTree, BptLeafNode};
pub use merkle::{MerkleProof, MerkleTree};
pub use models::*;
pub use ocsf::OcsfNormalizer;
pub use pipeline::{AegisPipeline, AiDiscoveryProvider};
pub use preprocessor::StructuralPreprocessor;
pub use quarantine::QuarantineManager;
pub use registry::ParserRegistry;
pub use trust_gate::TrustGate;
