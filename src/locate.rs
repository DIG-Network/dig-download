//! [`ProviderLocator`] — "which peers hold this content?" — and the real dig-dht-backed locator.
//!
//! Step 1 of a multi-source download (L7 §9): before fetching anything, find the candidate holders.
//! The trait abstracts discovery so the scheduler is tested with a mock that returns a controllable
//! provider set (see [`crate::testkit`]); the real [`DhtProviderLocator`] delegates to
//! [`dig_dht::DhtService::find_providers`]. The orchestrator re-runs the locator when a still-needed
//! range has exhausted its known holders, to discover more (L7 §4c "on content-want").

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::{ContentId, DhtService, ProviderRecord};

use crate::error::DownloadError;

/// Locate the providers (holders) of a content id. The one discovery capability the orchestrator
/// needs, abstracted for testability.
#[async_trait]
pub trait ProviderLocator: Send + Sync {
    /// Return the providers currently known to hold `content` (possibly empty). A locate failure is a
    /// [`DownloadError`]; an empty result is `Ok(vec![])` (no holders found, not an error).
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError>;
}

/// The real [`ProviderLocator`]: an iterative Kademlia `find_providers` over the DHT. dig-node
/// constructs the [`DhtService`] (with its dig-nat transport + bootstrap peers) and wraps it here.
#[derive(Clone)]
pub struct DhtProviderLocator {
    dht: Arc<DhtService>,
}

impl DhtProviderLocator {
    /// Wrap a shared [`DhtService`] as a provider locator.
    pub fn new(dht: Arc<DhtService>) -> Self {
        DhtProviderLocator { dht }
    }

    /// The wrapped DHT service (for maintenance / introspection by the caller).
    pub fn service(&self) -> &Arc<DhtService> {
        &self.dht
    }
}

#[async_trait]
impl ProviderLocator for DhtProviderLocator {
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        self.dht
            .find_providers(content)
            .await
            .map_err(|e| DownloadError::transport("dht", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dig_dht::transport::DhtTransport;
    use dig_dht::{
        CandidateAddr, Contact, DhtConfig, DhtError, DhtRequest, DhtResponse, Key, PeerId,
        ProviderRecord,
    };

    /// A canned DHT transport that answers `find_providers` with a fixed provider set — lets us build
    /// a REAL `DhtService` and prove `DhtProviderLocator` returns what the DHT found.
    struct CannedTransport {
        providers: Vec<ProviderRecord>,
    }

    #[async_trait]
    impl DhtTransport for CannedTransport {
        async fn rpc(
            &self,
            _from: &Contact,
            _peer: &Contact,
            request: &DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            match request {
                DhtRequest::FindProviders { .. } => Ok(DhtResponse::Providers {
                    providers: self.providers.clone(),
                    closer: vec![],
                }),
                DhtRequest::Ping { nonce } => Ok(DhtResponse::Pong { nonce: *nonce }),
                _ => Ok(DhtResponse::Nodes { nodes: vec![] }),
            }
        }
    }

    #[tokio::test]
    async fn dht_locator_returns_found_providers() {
        let content = ContentId::resource([1; 32], [2; 32], [3; 32]);
        let rec = ProviderRecord::new(
            &content.to_key(),
            &PeerId::from_bytes([7; 32]),
            vec![CandidateAddr::direct("203.0.113.7", 9444)],
            u64::MAX,
        );
        let transport = Arc::new(CannedTransport {
            providers: vec![rec.clone()],
        });
        // A real DhtService with one bootstrap peer so it has someone to "ask".
        let dht = DhtService::new(
            PeerId::from_bytes([0; 32]),
            vec![CandidateAddr::direct("127.0.0.1", 1)],
            DhtConfig::default(),
            transport,
        );
        // Seed the routing table so find_providers has a seed to query.
        dht.bootstrap(&[dig_dht::BootstrapPeer::direct(
            PeerId::from_bytes([5; 32]),
            "127.0.0.1",
            2,
        )])
        .await
        .unwrap();

        let locator = DhtProviderLocator::new(Arc::new(dht));
        let got = locator.find_providers(&content).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].provider_peer_id, rec.provider_peer_id);
        assert!(locator.service().local_id() == &PeerId::from_bytes([0; 32]));
        // Silence unused import warnings for Key in some configurations.
        let _ = Key::from_bytes([0; 32]);
    }
}
