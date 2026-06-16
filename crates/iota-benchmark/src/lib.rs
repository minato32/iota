// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod bank;
pub mod benchmark_setup;
pub mod drivers;
pub mod embedded_reconfig_observer;
pub mod fullnode_reconfig_observer;
pub mod in_memory_wallet;
pub mod options;
pub mod system_state_observer;
pub mod td_fullnode_reconfig_observer;
pub mod util;
pub mod workloads;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::bail;
use async_trait::async_trait;
use embedded_reconfig_observer::EmbeddedReconfigObserver;
use fullnode_reconfig_observer::FullNodeReconfigObserver;
use futures::TryStreamExt;
use iota_config::genesis::Genesis;
use iota_core::{
    authority_aggregator::{AuthorityAggregator, AuthorityAggregatorBuilder},
    authority_client::NetworkAuthorityClient,
    quorum_driver::{
        QuorumDriver, QuorumDriverHandler, QuorumDriverHandlerBuilder, QuorumDriverMetrics,
        reconfig_observer::ReconfigObserver,
    },
    transaction_driver::{
        SubmitTransactionOptions, TransactionDriver, TransactionDriverMetrics,
        reconfig_observer::{
            DummyReconfigObserver as TdDummyReconfigObserver,
            ReconfigObserver as TdReconfigObserver,
        },
    },
    validator_client_monitor::ValidatorClientMetrics,
};
use iota_json_rpc_types::{
    IotaObjectDataOptions, IotaObjectResponseQuery, IotaTransactionBlockEffects,
    IotaTransactionBlockEffectsAPI, IotaTransactionBlockResponseOptions,
};
use iota_sdk::{IotaClient, IotaClientBuilder, PagedFn};
use iota_types::{
    base_types::{
        AuthorityName, ConciseableName, IotaAddress, ObjectID, ObjectRef, SequenceNumber,
    },
    committee::{Committee, EpochId},
    crypto::AuthorityStrongQuorumSignInfo,
    effects::{
        CertifiedTransactionEffects, TransactionEffects, TransactionEffectsAPI, TransactionEvents,
    },
    execution_status::ExecutionFailureStatus,
    gas::GasCostSummary,
    gas_coin::GasCoin,
    iota_system_state::{IotaSystemStateTrait, iota_system_state_summary::IotaSystemStateSummary},
    object::{Object, Owner},
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    quorum_driver_types::{QuorumDriverError, QuorumDriverResponse},
    transaction::{Argument, CallArg, SharedObjectRef, Transaction},
};
use prometheus::Registry;
use rand::Rng;
use td_fullnode_reconfig_observer::TdFullNodeReconfigObserver;
use tokio::time::sleep;
use tracing::{error, info, warn};

#[derive(Debug)]
/// A wrapper on execution results to accommodate different types of
/// responses from LocalValidatorAggregatorProxy and FullNodeProxy
pub enum ExecutionEffects {
    CertifiedTransactionEffects(CertifiedTransactionEffects, TransactionEvents),
    IotaTransactionBlockEffects(IotaTransactionBlockEffects),
    // TransactionDriver finalizes with raw `TransactionEffects` (a quorum of
    // signed effects digests, not a single cert), so the direct-to-validator
    // white-flag path returns the effects directly rather than a cert.
    FinalizedTransactionEffects(TransactionEffects, TransactionEvents),
}

impl ExecutionEffects {
    pub fn mutated(&self) -> Vec<(ObjectRef, Owner)> {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                certified_effects.data().mutated().to_vec()
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => iota_tx_effects
                .mutated()
                .iter()
                .map(|refe| (refe.reference, refe.owner))
                .collect(),
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => {
                effects.mutated().to_vec()
            }
        }
    }

    pub fn created(&self) -> Vec<(ObjectRef, Owner)> {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                certified_effects.data().created()
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => iota_tx_effects
                .created()
                .iter()
                .map(|refe| (refe.reference, refe.owner))
                .collect(),
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => effects.created(),
        }
    }

    pub fn deleted(&self) -> Vec<ObjectRef> {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                certified_effects.data().deleted().to_vec()
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => {
                iota_tx_effects.deleted().to_vec()
            }
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => {
                effects.deleted().to_vec()
            }
        }
    }

    pub fn quorum_sig(&self) -> Option<&AuthorityStrongQuorumSignInfo> {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                Some(certified_effects.auth_sig())
            }
            ExecutionEffects::IotaTransactionBlockEffects(_) => None,
            // TransactionDriver finality is a quorum of signed effects digests,
            // not a single aggregated cert, so there is no quorum sig to expose.
            ExecutionEffects::FinalizedTransactionEffects(..) => None,
        }
    }

    pub fn gas_object(&self) -> (ObjectRef, Owner) {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                certified_effects.data().gas_object()
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => {
                let refe = &iota_tx_effects.gas_object();
                (refe.reference, refe.owner)
            }
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => effects.gas_object(),
        }
    }

    pub fn sender(&self) -> IotaAddress {
        *self.gas_object().1.as_address()
    }

    pub fn is_ok(&self) -> bool {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                certified_effects.data().status().is_success()
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => {
                iota_tx_effects.status().is_ok()
            }
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => {
                effects.status().is_success()
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(effects, ..) => {
                Self::status_is_cancelled(effects.data().status())
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => {
                let status = format!("{}", iota_tx_effects.status());
                status.contains("ExecutionCancelledDueToSharedObjectCongestion")
            }
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => {
                Self::status_is_cancelled(effects.status())
            }
        }
    }

    fn status_is_cancelled(status: &iota_types::execution_status::ExecutionStatus) -> bool {
        match status {
            iota_types::execution_status::ExecutionStatus::Success => false,
            iota_types::execution_status::ExecutionStatus::Failure {
                error:
                    ExecutionFailureStatus::ExecutionCancelledDueToSharedObjectCongestion { .. }
                    | ExecutionFailureStatus::ExecutionCancelledDueToSharedObjectCongestionV2 { .. },
                ..
            } => true,
            _ => false,
        }
    }

    pub fn status(&self) -> String {
        match self {
            ExecutionEffects::CertifiedTransactionEffects(certified_effects, ..) => {
                format!("{:#?}", certified_effects.data().status())
            }
            ExecutionEffects::IotaTransactionBlockEffects(iota_tx_effects) => {
                format!("{:#?}", iota_tx_effects.status())
            }
            ExecutionEffects::FinalizedTransactionEffects(effects, ..) => {
                format!("{:#?}", effects.status())
            }
        }
    }

    pub fn gas_cost_summary(&self) -> GasCostSummary {
        match self {
            crate::ExecutionEffects::CertifiedTransactionEffects(a, _) => {
                a.data().gas_cost_summary().clone()
            }
            crate::ExecutionEffects::IotaTransactionBlockEffects(b) => {
                std::convert::Into::<GasCostSummary>::into(b.gas_cost_summary().clone())
            }
            crate::ExecutionEffects::FinalizedTransactionEffects(effects, _) => {
                effects.gas_cost_summary().clone()
            }
        }
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_cost_summary().gas_used()
    }

    pub fn net_gas_used(&self) -> i64 {
        self.gas_cost_summary().net_gas_usage()
    }

    pub fn print_gas_summary(&self) {
        let gas_object = self.gas_object();
        let sender = self.sender();
        let status = self.status();
        let gas_cost_summary = self.gas_cost_summary();
        let gas_used = self.gas_used();
        let net_gas_used = self.net_gas_used();

        info!(
            "Summary:\n\
             Gas Object: {gas_object:?}\n\
             Sender: {sender:?}\n\
             status: {status}\n\
             Gas Cost Summary: {gas_cost_summary:#?}\n\
             Gas Used: {gas_used}\n\
             Net Gas Used: {net_gas_used}"
        );
    }
}

#[async_trait]
pub trait ValidatorProxy {
    async fn get_object(&self, object_id: ObjectID) -> Result<Object, anyhow::Error>;

    async fn get_owned_objects(
        &self,
        account_address: IotaAddress,
    ) -> Result<Vec<(u64, Object)>, anyhow::Error>;

    async fn get_latest_system_state_object(&self)
    -> Result<IotaSystemStateSummary, anyhow::Error>;

    async fn execute_transaction_block(&self, tx: Transaction) -> anyhow::Result<ExecutionEffects>;

    fn clone_committee(&self) -> Arc<Committee>;

    fn get_current_epoch(&self) -> EpochId;

    fn clone_new(&self) -> Box<dyn ValidatorProxy + Send + Sync>;

    /// This crate benchmarks committee performance, such as
    /// transaction execution (`execute_bench_transaction`).
    /// Therefore, we return the committee members here.
    async fn get_committee(&self) -> Result<Vec<IotaAddress>, anyhow::Error>;
}

// The driver the direct-to-validator proxy uses to submit transactions. Picked
// to match the fullnode's TransactionOrchestrator: white-flag flow on =>
// TransactionDriver (the attested, direct-to-consensus flow), off =>
// QuorumDriver (the legacy flow).
enum LocalDriver {
    Qd {
        // Stress client does not verify individual validator signatures since this is very
        // expensive
        _qd_handler: QuorumDriverHandler<NetworkAuthorityClient>,
        qd: Arc<QuorumDriver<NetworkAuthorityClient>>,
    },
    Td(Arc<TransactionDriver<NetworkAuthorityClient>>),
}

// TODO: Eventually remove this proxy because we shouldn't rely on validators to
// read objects.
pub struct LocalValidatorAggregatorProxy {
    driver: LocalDriver,
    committee: Committee,
    clients: BTreeMap<AuthorityName, NetworkAuthorityClient>,
    // Display names (concise pubkeys) of the validators submission may target.
    // Empty => any validator. Only honored on the TransactionDriver path; the
    // QuorumDriver path ignores it. Pins attestation to a subset (validator-1..N).
    allowed_validators: Vec<String>,
}

impl LocalValidatorAggregatorProxy {
    pub async fn from_genesis(
        genesis: &Genesis,
        registry: &Registry,
        reconfig_fullnode_rpc_url: Option<&str>,
        num_target_validators: Option<u64>,
    ) -> Self {
        let (aggregator, clients) = AuthorityAggregatorBuilder::from_genesis(genesis)
            .with_registry(registry)
            .build_network_clients();
        let committee = genesis.committee().unwrap();

        // Pin submission (and thus attestation) to the first N validators
        // (validator-1..validator-N). Empty => any validator. Only the
        // TransactionDriver path honors this; QuorumDriver ignores it.
        let allowed_validators = pinned_target_validators(genesis, num_target_validators);

        // Decide which driver to use the same way the fullnode's
        // TransactionOrchestrator does: white-flag flow on => TransactionDriver,
        // off => QuorumDriver. The flag is normally set via a runtime
        // protocol-config override on the nodes, so the genesis blob (which only
        // carries the version default) is NOT a reliable source — we read the
        // EFFECTIVE value from a fullnode's protocol config over RPC. When no
        // fullnode URL is available (e.g. the embedded local-network path) we
        // fall back to QuorumDriver, preserving the previous behavior.
        let use_transaction_driver = match reconfig_fullnode_rpc_url {
            Some(url) => detect_white_flag_flow(url).await,
            None => {
                info!(
                    "No fullnode RPC URL available; defaulting to QuorumDriver \
                     (white-flag-flow detection skipped)"
                );
                false
            }
        };

        Self::new_impl(
            aggregator,
            registry,
            reconfig_fullnode_rpc_url,
            clients,
            committee,
            use_transaction_driver,
            allowed_validators,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_impl(
        aggregator: AuthorityAggregator<NetworkAuthorityClient>,
        registry: &Registry,
        reconfig_fullnode_rpc_url: Option<&str>,
        clients: BTreeMap<AuthorityName, NetworkAuthorityClient>,
        committee: Committee,
        use_transaction_driver: bool,
        allowed_validators: Vec<String>,
    ) -> Self {
        if use_transaction_driver {
            // ----- TransactionDriver (white-flag direct-to-consensus flow) -----
            info!("Using TransactionDriver for direct-to-validator submission");
            let td_metrics = Arc::new(TransactionDriverMetrics::new(registry));
            let client_metrics = Arc::new(ValidatorClientMetrics::new(registry));
            let aggregator = Arc::new(aggregator);

            // TD reconfig observer: poll the fullnode RPC (the TransactionDriver
            // analog of the QuorumDriver FullNodeReconfigObserver). Falls back to
            // a no-op observer when no fullnode URL is available (committee then
            // stays fixed for the run).
            let td_reconfig_observer: Arc<
                dyn TdReconfigObserver<NetworkAuthorityClient> + Sync + Send,
            > = if let Some(url) = reconfig_fullnode_rpc_url {
                info!("Using TdFullNodeReconfigObserver: {:?}", url);
                Arc::new(
                    TdFullNodeReconfigObserver::new(
                        url,
                        aggregator.clone_committee_store(),
                        aggregator.safe_client_metrics_base.clone(),
                        aggregator.metrics.clone(),
                    )
                    .await,
                )
            } else {
                info!("Using TD DummyReconfigObserver (committee fixed for the run)");
                Arc::new(TdDummyReconfigObserver)
            };

            let td = TransactionDriver::new(
                aggregator,
                td_reconfig_observer,
                td_metrics,
                None, // node_config: use default ValidatorClientMonitor config
                client_metrics,
            );
            Self {
                driver: LocalDriver::Td(td),
                clients,
                committee,
                allowed_validators,
            }
        } else {
            // ----- QuorumDriver (legacy flow) -----
            info!("Using QuorumDriver for direct-to-validator submission");
            let quorum_driver_metrics = Arc::new(QuorumDriverMetrics::new(registry));
            let (aggregator, reconfig_observer): (
                Arc<_>,
                Arc<dyn ReconfigObserver<NetworkAuthorityClient> + Sync + Send>,
            ) = if let Some(reconfig_fullnode_rpc_url) = reconfig_fullnode_rpc_url {
                info!(
                    "Using FullNodeReconfigObserver: {:?}",
                    reconfig_fullnode_rpc_url
                );
                let committee_store = aggregator.clone_committee_store();
                let reconfig_observer = Arc::new(
                    FullNodeReconfigObserver::new(
                        reconfig_fullnode_rpc_url,
                        committee_store,
                        aggregator.safe_client_metrics_base.clone(),
                        aggregator.metrics.clone(),
                    )
                    .await,
                );
                (Arc::new(aggregator), reconfig_observer)
            } else {
                info!("Using EmbeddedReconfigObserver");
                let reconfig_observer = Arc::new(EmbeddedReconfigObserver::new());
                // Get the latest committee from config observer
                let aggregator = reconfig_observer
                    .get_committee(Arc::new(aggregator))
                    .await
                    .expect("Failed to get latest committee");
                (aggregator, reconfig_observer)
            };
            let qd_handler_builder =
                QuorumDriverHandlerBuilder::new(aggregator, quorum_driver_metrics.clone())
                    .with_reconfig_observer(reconfig_observer.clone());
            let qd_handler = qd_handler_builder.start();
            let qd = qd_handler.clone_quorum_driver();
            Self {
                driver: LocalDriver::Qd {
                    _qd_handler: qd_handler,
                    qd,
                },
                clients,
                committee,
                allowed_validators,
            }
        }
    }

    // The authority aggregator backing whichever driver is in use (each driver
    // owns an epoch-updatable aggregator).
    fn auth_agg(&self) -> Arc<AuthorityAggregator<NetworkAuthorityClient>> {
        match &self.driver {
            LocalDriver::Qd { qd, .. } => qd.authority_aggregator().load_full(),
            LocalDriver::Td(td) => td.authority_aggregator().load_full(),
        }
    }
}

// Read the EFFECTIVE `enable_white_flag_flow` feature flag from a fullnode's
// protocol config over RPC. This reflects runtime protocol-config overrides
// (how the flag is toggled in the stress setup), which the genesis blob does
// not.
async fn detect_white_flag_flow(fullnode_rpc_url: &str) -> bool {
    let client = IotaClientBuilder::default()
        .build(fullnode_rpc_url)
        .await
        .unwrap_or_else(|e| {
            panic!("Can't create IotaClient with rpc url {fullnode_rpc_url}: {e:?}")
        });
    let resp = client
        .read_api()
        .get_protocol_config(None)
        .await
        .expect("Failed to fetch protocol config from fullnode");
    let enabled = resp
        .feature_flags
        .get("enable_white_flag_flow")
        .copied()
        .unwrap_or(false);
    info!(
        "Detected enable_white_flag_flow={enabled} from fullnode {fullnode_rpc_url}; \
         direct submission will use {}",
        if enabled {
            "TransactionDriver"
        } else {
            "QuorumDriver"
        }
    );
    enabled
}

// Build the `allowed_validators` list (concise display names, matching what
// `RequestRetrier` compares against) that pins submission to the first
// `num_target_validators` validators, ordered validator-1..validator-N by their
// genesis hostname. Returns empty (=> any validator, current behavior) when the
// count is unset, 0, or >= the committee size.
fn pinned_target_validators(genesis: &Genesis, num_target_validators: Option<u64>) -> Vec<String> {
    let k = match num_target_validators {
        Some(k) if k > 0 => k as usize,
        _ => return vec![],
    };
    let committee_with_network = genesis.committee_with_network();
    // (hostname, authority) for each validator; hostname is `validator-N` from
    // the genesis network address (falls back to the concise key if absent).
    let mut by_host: Vec<(String, AuthorityName)> = committee_with_network
        .validators()
        .iter()
        .map(|(name, (_stake, meta))| {
            let host = meta
                .network_address
                .hostname()
                .unwrap_or_else(|| name.concise().to_string());
            (host, *name)
        })
        .collect();
    if k >= by_host.len() {
        return vec![]; // pin to all == no restriction
    }
    // Order validator-1, validator-2, ... validator-10 (numeric suffix, not
    // lexicographic) so "first k" is validator-1..validator-k.
    by_host.sort_by(|a, b| host_sort_key(&a.0).cmp(&host_sort_key(&b.0)));
    by_host.truncate(k);
    for (host, name) in &by_host {
        info!(
            "Pinning submission/attestation to {host} ({})",
            name.concise()
        );
    }
    by_host
        .into_iter()
        .map(|(_host, name)| name.concise().to_string())
        .collect()
}

// Sort key for a `validator-<n>` hostname: (numeric suffix, full string) so
// validator-2 sorts before validator-10. Non-numeric suffixes sort last.
fn host_sort_key(host: &str) -> (u64, String) {
    let num = host
        .rsplit('-')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    (num, host.to_string())
}

#[async_trait]
impl ValidatorProxy for LocalValidatorAggregatorProxy {
    async fn get_object(&self, object_id: ObjectID) -> Result<Object, anyhow::Error> {
        let auth_agg = self.auth_agg();
        Ok(auth_agg
            .get_latest_object_version_for_testing(object_id)
            .await?)
    }

    async fn get_owned_objects(
        &self,
        _account_address: IotaAddress,
    ) -> Result<Vec<(u64, Object)>, anyhow::Error> {
        unimplemented!("Not available for local proxy");
    }

    async fn get_latest_system_state_object(
        &self,
    ) -> Result<IotaSystemStateSummary, anyhow::Error> {
        let auth_agg = self.auth_agg();
        Ok(auth_agg
            .get_latest_system_state_object_for_testing()
            .await?
            .into_iota_system_state_summary())
    }

    async fn execute_transaction_block(&self, tx: Transaction) -> anyhow::Result<ExecutionEffects> {
        let tx_digest = *tx.digest();
        let mut retry_cnt = 0;
        while retry_cnt < 3 {
            match &self.driver {
                LocalDriver::Qd { qd, .. } => {
                    let ticket = qd
                        .submit_transaction(
                            iota_types::quorum_driver_types::ExecuteTransactionRequestV1 {
                                transaction: tx.clone(),
                                include_events: true,
                                include_input_objects: false,
                                include_output_objects: false,
                                include_auxiliary_data: false,
                            },
                        )
                        .await?;
                    // The ticket only times out when QuorumDriver exceeds the retry times
                    match ticket.await {
                        Ok(resp) => {
                            let QuorumDriverResponse {
                                effects_cert,
                                events,
                                ..
                            } = resp;
                            return Ok(ExecutionEffects::CertifiedTransactionEffects(
                                effects_cert.into(),
                                events.unwrap_or_default(),
                            ));
                        }
                        Err(QuorumDriverError::NonRecoverableTransactionError { errors }) => {
                            bail!(QuorumDriverError::NonRecoverableTransactionError { errors });
                        }
                        Err(err) => {
                            let delay =
                                Duration::from_millis(rand::thread_rng().gen_range(100..1000));
                            warn!(
                                ?tx_digest,
                                retry_cnt,
                                "Transaction failed with err: {:?}. Sleeping for {:?} ...",
                                err,
                                delay,
                            );
                            retry_cnt += 1;
                            sleep(delay).await;
                        }
                    }
                }
                LocalDriver::Td(td) => {
                    // TransactionDriver drives to finality internally; a returned
                    // error is a finality/submission failure (execution failures
                    // come back as Ok with a failure status in the effects).
                    match td
                        .drive_transaction(
                            Some(tx.clone()),
                            SubmitTransactionOptions {
                                allowed_validators: self.allowed_validators.clone(),
                                ..Default::default()
                            },
                            Some(Duration::from_secs(60)),
                        )
                        .await
                    {
                        Ok(resp) => {
                            return Ok(ExecutionEffects::FinalizedTransactionEffects(
                                resp.effects.effects,
                                resp.events.unwrap_or_default(),
                            ));
                        }
                        Err(err) => {
                            let delay =
                                Duration::from_millis(rand::thread_rng().gen_range(100..1000));
                            warn!(
                                ?tx_digest,
                                retry_cnt,
                                "TransactionDriver failed with err: {:?}. Sleeping for {:?} ...",
                                err,
                                delay,
                            );
                            retry_cnt += 1;
                            sleep(delay).await;
                        }
                    }
                }
            }
        }
        bail!("Transaction {:?} failed for {retry_cnt} times", tx_digest);
    }

    fn clone_committee(&self) -> Arc<Committee> {
        self.auth_agg().committee.clone()
    }

    fn get_current_epoch(&self) -> EpochId {
        self.auth_agg().committee.epoch()
    }

    fn clone_new(&self) -> Box<dyn ValidatorProxy + Send + Sync> {
        let driver = match &self.driver {
            LocalDriver::Qd { _qd_handler, .. } => {
                let qdh = _qd_handler.clone_new();
                let qd = qdh.clone_quorum_driver();
                LocalDriver::Qd {
                    _qd_handler: qdh,
                    qd,
                }
            }
            // TransactionDriver is shared via Arc; clones drive against the same
            // instance (and its epoch-updatable aggregator).
            LocalDriver::Td(td) => LocalDriver::Td(td.clone()),
        };
        Box::new(Self {
            driver,
            clients: self.clients.clone(),
            committee: self.committee.clone(),
            allowed_validators: self.allowed_validators.clone(),
        })
    }

    async fn get_committee(&self) -> Result<Vec<IotaAddress>, anyhow::Error> {
        Ok(self
            .get_latest_system_state_object()
            .await?
            .iter_committee_members()
            .map(|v| v.iota_address)
            .collect())
    }
}

pub struct FullNodeProxy {
    iota_client: IotaClient,
    committee: Arc<Committee>,
}

impl FullNodeProxy {
    pub async fn from_url(http_url: &str) -> Result<Self, anyhow::Error> {
        // Each request times out after 60s (default value)
        let iota_client = IotaClientBuilder::default()
            .max_concurrent_requests(500_000)
            .build(http_url)
            .await?;

        let resp = iota_client
            .governance_api()
            .get_committee_info(None)
            .await?;
        let epoch = resp.epoch;
        let committee_vec = resp.validators;
        let committee_map = BTreeMap::from_iter(committee_vec);
        let committee =
            Committee::new_for_testing_with_normalized_voting_power(epoch, committee_map);

        Ok(Self {
            iota_client,
            committee: Arc::new(committee),
        })
    }
}

#[async_trait]
impl ValidatorProxy for FullNodeProxy {
    async fn get_object(&self, object_id: ObjectID) -> Result<Object, anyhow::Error> {
        let response = self
            .iota_client
            .read_api()
            .get_object_with_options(object_id, IotaObjectDataOptions::bcs_lossless())
            .await?;

        if let Some(iota_object) = response.data {
            iota_object.try_into()
        } else if let Some(error) = response.error {
            bail!("Error getting object {:?}: {}", object_id, error)
        } else {
            bail!("Object {:?} not found and no error provided", object_id)
        }
    }

    async fn get_owned_objects(
        &self,
        account_address: IotaAddress,
    ) -> Result<Vec<(u64, Object)>, anyhow::Error> {
        let mut stream = PagedFn::stream(async |cursor| {
            self.iota_client
                .read_api()
                .get_owned_objects(
                    account_address,
                    Some(IotaObjectResponseQuery::new_with_options(
                        IotaObjectDataOptions::bcs_lossless(),
                    )),
                    cursor,
                    None,
                )
                .await
        });

        let mut values_objects = Vec::new();

        while let Some(object) = stream.try_next().await? {
            let o = object.data;
            if let Some(o) = o {
                let temp: Object = o.clone().try_into()?;
                let gas_coin = GasCoin::try_from(&temp)?;
                values_objects.push((gas_coin.value(), o.clone().try_into()?));
            }
        }

        Ok(values_objects)
    }

    async fn get_latest_system_state_object(
        &self,
    ) -> Result<IotaSystemStateSummary, anyhow::Error> {
        Ok(self
            .iota_client
            .governance_api()
            .get_latest_iota_system_state()
            .await?)
    }

    async fn execute_transaction_block(&self, tx: Transaction) -> anyhow::Result<ExecutionEffects> {
        let tx_digest = *tx.digest();
        let mut retry_cnt = 0;
        while retry_cnt < 10 {
            // Fullnode could time out after WAIT_FOR_FINALITY_TIMEOUT (30s) in
            // TransactionOrchestrator IotaClient times out after 60s
            match self
                .iota_client
                .quorum_driver_api()
                .execute_transaction_block(
                    tx.clone(),
                    IotaTransactionBlockResponseOptions::new().with_effects(),
                    None,
                )
                .await
            {
                Ok(resp) => {
                    return Ok(ExecutionEffects::IotaTransactionBlockEffects(
                        resp.effects.expect("effects field should not be None"),
                    ));
                }
                Err(err) => {
                    error!(
                        ?tx_digest,
                        retry_cnt, "Transaction failed with err: {:?}", err
                    );
                    retry_cnt += 1;
                }
            }
        }
        bail!("Transaction {:?} failed for {retry_cnt} times", tx_digest);
    }

    fn clone_committee(&self) -> Arc<Committee> {
        self.committee.clone()
    }

    fn get_current_epoch(&self) -> EpochId {
        self.committee.epoch
    }

    fn clone_new(&self) -> Box<dyn ValidatorProxy + Send + Sync> {
        Box::new(Self {
            iota_client: self.iota_client.clone(),
            committee: self.clone_committee(),
        })
    }

    async fn get_committee(&self) -> Result<Vec<IotaAddress>, anyhow::Error> {
        Ok(self
            .iota_client
            .governance_api()
            .get_latest_iota_system_state()
            .await?
            .iter_committee_members()
            .map(|v| v.iota_address)
            .collect())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum BenchMoveCallArg {
    Pure(Vec<u8>),
    Shared((ObjectID, SequenceNumber, bool)),
    ImmOrOwnedObject(ObjectRef),
    ImmOrOwnedObjectVec(Vec<ObjectRef>),
    SharedObjectVec(Vec<(ObjectID, SequenceNumber, bool)>),
}

impl From<bool> for BenchMoveCallArg {
    fn from(b: bool) -> Self {
        // unwrap safe because every u8 value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(&b).unwrap())
    }
}

impl From<u8> for BenchMoveCallArg {
    fn from(n: u8) -> Self {
        // unwrap safe because every u8 value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(&n).unwrap())
    }
}

impl From<u16> for BenchMoveCallArg {
    fn from(n: u16) -> Self {
        // unwrap safe because every u16 value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(&n).unwrap())
    }
}

impl From<u32> for BenchMoveCallArg {
    fn from(n: u32) -> Self {
        // unwrap safe because every u32 value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(&n).unwrap())
    }
}

impl From<u64> for BenchMoveCallArg {
    fn from(n: u64) -> Self {
        // unwrap safe because every u64 value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(&n).unwrap())
    }
}

impl From<u128> for BenchMoveCallArg {
    fn from(n: u128) -> Self {
        // unwrap safe because every u128 value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(&n).unwrap())
    }
}

impl From<&Vec<u8>> for BenchMoveCallArg {
    fn from(v: &Vec<u8>) -> Self {
        // unwrap safe because every vec<u8> value is BCS-serializable
        BenchMoveCallArg::Pure(bcs::to_bytes(v).unwrap())
    }
}

impl From<ObjectRef> for BenchMoveCallArg {
    fn from(obj: ObjectRef) -> Self {
        BenchMoveCallArg::ImmOrOwnedObject(obj)
    }
}

impl From<CallArg> for BenchMoveCallArg {
    fn from(ca: CallArg) -> Self {
        match ca {
            CallArg::Pure(value) => BenchMoveCallArg::Pure(value),
            CallArg::ImmutableOrOwned(obj_ref) => BenchMoveCallArg::ImmOrOwnedObject(obj_ref),
            CallArg::Shared(SharedObjectRef {
                object_id,
                initial_shared_version,
                mutable,
            }) => BenchMoveCallArg::Shared((object_id, initial_shared_version, mutable)),
            CallArg::Receiving(_) => {
                unimplemented!("Receiving is not supported for benchmarks")
            }
            _ => unimplemented!("a new CallArg enum variant was added and needs to be handled"),
        }
    }
}

/// Convert MoveCallArg to Vector of Argument for PT
pub fn convert_move_call_args(
    args: &[BenchMoveCallArg],
    pt_builder: &mut ProgrammableTransactionBuilder,
) -> Vec<Argument> {
    args.iter()
        .map(|arg| match arg {
            BenchMoveCallArg::Pure(bytes) => pt_builder.pure(bytes.clone()).unwrap(),
            BenchMoveCallArg::Shared((id, initial_shared_version, mutable)) => pt_builder
                .input(CallArg::Shared(SharedObjectRef {
                    object_id: *id,
                    initial_shared_version: *initial_shared_version,
                    mutable: *mutable,
                }))
                .unwrap(),
            BenchMoveCallArg::ImmOrOwnedObject(obj_ref) => pt_builder
                .input(CallArg::ImmutableOrOwned(*obj_ref))
                .unwrap(),
            BenchMoveCallArg::ImmOrOwnedObjectVec(obj_refs) => pt_builder
                .make_obj_vec(obj_refs.iter().map(|q| CallArg::ImmutableOrOwned(*q)))
                .unwrap(),
            BenchMoveCallArg::SharedObjectVec(obj_refs) => pt_builder
                .make_obj_vec(
                    obj_refs
                        .iter()
                        .map(|(id, initial_shared_version, mutable)| {
                            CallArg::Shared(SharedObjectRef {
                                object_id: *id,
                                initial_shared_version: *initial_shared_version,
                                mutable: *mutable,
                            })
                        }),
                )
                .unwrap(),
        })
        .collect()
}
