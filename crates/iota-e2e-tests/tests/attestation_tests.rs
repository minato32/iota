// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the validator attestation path (Phase 1).
//!
//! These tests exercise the V2 transaction submission pathway
//! (`ValidatorV2API::submit_tx`) with both `enable_white_flag_flow` and
//! `enable_validator_attestation` protocol flags enabled.  The Move abstract
//! account setup is reused from `abstract_account_tests` so the attestor
//! dry-run runs `authenticate_then_execute_transaction_to_effects`, which is
//! the more interesting branch of `attest_transaction`.
//!
//! # Protocol config propagation
//!
//! `ProtocolConfig::apply_overrides_for_testing` is thread-local and does not
//! reach validator nodes, which run in separate OS threads (see
//! `iota-swarm/src/memory/container.rs`).  We therefore rely on the
//! `IOTA_PROTOCOL_CONFIG_OVERRIDE_ENABLE` / serde-env mechanism, which is
//! process-wide and readable by every thread.  See `ProtocolEnvOverride`.
//!
//! # Authority aggregator access when WFF is enabled
//!
//! When `enable_white_flag_flow` is `true`, `TransactionOrchestrator` stores
//! the aggregator in `TransactionDriver`, not in `QuorumDriverHandler`.
//! `TestCluster::authority_aggregator()` panics in this configuration because
//! it always goes through `quorum_driver()`.  We therefore reach the
//! aggregator via `transaction_driver()` in `submit_tx_v2`.
//!
//! For the same reason, setup transactions must go through the wallet JSON-RPC
//! path (`test_cluster.execute_transaction`) rather than
//! `execute_transaction_return_raw_effects`, which internally calls
//! `authority_aggregator()`.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use fastcrypto::{
    ed25519::Ed25519Signature,
    encoding::{Encoding, Hex},
    traits::Authenticator,
};
use iota_common::fatal;
use iota_core::authority_client::validator_v2::ValidatorV2API;
use iota_json_rpc_types::ObjectChange;
use iota_keys::keystore::AccountKeystore;
use iota_macros::sim_test;
use iota_test_transaction_builder::publish_package;
use iota_types::{
    IOTA_FRAMEWORK_PACKAGE_ID,
    attestation::{Attestation, AttestationData},
    base_types::{Identifier, IotaAddress, ObjectID, ObjectRef, TypeTag},
    deny_list_v1::{check_address_denied_by_config, get_per_type_coin_deny_list_v1},
    error::{IotaError, UserInputError},
    executable_transaction::{
        CertificateProof, ExecutableTransaction, VerifiedExecutableAttestedTransaction,
        VerifiedExecutableTransaction,
    },
    messages_grpc::TxStatusUpdate,
    move_authenticator::MoveAuthenticator,
    move_package,
    object::Owner,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    signature::GenericSignature,
    transaction::{
        Argument, CallArg, ProgrammableTransaction, SharedObjectRef,
        TEST_ONLY_GAS_UNIT_FOR_HEAVY_COMPUTATION_STORAGE, Transaction, TransactionData,
    },
};
use starfish_config::AuthorityIndex;
use test_cluster::{TestCluster, TestClusterBuilder};
use tokio::time::sleep;

const AA_PACKAGE_PATH: &str = "tests/abstract_account/abstract_account";
const AA_MODULE_NAME: &str = "abstract_account";
const AA_ACCOUNT_NAME: &str = "AbstractAccount";
const AA_CREATE_MODULE_NAME: &str = "abstract_account_keyed";
const AA_AUTHENTICATE_MODULE_NAME: &str = "abstract_account_keyed";
const AA_AUTHENTICATE_FN_NAME_ED25519: &str = "authenticate_ed25519";

// ------------------------------------------
// --- Attestation end-to-end tests ---------
// ------------------------------------------

/// An AA transaction submitted via the V2 gRPC path with both
/// `enable_white_flag_flow` and `enable_validator_attestation` enabled must be
/// attested and accepted (status `Submitted` or `Executed`).
///
/// The MoveAuthenticator path is exercised deliberately because the attestor
/// dry-run takes the `authenticate_then_execute_transaction_to_effects` branch
/// of `attest_transaction`, which is the more interesting code path.
#[sim_test]
async fn test_aa_tx_accepted_via_v2_attestation_path() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();

    // Enable white-flag flow and validator attestation for every node.
    // Must be set BEFORE TestClusterBuilder::build() spawns node threads.
    let _env = ProtocolEnvOverride::new(&[
        ("IOTA_PROTOCOL_CONFIG_OVERRIDE_ENABLE", "1"),
        (
            "IOTA_PROTOCOL_CONFIG_FEATURE_FLAGS_OVERRIDE_ENABLE_WHITE_FLAG_FLOW",
            "true",
        ),
        (
            "IOTA_PROTOCOL_CONFIG_FEATURE_FLAGS_OVERRIDE_ENABLE_VALIDATOR_ATTESTATION",
            "true",
        ),
    ]);

    // Build a test environment and create an abstract account.
    let mut test_env = TestEnvironment::new().await;
    test_env
        .setup_abstract_account(AA_AUTHENTICATE_FN_NAME_ED25519)
        .await?;
    let aa_ref = test_env.aa_ref.unwrap();
    let aa_sender: IotaAddress = aa_ref.object_id.into();

    // Fund the AA with gas.
    let rgp = test_env.test_cluster.get_reference_gas_price().await;
    let aa_gas = test_env
        .test_cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), aa_sender)
        .await;

    // Build a simple AA transaction.
    let pt = test_env.craft_aa_simple_ptb()?;
    let tx_data = test_env.craft_tx_from_pt(pt, aa_gas, aa_sender).await?;
    let tx_digest = tx_data.digest().into_inner();

    let signatures = vec![test_env.create_move_authenticator_for_ed25519(&tx_digest)?];
    let aa_tx = Transaction::from_generic_sig_data(tx_data, signatures);

    // Submit via the V2 attestation path.
    let results = test_env.submit_tx_v2(aa_tx).await?;

    assert!(
        !results.is_empty(),
        "Expected at least one status update from the V2 submit path"
    );
    let (_, status) = &results[0];
    assert!(
        matches!(
            status,
            TxStatusUpdate::Submitted | TxStatusUpdate::Executed { .. }
        ),
        "Expected Submitted or Executed from V2 path, got: {status:?}"
    );

    Ok(())
}

/// An AA transaction whose Move authentication fails (here: a wrong ed25519
/// signature) must be DROPPED by the attestor — never attested, so it can never
/// be sequenced or charged.
#[sim_test]
async fn test_aa_tx_with_failed_authentication_is_dropped() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();
    let _env = enable_attestation_env();

    let mut test_env = TestEnvironment::new().await;
    test_env
        .setup_abstract_account(AA_AUTHENTICATE_FN_NAME_ED25519)
        .await?;
    let aa_ref = test_env.aa_ref.unwrap();
    let aa_sender: IotaAddress = aa_ref.object_id.into();

    let rgp = test_env.test_cluster.get_reference_gas_price().await;
    let aa_gas = test_env
        .test_cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), aa_sender)
        .await;

    let pt = test_env.craft_aa_simple_ptb()?;
    let tx_data = test_env.craft_tx_from_pt(pt, aa_gas, aa_sender).await?;
    let tx_digest = tx_data.digest().into_inner();

    // Attach a Move authenticator that signs a tampered digest, so the in-VM
    // ed25519 verification in `authenticate_ed25519` aborts: the authentication
    // phase fails.
    let signatures = vec![test_env.create_bad_move_authenticator_for_ed25519(&tx_digest)?];
    let aa_tx = Transaction::from_generic_sig_data(tx_data, signatures);

    match test_env.submit_tx_v2(aa_tx).await {
        Ok(results) => {
            assert!(!results.is_empty(), "expected at least one status update");
            let (_, status) = &results[0];
            assert!(
                matches!(status, TxStatusUpdate::Rejected { .. }),
                "auth-failing AA tx must be rejected by the attestor, got: {status:?}"
            );
        }
        // A validator/transport-level error is also an acceptable outcome: the
        // transaction was not attested or accepted.
        Err(e) => {
            tracing::info!("auth-failing AA tx submission errored as expected: {e:?}");
        }
    }

    Ok(())
}

/// An AA transaction whose Move authentication SUCCEEDS but whose transaction
/// body aborts must still be attested (status `Submitted`/`Executed`).
#[sim_test]
async fn test_aa_tx_with_body_abort_is_attested() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();
    let _env = enable_attestation_env();

    let mut test_env = TestEnvironment::new().await;
    test_env
        .setup_abstract_account(AA_AUTHENTICATE_FN_NAME_ED25519)
        .await?;
    let aa_ref = test_env.aa_ref.unwrap();
    let aa_sender: IotaAddress = aa_ref.object_id.into();

    let rgp = test_env.test_cluster.get_reference_gas_price().await;
    let aa_gas = test_env
        .test_cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), aa_sender)
        .await;

    let pt = test_env.craft_aa_double_add_ptb()?;
    let tx_data = test_env.craft_tx_from_pt(pt, aa_gas, aa_sender).await?;
    let tx_digest = tx_data.digest().into_inner();

    // Correct signature: the authentication phase succeeds; only the body aborts.
    let signatures = vec![test_env.create_move_authenticator_for_ed25519(&tx_digest)?];
    let aa_tx = Transaction::from_generic_sig_data(tx_data, signatures);

    let results = test_env.submit_tx_v2(aa_tx).await?;
    assert!(!results.is_empty(), "expected at least one status update");
    let (_, status) = &results[0];
    assert!(
        matches!(
            status,
            TxStatusUpdate::Submitted | TxStatusUpdate::Executed { .. }
        ),
        "AA tx with successful auth but a body abort must still be attested, got: {status:?}"
    );

    Ok(())
}

/// A normal (non-abstract-account) transaction whose body aborts must be
/// attested too. Here a normal owner-signed tx calls `add_field` on the shared
/// AA object; `ensure_tx_sender_is_account` aborts because the sender is the
/// owner, not the account.
#[sim_test]
async fn test_normal_tx_with_body_abort_is_attested() -> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();
    let _env = enable_attestation_env();

    let mut test_env = TestEnvironment::new().await;
    test_env
        .setup_abstract_account(AA_AUTHENTICATE_FN_NAME_ED25519)
        .await?;

    // Build a normal transaction (no Move authenticator) signed by the owner.
    let pt = test_env.craft_aa_simple_ptb()?;
    let tx_data = test_env
        .test_cluster
        .test_transaction_builder()
        .await
        .programmable(pt)
        .build();
    let normal_tx = test_env.test_cluster.wallet.sign_transaction(&tx_data);

    let results = test_env.submit_tx_v2(normal_tx).await?;
    assert!(!results.is_empty(), "expected at least one status update");
    let (_, status) = &results[0];
    assert!(
        matches!(
            status,
            TxStatusUpdate::Submitted | TxStatusUpdate::Executed { .. }
        ),
        "normal tx with a body abort must still be attested, got: {status:?}"
    );

    Ok(())
}

// --------------------------------------------------
// --- Protocol config env override RAII guard ------
// --------------------------------------------------

/// Enable white-flag flow and validator attestation for every node. Must be
/// called BEFORE `TestClusterBuilder::build()` spawns node threads.
fn enable_attestation_env() -> ProtocolEnvOverride {
    ProtocolEnvOverride::new(&[
        ("IOTA_PROTOCOL_CONFIG_OVERRIDE_ENABLE", "1"),
        (
            "IOTA_PROTOCOL_CONFIG_FEATURE_FLAGS_OVERRIDE_ENABLE_WHITE_FLAG_FLOW",
            "true",
        ),
        (
            "IOTA_PROTOCOL_CONFIG_FEATURE_FLAGS_OVERRIDE_ENABLE_VALIDATOR_ATTESTATION",
            "true",
        ),
    ])
}

/// Sets process-wide environment variables on construction, restores them (by
/// removing them) on drop.  Must be constructed **before**
/// `TestClusterBuilder::build()` so that validator node threads inherit the
/// values when they call `ProtocolConfig::get_for_version`.
struct ProtocolEnvOverride {
    keys: Vec<&'static str>,
}

impl ProtocolEnvOverride {
    fn new(overrides: &[(&'static str, &'static str)]) -> Self {
        for (key, val) in overrides {
            // Set before any node thread is spawned; no concurrent env readers at this
            // point.
            #[allow(deprecated)]
            std::env::set_var(key, val);
        }
        Self {
            keys: overrides.iter().map(|(k, _)| *k).collect(),
        }
    }
}

impl Drop for ProtocolEnvOverride {
    fn drop(&mut self) {
        for key in &self.keys {
            #[allow(deprecated)]
            std::env::remove_var(key);
        }
    }
}

// --------------------------------------------------
// --- Minimal test environment ---------------------
// --------------------------------------------------

struct TestEnvironment {
    test_cluster: TestCluster,
    owner: Option<IotaAddress>,
    aa_package_id: Option<ObjectID>,
    aa_package_metadata_ref: Option<ObjectRef>,
    aa_ref: Option<ObjectRef>,
}

impl TestEnvironment {
    async fn new() -> Self {
        let test_cluster = TestClusterBuilder::new().build().await;
        Self {
            test_cluster,
            owner: None,
            aa_package_id: None,
            aa_package_metadata_ref: None,
            aa_ref: None,
        }
    }

    async fn setup_abstract_account(
        &mut self,
        authenticate_fn_name: &str,
    ) -> Result<(), anyhow::Error> {
        self.owner = Some(
            self.test_cluster
                .wallet
                .config()
                .keystore()
                .addresses()
                .first()
                .cloned()
                .unwrap(),
        );

        let path = [env!("CARGO_MANIFEST_DIR"), AA_PACKAGE_PATH]
            .iter()
            .collect();
        let aa_package_id = publish_package(self.test_cluster.wallet(), path)
            .await
            .object_id;
        let aa_package_metadata_id = move_package::derive_package_metadata_id(aa_package_id);
        let aa_package_metadata_ref = self
            .test_cluster
            .get_latest_object_ref(&aa_package_metadata_id)
            .await;

        self.aa_package_id = Some(aa_package_id);
        self.aa_package_metadata_ref = Some(aa_package_metadata_ref);

        let transaction = self
            .craft_create_abstract_account(authenticate_fn_name)
            .await?;

        // Use the wallet JSON-RPC path so we don't call authority_aggregator(),
        // which panics when white-flag flow is active (QuorumDriverHandler is None).
        let response = self.test_cluster.execute_transaction(transaction).await;

        self.aa_ref = response
            .object_changes
            .as_ref()
            .expect("object_changes must be populated")
            .iter()
            .find_map(|change| {
                if let ObjectChange::Created {
                    object_id,
                    version,
                    digest,
                    owner: Owner::Shared { .. },
                    ..
                } = change
                {
                    Some(iota_types::base_types::ObjectRef::new(
                        *object_id, *version, *digest,
                    ))
                } else {
                    None
                }
            });

        assert!(
            self.aa_ref.is_some(),
            "Abstract account creation did not produce a shared object"
        );
        Ok(())
    }

    async fn craft_create_abstract_account(
        &self,
        authenticate_fn_name: &str,
    ) -> anyhow::Result<Transaction> {
        let (Some(owner), Some(aa_package_id), Some(aa_package_metadata_ref)) =
            (self.owner, self.aa_package_id, self.aa_package_metadata_ref)
        else {
            anyhow::bail!("setup_abstract_account must be called first");
        };

        let aa_owner_pk = self
            .test_cluster
            .wallet
            .config()
            .keystore()
            .get_key(&owner)?
            .public();

        let pt = {
            let mut builder = ProgrammableTransactionBuilder::new();

            let arguments = vec![
                builder.obj(CallArg::ImmutableOrOwned(aa_package_metadata_ref))?,
                builder.pure(AA_AUTHENTICATE_MODULE_NAME)?,
                builder.pure(authenticate_fn_name)?,
            ];
            if let Argument::Result(auth_fn_ref) = builder.programmable_move_call(
                IOTA_FRAMEWORK_PACKAGE_ID,
                Identifier::from_static("authenticator_function"),
                Identifier::from_static("create_auth_function_ref_v1"),
                vec![abstract_account_type_tag(&aa_package_id)],
                arguments,
            ) {
                let arguments = vec![
                    builder.pure(aa_owner_pk.as_ref())?,
                    Argument::Result(auth_fn_ref),
                ];
                builder.programmable_move_call(
                    aa_package_id,
                    Identifier::from_static(AA_CREATE_MODULE_NAME),
                    Identifier::from_static("create"),
                    vec![],
                    arguments,
                );
            }
            builder.finish()
        };

        let tx_data = self
            .test_cluster
            .test_transaction_builder()
            .await
            .programmable(pt)
            .build();

        Ok(self.test_cluster.wallet.sign_transaction(&tx_data))
    }

    fn craft_aa_simple_ptb(&self) -> anyhow::Result<ProgrammableTransaction> {
        let (Some(aa_ref), Some(aa_package_id)) = (self.aa_ref, self.aa_package_id) else {
            anyhow::bail!("Abstract account not set up yet");
        };
        let mut builder = ProgrammableTransactionBuilder::new();
        let arguments = vec![
            builder.obj(CallArg::Shared(SharedObjectRef {
                object_id: aa_ref.object_id,
                initial_shared_version: aa_ref.version,
                mutable: true,
            }))?,
            builder.pure(1_u8)?,
            builder.pure(2_u8)?,
        ];
        builder.programmable_move_call(
            aa_package_id,
            Identifier::from_static(AA_MODULE_NAME),
            Identifier::from_static("add_field"),
            vec![
                iota_types::base_types::TypeTag::U8,
                iota_types::base_types::TypeTag::U8,
            ],
            arguments,
        );
        Ok(builder.finish())
    }

    /// A PTB that adds the same dynamic field key twice, so the second
    /// `add_field` aborts in the transaction body (the auth phase, if present,
    /// is unaffected).
    fn craft_aa_double_add_ptb(&self) -> anyhow::Result<ProgrammableTransaction> {
        let (Some(aa_ref), Some(aa_package_id)) = (self.aa_ref, self.aa_package_id) else {
            anyhow::bail!("Abstract account not set up yet");
        };
        let mut builder = ProgrammableTransactionBuilder::new();
        let aa_arg = builder.obj(CallArg::Shared(SharedObjectRef {
            object_id: aa_ref.object_id,
            initial_shared_version: aa_ref.version,
            mutable: true,
        }))?;
        let type_args = vec![
            iota_types::base_types::TypeTag::U8,
            iota_types::base_types::TypeTag::U8,
        ];
        for value in [2_u8, 3_u8] {
            // Same key (1u8) both times; the second `dynamic_field::add` aborts.
            let key = builder.pure(1_u8)?;
            let val = builder.pure(value)?;
            builder.programmable_move_call(
                aa_package_id,
                Identifier::from_static(AA_MODULE_NAME),
                Identifier::from_static("add_field"),
                type_args.clone(),
                vec![aa_arg, key, val],
            );
        }
        Ok(builder.finish())
    }

    async fn craft_tx_from_pt(
        &self,
        pt: ProgrammableTransaction,
        gas_coin: ObjectRef,
        sender: IotaAddress,
    ) -> anyhow::Result<TransactionData> {
        let gas_price = self.test_cluster.get_reference_gas_price().await;
        Ok(TransactionData::new_programmable_allow_sponsor(
            sender,
            vec![gas_coin],
            pt,
            gas_price * TEST_ONLY_GAS_UNIT_FOR_HEAVY_COMPUTATION_STORAGE,
            gas_price,
            sender,
        ))
    }

    fn create_move_authenticator_for_ed25519(
        &self,
        tx_digest: &[u8; 32],
    ) -> anyhow::Result<GenericSignature> {
        let (Some(aa_ref), Some(owner)) = (self.aa_ref, self.owner) else {
            anyhow::bail!("Abstract account not set up yet");
        };
        let signature = self
            .test_cluster
            .wallet
            .config()
            .keystore()
            .sign_hashed(&owner, tx_digest)?;

        let hex_encoded_signature: String = Hex::encode(&signature)
            .chars()
            .skip(2)
            .take(Ed25519Signature::LENGTH * 2)
            .collect();
        let self_call_arg = CallArg::Shared(SharedObjectRef {
            object_id: aa_ref.object_id,
            initial_shared_version: aa_ref.version,
            mutable: false,
        });
        let signature_call_arg = CallArg::Pure(bcs::to_bytes(&hex_encoded_signature)?);
        Ok(GenericSignature::MoveAuthenticator(
            MoveAuthenticator::new_v1(vec![signature_call_arg], vec![], self_call_arg),
        ))
    }

    /// Like [`Self::create_move_authenticator_for_ed25519`], but signs a
    /// *tampered* digest so the in-VM ed25519 verification fails — the
    /// authentication phase aborts.
    fn create_bad_move_authenticator_for_ed25519(
        &self,
        tx_digest: &[u8; 32],
    ) -> anyhow::Result<GenericSignature> {
        let mut tampered = *tx_digest;
        tampered[0] ^= 0xff;
        self.create_move_authenticator_for_ed25519(&tampered)
    }

    /// Submit a transaction via the V2 gRPC path on the first available
    /// validator.
    ///
    /// When `enable_white_flag_flow` is on, `TransactionOrchestrator` stores
    /// the aggregator in `TransactionDriver` (not `QuorumDriverHandler`).
    /// We select the right source at runtime.
    async fn submit_tx_v2(
        &self,
        tx: Transaction,
    ) -> Result<
        Vec<(iota_types::digests::TransactionDigest, TxStatusUpdate)>,
        iota_types::error::IotaError,
    > {
        let client = self.test_cluster.fullnode_handle.iota_node.with(|node| {
            let orchestrator = node
                .transaction_orchestrator()
                .expect("TransactionOrchestrator not initialised on fullnode");

            // When WFF is enabled TransactionDriver holds the aggregator;
            // QuorumDriverHandler is None and clone_authority_aggregator() would panic.
            let agg = if let Some(td) = orchestrator.transaction_driver() {
                td.authority_aggregator().load_full()
            } else {
                orchestrator.clone_authority_aggregator()
            };

            agg.authority_clients
                .values()
                .next()
                .expect("No authority clients")
                .authority_client()
                .clone()
        });

        client
            .submit_tx(vec![tx], Some(SocketAddr::new([127, 0, 0, 1].into(), 0)))
            .await
    }
}

fn abstract_account_type_tag(aa_package_id: &ObjectID) -> iota_types::base_types::TypeTag {
    use std::str::FromStr;
    iota_types::base_types::TypeTag::from_str(&format!(
        "{aa_package_id}::{AA_MODULE_NAME}::{AA_ACCOUNT_NAME}"
    ))
    .unwrap()
}

// --------------------------------------------------
// --- Deny-list crash on the MoveAuthenticator path -
// --------------------------------------------------

impl TestEnvironment {
    /// Publishes `move_test_code` (whose `regulated_coin` module mints a
    /// `REGULATED_COIN` to the publisher and transfers it the `DenyCap`).
    /// Returns `(coin_id, deny_cap_id, coin_type)`.
    async fn publish_regulated_coin(&self) -> (ObjectID, ObjectID, TypeTag) {
        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/move_test_code"]
            .iter()
            .collect();
        let tx_data = self
            .test_cluster
            .test_transaction_builder()
            .await
            .publish(path)
            .build();
        let tx = self.test_cluster.wallet.sign_transaction(&tx_data);
        let response = self.test_cluster.execute_transaction(tx).await;

        let mut coin_id = None;
        let mut coin_type = None;
        let mut deny_cap_id = None;
        for change in response
            .object_changes
            .as_ref()
            .expect("object_changes must be populated")
        {
            if let ObjectChange::Created { object_id, .. } = change {
                let object = self
                    .test_cluster
                    .get_object_from_fullnode_store(object_id)
                    .await
                    .unwrap();
                if object.is_coin() {
                    coin_id = Some(*object_id);
                    coin_type = object.coin_type_opt().cloned();
                } else if object.type_().map_or(false, |t| t.is_deny_cap_v1()) {
                    deny_cap_id = Some(*object_id);
                }
            }
        }
        (coin_id.unwrap(), deny_cap_id.unwrap(), coin_type.unwrap())
    }

    /// Transfers an owned object to `recipient` via the wallet path.
    async fn transfer_object_to(&self, object_id: &ObjectID, recipient: IotaAddress) {
        let object_ref = self.test_cluster.get_latest_object_ref(object_id).await;
        let tx_data = self
            .test_cluster
            .test_transaction_builder()
            .await
            .transfer(object_ref, recipient)
            .build();
        let tx = self.test_cluster.wallet.sign_transaction(&tx_data);
        let response = self.test_cluster.execute_transaction(tx).await;
        assert!(
            response.status_ok().unwrap_or(false),
            "transfer to {recipient} failed: {response:?}"
        );
    }

    /// Adds `address` to the deny list for `coin_type` (signed by the wallet
    /// owner, who holds the `DenyCap`).
    async fn deny_address_for_coin(
        &self,
        address: IotaAddress,
        deny_cap_id: &ObjectID,
        coin_type: &TypeTag,
    ) {
        let deny_list_init_version = self
            .test_cluster
            .get_object_from_fullnode_store(&ObjectID::DENY_LIST)
            .await
            .unwrap()
            .version();
        let deny_cap_ref = self.test_cluster.get_latest_object_ref(deny_cap_id).await;
        let tx_data = self
            .test_cluster
            .test_transaction_builder()
            .await
            .move_call(
                IOTA_FRAMEWORK_PACKAGE_ID,
                "coin",
                "deny_list_v1_add",
                vec![
                    CallArg::Shared(SharedObjectRef {
                        object_id: ObjectID::DENY_LIST,
                        initial_shared_version: deny_list_init_version,
                        mutable: true,
                    }),
                    CallArg::ImmutableOrOwned(deny_cap_ref),
                    CallArg::pure(&address),
                ],
            )
            .with_type_args(vec![coin_type.clone()])
            .build();
        let tx = self.test_cluster.wallet.sign_transaction(&tx_data);
        let response = self.test_cluster.execute_transaction(tx).await;
        assert!(
            response.status_ok().unwrap_or(false),
            "deny_list_v1_add failed: {response:?}"
        );
    }
}

/// Same bug as the owned-object case (`per_epoch_config_stress_tests`), but on
/// the **MoveAuthenticator** branch of `prepare_certificate`
/// (`authority.rs:1924-1936`).
///
/// An attested `UserTransactionV2` that uses a Move authenticator (abstract
/// account) and a regulated coin is attested while the sender is allowed, but
/// the sender is added to the deny list before execution. The execution-time
/// re-check (`check_coin_deny_list_v1?`) then returns `Err`, which the
/// execution driver turns into `fatal!`.
///
/// Unlike the owned-object test, a MoveAuthenticator tx takes the abstract
/// account as a *shared* input, so it can't be certified + executed by hand the
/// simple way. Instead we build the V2-style `ConsensusOrdered` executable the
/// sequencer builds, hand-assign its shared-object versions with the test
/// helper, then drive `try_execute_immediately` directly on a validator. The
/// resulting `Err` is fed through the verbatim `execution_driver.rs` match so
/// `fatal!` fires, caught with `catch_unwind`.
#[sim_test]
async fn attested_move_auth_tx_denylisted_at_execution_crashes_validator()
-> Result<(), anyhow::Error> {
    telemetry_subscribers::init_for_testing();

    let _env = ProtocolEnvOverride::new(&[
        ("IOTA_PROTOCOL_CONFIG_OVERRIDE_ENABLE", "1"),
        (
            "IOTA_PROTOCOL_CONFIG_FEATURE_FLAGS_OVERRIDE_ENABLE_WHITE_FLAG_FLOW",
            "true",
        ),
        (
            "IOTA_PROTOCOL_CONFIG_FEATURE_FLAGS_OVERRIDE_ENABLE_VALIDATOR_ATTESTATION",
            "true",
        ),
    ]);

    let mut test_env = TestEnvironment::new().await;
    test_env
        .setup_abstract_account(AA_AUTHENTICATE_FN_NAME_ED25519)
        .await?;
    let aa_ref = test_env.aa_ref.unwrap();
    let aa_sender: IotaAddress = aa_ref.object_id.into();

    // Fund the abstract account with gas.
    let rgp = test_env.test_cluster.get_reference_gas_price().await;
    let aa_gas = test_env
        .test_cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), aa_sender)
        .await;

    // Publish a regulated coin and move it under the abstract account's address.
    let (coin_id, deny_cap_id, coin_type) = test_env.publish_regulated_coin().await;
    test_env.transfer_object_to(&coin_id, aa_sender).await;
    let coin_ref = test_env.test_cluster.get_latest_object_ref(&coin_id).await;

    // Build a MoveAuthenticator tx (sender = AA) that (a) touches the AA shared
    // object so it receives a shared-version assignment, and (b) takes the
    // regulated coin as input so the deny-list check has a coin type to inspect.
    let pt = {
        let mut builder = ProgrammableTransactionBuilder::new();
        let aa_arg = builder.obj(CallArg::Shared(SharedObjectRef {
            object_id: aa_ref.object_id,
            initial_shared_version: aa_ref.version,
            mutable: true,
        }))?;
        let key = builder.pure(1_u8)?;
        let value = builder.pure(2_u8)?;
        builder.programmable_move_call(
            test_env.aa_package_id.unwrap(),
            Identifier::from_static(AA_MODULE_NAME),
            Identifier::from_static("add_field"),
            vec![TypeTag::U8, TypeTag::U8],
            vec![aa_arg, key, value],
        );
        let coin_arg = builder.obj(CallArg::ImmutableOrOwned(coin_ref))?;
        builder.transfer_arg(IotaAddress::ZERO, coin_arg);
        builder.finish()
    };
    let tx_data = test_env.craft_tx_from_pt(pt, aa_gas, aa_sender).await?;
    let tx_digest = tx_data.digest().into_inner();
    let signatures = vec![test_env.create_move_authenticator_for_ed25519(&tx_digest)?];
    let aa_tx = Transaction::from_generic_sig_data(tx_data, signatures);

    // Pick a validator and build the V2-style executable (`ConsensusOrdered`
    // proof), exactly as the sequencer does for `UserTransactionV2`.
    let validator_state = test_env
        .test_cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .next()
        .unwrap()
        .with(|node| node.state());
    let epoch_store = validator_state.epoch_store_for_testing();
    let executable =
        VerifiedExecutableTransaction::new_unchecked(ExecutableTransaction::new_from_data_and_sig(
            aa_tx.data().clone(),
            CertificateProof::ConsensusOrdered(epoch_store.epoch()),
        ));

    // Assign the shared-object versions the sequencer would assign.
    epoch_store.assign_shared_object_versions_for_tests(
        validator_state.get_object_cache_reader().as_ref(),
        std::slice::from_ref(&executable),
    )?;

    // Deny the sender AFTER the executable was built — modelling the deny list
    // changing between attestation and execution. `None`-epoch reads make this
    // visible immediately, in the same epoch.
    test_env
        .deny_address_for_coin(aa_sender, &deny_cap_id, &coin_type)
        .await;

    // Wait until this validator observes the denial in its own store.
    let coin_type_str = coin_type.to_canonical_string(false);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(cfg) =
                get_per_type_coin_deny_list_v1(&coin_type_str, &validator_state.get_object_store())
            {
                if check_address_denied_by_config(
                    &cfg,
                    aa_sender,
                    &validator_state.get_object_store(),
                    None,
                ) {
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("validator never observed the denial");

    // Execute as an attested tx → MoveAuthenticator branch of
    // `prepare_certificate` runs the deny-list re-check → `AddressDeniedForCoin`.
    let attestation = Attestation::Validator {
        payload: AttestationData::V1 {
            estimated_computation_cost: 1_000_000,
            object_versions: vec![],
        },
        attestor_index: AuthorityIndex::new_for_test(0),
    };
    let attested = VerifiedExecutableAttestedTransaction::new(executable, Some(attestation));
    let result = validator_state.try_execute_immediately(&attested, None, &epoch_store);

    assert!(
        matches!(
            &result,
            Err(IotaError::UserInput {
                error: UserInputError::AddressDeniedForCoin { .. }
            })
        ),
        "expected AddressDeniedForCoin from the move-authenticator branch, got {result:?}",
    );

    // Feed that real `Err` through the EXACT match from `execution_driver.rs`.
    // `fatal!` is `panic!`, so this reproduces the node crash; catch it
    // explicitly (silencing the expected backtrace).
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match result {
        Err(IotaError::ValidatorHaltedAtEpochEnd) => {}
        Err(e) => fatal!("Failed to execute certified transaction! error={e}"),
        _ => {}
    }));
    std::panic::set_hook(prev_hook);
    assert!(
        crashed.is_err(),
        "expected the attested deny-listed move-authenticator tx to crash the validator via fatal!, but it did not",
    );

    Ok(())
}
