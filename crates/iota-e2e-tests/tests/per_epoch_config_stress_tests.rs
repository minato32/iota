// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use iota_common::fatal;
use iota_json_rpc_types::IotaTransactionBlockEffectsAPI;
use iota_macros::sim_test;
use iota_types::{
    attestation::{Attestation, AttestationData},
    base_types::{EpochId, Identifier, IotaAddress, ObjectID, ObjectRef, SequenceNumber, TypeTag},
    deny_list_v1::{check_address_denied_by_config, get_per_type_coin_deny_list_v1},
    error::{IotaError, UserInputError},
    executable_transaction::{
        VerifiedExecutableAttestedTransaction, VerifiedExecutableTransaction,
    },
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{CallArg, SharedObjectRef, TransactionData, VerifiedCertificate},
};
use rand::random;
use starfish_config::AuthorityIndex;
use test_cluster::{TestCluster, TestClusterBuilder};
use tracing::info;

const DENY_ADDRESS: IotaAddress = IotaAddress::ZERO;

#[sim_test]
async fn per_epoch_config_stress_test() {
    let test_env = Arc::new(create_test_env().await);
    let target_epoch = 10;
    let mut gas_objects = test_env
        .test_cluster
        .wallet
        .get_all_gas_objects_owned_by_address(test_env.regulated_coin_owner)
        .await
        .unwrap();
    let gas1 = gas_objects.pop().unwrap();
    let gas2 = gas_objects.pop().unwrap();
    let handle1 = {
        let test_env = test_env.clone();
        tokio::spawn(async move {
            run_thread(
                1,
                test_env,
                target_epoch,
                gas1.object_id,
                create_transfer_tx,
                true,
            )
            .await
        })
    };
    let handle2 = {
        let test_env = test_env.clone();
        tokio::spawn(async move {
            run_thread(
                2,
                test_env,
                target_epoch,
                gas2.object_id,
                create_deny_tx,
                false,
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(600), async {
        tokio::try_join!(handle1, handle2)
    })
    .await
    .unwrap()
    .unwrap();
}

async fn run_thread<F, Fut>(
    thread_id: u64,
    test_env: Arc<TestEnv>,
    target_epoch: EpochId,
    gas_id: ObjectID,
    tx_creation_func: F,
    tx_may_fail: bool,
) where
    F: Fn(Arc<TestEnv>, ObjectRef) -> Fut,
    Fut: Future<Output = TransactionData>,
{
    info!(?thread_id, "Thread started");
    let mut num_tx_succeeded = 0;
    let mut num_tx_failed = 0;
    loop {
        let gas = test_env.get_latest_object_ref(&gas_id).await;
        let tx_data = tx_creation_func(test_env.clone(), gas).await;
        let tx = test_env.test_cluster.sign_transaction(&tx_data);
        let tx_digest = *tx.digest();
        info!(?thread_id, ?tx_digest, "Sending transaction");
        let Ok(effects) = test_env
            .test_cluster
            .wallet
            .execute_transaction_may_fail(tx)
            .await
            .map(|r| r.effects.unwrap())
        else {
            // When epochs are short, it is possible that some transactions
            // keep getting sent at epoch boundaries and timeout eventually.
            continue;
        };
        if effects.status().is_ok() {
            info!(?thread_id, ?tx_digest, "Transaction succeeded");
            num_tx_succeeded += 1;
        } else {
            info!(?thread_id, ?tx_digest, "Transaction failed");
            num_tx_failed += 1;
        }
        let executed_epoch = effects.executed_epoch();
        if executed_epoch >= target_epoch {
            info!(
                ?thread_id,
                "Reached target epoch {target_epoch}. Current {executed_epoch}."
            );
            break;
        }
    }
    if !tx_may_fail {
        assert_eq!(num_tx_failed, 0);
    }
    assert!(
        num_tx_succeeded + num_tx_failed > 5,
        "Thread {thread_id} succeeded {num_tx_succeeded} transactions and failed {num_tx_failed} transactions"
    );
    info!(
        ?thread_id,
        "Thread {thread_id} finished. Succeeded {num_tx_succeeded} transactions and failed {num_tx_failed} transactions."
    );
}

async fn create_deny_tx(test_env: Arc<TestEnv>, gas: ObjectRef) -> TransactionData {
    let deny: bool = random();
    test_env
        .test_cluster
        .test_transaction_builder_with_gas_object(test_env.regulated_coin_owner, gas)
        .await
        .move_call(
            ObjectID::FRAMEWORK,
            "coin",
            if deny {
                "deny_list_v1_add"
            } else {
                "deny_list_v1_remove"
            },
            vec![
                CallArg::Shared(SharedObjectRef {
                    object_id: ObjectID::DENY_LIST,
                    initial_shared_version: test_env.deny_list_object_init_version,
                    mutable: true,
                }),
                CallArg::ImmutableOrOwned(
                    test_env.get_latest_object_ref(&test_env.deny_cap_id).await,
                ),
                CallArg::pure(&DENY_ADDRESS),
            ],
        )
        .with_type_args(vec![test_env.regulated_coin_type.clone()])
        .build()
}

async fn create_transfer_tx(test_env: Arc<TestEnv>, gas: ObjectRef) -> TransactionData {
    let use_move: bool = random();
    if use_move {
        create_move_transfer_tx(test_env, gas).await
    } else {
        create_native_transfer_tx(test_env, gas).await
    }
}

async fn create_move_transfer_tx(test_env: Arc<TestEnv>, gas: ObjectRef) -> TransactionData {
    test_env
        .test_cluster
        .test_transaction_builder_with_gas_object(test_env.regulated_coin_owner, gas)
        .await
        .move_call(
            ObjectID::FRAMEWORK,
            "pay",
            "split_and_transfer",
            vec![
                CallArg::ImmutableOrOwned(
                    test_env
                        .get_latest_object_ref(&test_env.regulated_coin_id)
                        .await,
                ),
                CallArg::pure(&1u64),
                CallArg::pure(&DENY_ADDRESS),
            ],
        )
        .with_type_args(vec![test_env.regulated_coin_type.clone()])
        .build()
}

async fn create_native_transfer_tx(test_env: Arc<TestEnv>, gas: ObjectRef) -> TransactionData {
    let mut pt_builder = ProgrammableTransactionBuilder::new();
    let coin_input = pt_builder
        .obj(CallArg::ImmutableOrOwned(
            test_env
                .get_latest_object_ref(&test_env.regulated_coin_id)
                .await,
        ))
        .unwrap();
    let amount_input = pt_builder.pure(1u64).unwrap();
    let split_coin = pt_builder.programmable_move_call(
        ObjectID::FRAMEWORK,
        Identifier::COIN_MODULE,
        Identifier::from_static("split"),
        vec![test_env.regulated_coin_type.clone()],
        vec![coin_input, amount_input],
    );
    pt_builder.transfer_arg(DENY_ADDRESS, split_coin);
    let pt = pt_builder.finish();
    test_env
        .test_cluster
        .test_transaction_builder_with_gas_object(test_env.regulated_coin_owner, gas)
        .await
        .programmable(pt)
        .build()
}

struct TestEnv {
    test_cluster: TestCluster,
    regulated_coin_id: ObjectID,
    regulated_coin_type: TypeTag,
    regulated_coin_owner: IotaAddress,
    deny_cap_id: ObjectID,
    deny_list_object_init_version: SequenceNumber,
}

impl TestEnv {
    async fn get_latest_object_ref(&self, object_id: &ObjectID) -> ObjectRef {
        self.test_cluster
            .get_object_from_fullnode_store(object_id)
            .await
            .unwrap()
            .compute_object_reference()
    }
}

async fn create_test_env() -> TestEnv {
    create_test_env_with_epoch_duration(Some(1000)).await
}

async fn create_test_env_with_epoch_duration(epoch_duration_ms: Option<u64>) -> TestEnv {
    let mut builder = TestClusterBuilder::new().with_num_validators(5);
    if let Some(ms) = epoch_duration_ms {
        builder = builder.with_epoch_duration_ms(ms);
    }
    let test_cluster = builder.build().await;
    let deny_list_object_init_version = test_cluster
        .get_object_from_fullnode_store(&ObjectID::DENY_LIST)
        .await
        .unwrap()
        .version();
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/move_test_code");
    let tx_data = test_cluster
        .test_transaction_builder()
        .await
        .publish(path)
        .build();
    let effects = test_cluster
        .sign_and_execute_transaction(&tx_data)
        .await
        .effects
        .unwrap();
    let mut coin_id = None;
    let mut coin_type = None;
    let mut coin_owner = None;
    let mut deny_cap = None;
    for created in effects.created() {
        let object_id = created.reference.object_id;
        let object = test_cluster
            .get_object_from_fullnode_store(&object_id)
            .await
            .unwrap();
        if object.is_package() {
            continue;
        } else if object.is_coin() {
            coin_id = Some(object_id);
            coin_type = object.coin_type_opt().cloned();
            coin_owner = Some(*created.owner.as_address());
        } else if object.type_().unwrap().is_deny_cap_v1() {
            deny_cap = Some(object_id);
        }
    }
    TestEnv {
        test_cluster,
        regulated_coin_id: coin_id.unwrap(),
        regulated_coin_type: coin_type.unwrap(),
        regulated_coin_owner: coin_owner.unwrap(),
        deny_cap_id: deny_cap.unwrap(),
        deny_list_object_init_version,
    }
}

/// Reproduces the validator-attestation deny-list execution crash from PR
/// #11574.
///
/// `prepare_certificate` re-runs the sender-side coin deny-list check for any
/// *attested* transaction and propagates a failure as `Err` out of
/// `try_execute_immediately`. The execution driver (`execution_driver.rs`)
/// turns any such `Err` (other than `ValidatorHaltedAtEpochEnd`) into `fatal!`
/// — a node panic.
///
/// The input deny-list check reads with `cur_epoch = None`, so a
/// `deny_list_v1_add` takes effect IMMEDIATELY, within the same epoch. A
/// transfer that was attested/certified *before* the sender was denied
/// therefore fails this re-check at execution time, crashing every honest
/// validator deterministically.
///
/// This test certifies the transfer while the sender is allowed, denies the
/// sender, then executes the attested certificate on a real validator
/// `AuthorityState`. The resulting `Err` is fed through the exact
/// `execution_driver.rs` match, so `fatal!` fires and the test panics.
#[sim_test]
async fn attested_tx_denylisted_between_attestation_and_execution_crashes_validator() {
    // Use a long (default) epoch so the certificate's epoch does not advance
    // between certifying and executing it (a 1s epoch yields `WrongEpoch`).
    let test_env = create_test_env_with_epoch_duration(None).await;
    let owner = test_env.regulated_coin_owner;

    // Two gas coins: one funds the transfer cert, one funds the deny-list add.
    let gas_objs = test_env
        .test_cluster
        .wallet
        .get_all_gas_objects_owned_by_address(owner)
        .await
        .unwrap();
    let gas_for_transfer = gas_objs[0];
    let gas_for_deny = gas_objs[1];

    // 1) Certify a transfer of the regulated coin WHILE THE SENDER IS NOT YET
    //    DENIED. Stands in for the attestor's pre-consensus dry-run + signing: it
    //    passes because the deny-list check currently allows it.
    //    `create_certificate` gathers a quorum of signatures but does NOT execute
    //    the transaction.
    let transfer_data = test_env
        .test_cluster
        .test_transaction_builder_with_gas_object(owner, gas_for_transfer)
        .await
        .move_call(
            ObjectID::FRAMEWORK,
            "pay",
            "split_and_transfer",
            vec![
                CallArg::ImmutableOrOwned(
                    test_env
                        .get_latest_object_ref(&test_env.regulated_coin_id)
                        .await,
                ),
                CallArg::pure(&1u64),
                CallArg::pure(&IotaAddress::ZERO),
            ],
        )
        .with_type_args(vec![test_env.regulated_coin_type.clone()])
        .build();
    let transfer_tx = test_env.test_cluster.sign_transaction(&transfer_data);
    let cert = test_env
        .test_cluster
        .create_certificate(transfer_tx, None)
        .await
        .unwrap();

    // 2) Now deny the sender. With `None`-epoch reads (used by the input deny-list
    //    check) this is visible IMMEDIATELY, in the same epoch.
    let deny_data = test_env
        .test_cluster
        .test_transaction_builder_with_gas_object(owner, gas_for_deny)
        .await
        .move_call(
            ObjectID::FRAMEWORK,
            "coin",
            "deny_list_v1_add",
            vec![
                CallArg::Shared(SharedObjectRef {
                    object_id: ObjectID::DENY_LIST,
                    initial_shared_version: test_env.deny_list_object_init_version,
                    mutable: true,
                }),
                CallArg::ImmutableOrOwned(
                    test_env.get_latest_object_ref(&test_env.deny_cap_id).await,
                ),
                CallArg::pure(&owner),
            ],
        )
        .with_type_args(vec![test_env.regulated_coin_type.clone()])
        .build();
    let deny_tx = test_env.test_cluster.sign_transaction(&deny_data);
    test_env
        .test_cluster
        .wallet
        .execute_transaction_must_succeed(deny_tx)
        .await;

    // 3) Pick a validator and wait until it has observed the denial in its own
    //    object store, so the execution-time re-check is deterministic.
    let validator_state = test_env
        .test_cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .next()
        .unwrap()
        .with(|node| node.state());
    let coin_type_str = test_env.regulated_coin_type.to_canonical_string(false);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(cfg) =
                get_per_type_coin_deny_list_v1(&coin_type_str, &validator_state.get_object_store())
            {
                if check_address_denied_by_config(
                    &cfg,
                    owner,
                    &validator_state.get_object_store(),
                    None,
                ) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("validator never observed the denial");

    // 4) Execute the pre-denial certificate as an ATTESTED transaction. The sender
    //    is now denied → the deny-list re-check inside `prepare_certificate`
    //    returns `Err(AddressDeniedForCoin)`.
    let executable = VerifiedExecutableTransaction::new_from_certificate(
        VerifiedCertificate::new_unchecked(cert),
    );
    let attestation = Attestation::Validator {
        payload: AttestationData::V1 {
            estimated_computation_cost: 1_000_000,
            object_versions: vec![],
        },
        attestor_index: AuthorityIndex::new_for_test(0),
    };
    let attested = VerifiedExecutableAttestedTransaction::new(executable, Some(attestation));
    let epoch_store = validator_state.epoch_store_for_testing();
    let result = validator_state.try_execute_immediately(&attested, None, &epoch_store);

    // Confirm it is exactly the deny-list rejection, not an unrelated error.
    assert!(
        matches!(
            &result,
            Err(IotaError::UserInput {
                error: UserInputError::AddressDeniedForCoin { .. }
            })
        ),
        "expected AddressDeniedForCoin, got {result:?}",
    );

    // 5) Feed that real `Err` through the EXACT match from `execution_driver.rs`.
    //    `fatal!` is `panic!`, so this reproduces the node crash. The `sim_test`
    //    macro drops `#[should_panic]`, so we catch the panic explicitly and assert
    //    it fired (silencing its backtrace, which is expected).
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
        "expected the attested deny-listed tx to crash the validator via fatal!, but it did not",
    );
}
