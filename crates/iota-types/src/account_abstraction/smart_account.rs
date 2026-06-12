// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk_types::ObjectId;
use move_core_types::{ident_str, identifier::IdentStr, language_storage::StructTag};
use serde::{Deserialize, Serialize};

use crate::{
    IOTA_FRAMEWORK_ADDRESS,
    id::UID,
    object::{MoveObject, OBJECT_START_VERSION},
};

pub const SMART_ACCOUNT_MODULE_NAME: &IdentStr = ident_str!("smart_account");
pub const SMART_ACCOUNT_STRUCT_NAME: &IdentStr = ident_str!("SmartAccount");

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SmartAccount {
    pub id: UID,
}

impl SmartAccount {
    pub fn new(id: ObjectId) -> Self {
        Self { id: UID::new(id) }
    }

    pub fn tag() -> StructTag {
        StructTag {
            address: IOTA_FRAMEWORK_ADDRESS,
            module: SMART_ACCOUNT_MODULE_NAME.to_owned(),
            name: SMART_ACCOUNT_STRUCT_NAME.to_owned(),
            type_params: Vec::new(),
        }
    }

    pub fn to_bcs_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self).unwrap()
    }

    pub fn to_object(self) -> MoveObject {
        MoveObject::new_from_execution_with_limit(
            Self::tag().into(),
            OBJECT_START_VERSION,
            bcs::to_bytes(&self).expect("should serialize a SmartAccount into bytes"),
            254,
        )
        .expect("should not overcome the move objects size limits")
    }
}
