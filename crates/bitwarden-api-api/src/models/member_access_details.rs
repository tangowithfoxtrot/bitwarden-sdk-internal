/*
 * Bitwarden Internal API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: latest
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberAccessDetails {
    #[serde(rename = "collectionId", skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<uuid::Uuid>,
    #[serde(rename = "groupId", skip_serializing_if = "Option::is_none")]
    pub group_id: Option<uuid::Uuid>,
    #[serde(rename = "groupName", skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(rename = "collectionName", skip_serializing_if = "Option::is_none")]
    pub collection_name: Option<String>,
    #[serde(rename = "itemCount", skip_serializing_if = "Option::is_none")]
    pub item_count: Option<i32>,
    #[serde(rename = "readOnly", skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(rename = "hidePasswords", skip_serializing_if = "Option::is_none")]
    pub hide_passwords: Option<bool>,
    #[serde(rename = "manage", skip_serializing_if = "Option::is_none")]
    pub manage: Option<bool>,
    /// The CipherIds associated with the group/collection access
    #[serde(
        rename = "collectionCipherIds",
        skip_serializing_if = "Option::is_none"
    )]
    pub collection_cipher_ids: Option<Vec<String>>,
}

impl MemberAccessDetails {
    pub fn new() -> MemberAccessDetails {
        MemberAccessDetails {
            collection_id: None,
            group_id: None,
            group_name: None,
            collection_name: None,
            item_count: None,
            read_only: None,
            hide_passwords: None,
            manage: None,
            collection_cipher_ids: None,
        }
    }
}