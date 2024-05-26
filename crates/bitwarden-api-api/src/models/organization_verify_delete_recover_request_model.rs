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
pub struct OrganizationVerifyDeleteRecoverRequestModel {
    #[serde(rename = "token")]
    pub token: String,
}

impl OrganizationVerifyDeleteRecoverRequestModel {
    pub fn new(token: String) -> OrganizationVerifyDeleteRecoverRequestModel {
        OrganizationVerifyDeleteRecoverRequestModel { token }
    }
}