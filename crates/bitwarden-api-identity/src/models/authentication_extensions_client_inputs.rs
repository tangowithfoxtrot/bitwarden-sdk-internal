/*
 * Bitwarden Identity
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(rename = "example.extension", skip_serializing_if = "Option::is_none")]
    pub example_period_extension: Option<serde_json::Value>,
    #[serde(rename = "appid", skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    #[serde(rename = "authnSel", skip_serializing_if = "Option::is_none")]
    pub authn_sel: Option<Vec<String>>,
    #[serde(rename = "exts", skip_serializing_if = "Option::is_none")]
    pub exts: Option<bool>,
    #[serde(rename = "uvm", skip_serializing_if = "Option::is_none")]
    pub uvm: Option<bool>,
}

impl AuthenticationExtensionsClientInputs {
    pub fn new() -> AuthenticationExtensionsClientInputs {
        AuthenticationExtensionsClientInputs {
            example_period_extension: None,
            appid: None,
            authn_sel: None,
            exts: None,
            uvm: None,
        }
    }
}
