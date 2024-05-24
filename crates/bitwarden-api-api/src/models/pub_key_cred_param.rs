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
pub struct PubKeyCredParam {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<models::PublicKeyCredentialType>,
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none")]
    pub alg: Option<models::Algorithm>,
}

impl PubKeyCredParam {
    pub fn new() -> PubKeyCredParam {
        PubKeyCredParam {
            r#type: None,
            alg: None,
        }
    }
}
