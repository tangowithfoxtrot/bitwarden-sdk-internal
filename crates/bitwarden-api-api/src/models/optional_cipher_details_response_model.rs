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
pub struct OptionalCipherDetailsResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "unavailable", skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<bool>,
    #[serde(rename = "cipher", skip_serializing_if = "Option::is_none")]
    pub cipher: Option<Box<models::CipherDetailsResponseModel>>,
}

impl OptionalCipherDetailsResponseModel {
    pub fn new() -> OptionalCipherDetailsResponseModel {
        OptionalCipherDetailsResponseModel {
            object: None,
            unavailable: None,
            cipher: None,
        }
    }
}
