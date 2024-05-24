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
pub struct CipherMiniDetailsResponseModelListResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<models::CipherMiniDetailsResponseModel>>,
    #[serde(rename = "continuationToken", skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
}

impl CipherMiniDetailsResponseModelListResponseModel {
    pub fn new() -> CipherMiniDetailsResponseModelListResponseModel {
        CipherMiniDetailsResponseModelListResponseModel {
            object: None,
            data: None,
            continuation_token: None,
        }
    }
}
