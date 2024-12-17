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
pub struct DropPasswordHealthReportApplicationRequest {
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<uuid::Uuid>,
    #[serde(
        rename = "passwordHealthReportApplicationIds",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_health_report_application_ids: Option<Vec<uuid::Uuid>>,
}

impl DropPasswordHealthReportApplicationRequest {
    pub fn new() -> DropPasswordHealthReportApplicationRequest {
        DropPasswordHealthReportApplicationRequest {
            organization_id: None,
            password_health_report_application_ids: None,
        }
    }
}