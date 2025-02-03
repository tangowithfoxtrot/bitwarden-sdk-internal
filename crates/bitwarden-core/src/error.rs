//! Errors that can occur when using this SDK

use std::{borrow::Cow, fmt::Debug};

use bitwarden_api_api::apis::Error as ApiApisError;
use bitwarden_api_identity::apis::Error as IdentityError;
use bitwarden_error::bitwarden_error;
use reqwest::StatusCode;
use thiserror::Error;

use crate::client::encryption_settings::EncryptionSettingsError;

#[bitwarden_error(flat, export_as = "CoreError")]
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    MissingFieldError(#[from] MissingFieldError),
    #[error(transparent)]
    VaultLocked(#[from] VaultLocked),
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),

    #[error("Access token is not in a valid format: {0}")]
    AccessTokenInvalid(#[from] AccessTokenInvalidError),

    #[error("The response received was invalid and could not be processed")]
    InvalidResponse,

    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    #[error("Error parsing Identity response: {0}")]
    IdentityFail(crate::auth::api::response::IdentityTokenFailResponse),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),

    #[error("Received error message from server: [{}] {}", .status, .message)]
    ResponseContent { status: StatusCode, message: String },

    #[error("The state file version is invalid")]
    InvalidStateFileVersion,

    #[error("The state file could not be read")]
    InvalidStateFile,

    #[error("Internal error: {0}")]
    Internal(Cow<'static, str>),

    #[error(transparent)]
    EncryptionSettings(#[from] EncryptionSettingsError),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Internal(s.into())
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self::Internal(s.into())
    }
}

#[derive(Debug, Error)]
pub enum AccessTokenInvalidError {
    #[error("Doesn't contain a decryption key")]
    NoKey,
    #[error("Has the wrong number of parts")]
    WrongParts,
    #[error("Is the wrong version")]
    WrongVersion,
    #[error("Has an invalid identifier")]
    InvalidUuid,

    #[error("Error decoding base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("Invalid base64 length: expected {expected}, got {got}")]
    InvalidBase64Length { expected: usize, got: usize },
}

// Ensure that the error messages implement Send and Sync
#[cfg(test)]
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn assert_all() {
        assert_send::<Error>();
        assert_sync::<Error>();
    }
};

macro_rules! impl_bitwarden_error {
    ($name:ident, $error:ident) => {
        impl<T> From<$name<T>> for $error {
            fn from(e: $name<T>) -> Self {
                match e {
                    $name::Reqwest(e) => Self::Reqwest(e),
                    $name::ResponseError(e) => Self::ResponseContent {
                        status: e.status,
                        message: e.content,
                    },
                    $name::Serde(e) => Self::Serde(e),
                    $name::Io(e) => Self::Io(e),
                }
            }
        }
    };
}
impl_bitwarden_error!(ApiApisError, Error);
impl_bitwarden_error!(IdentityError, Error);

#[derive(Debug, Error)]
pub enum ApiError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Received error message from server: [{}] {}", .status, .message)]
    ResponseContent { status: StatusCode, message: String },
}

impl_bitwarden_error!(ApiApisError, ApiError);

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
#[error("The client is not authenticated or the session has expired")]
pub struct NotAuthenticatedError;

#[derive(Debug, Error)]
#[error("The response received was missing a required field: {0}")]
pub struct MissingFieldError(pub &'static str);

#[derive(Debug, Error)]
#[error("The client vault is locked and needs to be unlocked before use")]
pub struct VaultLocked;

/// This macro is used to require that a value is present or return an error otherwise.
/// It is equivalent to using `val.ok_or(Error::MissingFields)?`, but easier to use and
/// with a more descriptive error message.
/// Note that this macro will return early from the function if the value is not present.
#[macro_export]
macro_rules! require {
    ($val:expr) => {
        match $val {
            Some(val) => val,
            None => return Err($crate::MissingFieldError(stringify!($val)).into()),
        }
    };
}
