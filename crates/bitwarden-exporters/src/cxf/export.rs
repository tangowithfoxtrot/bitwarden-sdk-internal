use bitwarden_vault::{Totp, TotpAlgorithm};
use credential_exchange_types::format::{
    Account as CxfAccount, Credential, Item, ItemType, NoteCredential, OTPHashAlgorithm,
    TotpCredential,
};
use uuid::Uuid;

use crate::{cxf::CxfError, Cipher, CipherType, Login};

/// Temporary struct to hold metadata related to current account
///
/// Eventually the SDK itself should have this state and we get rid of this struct.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Account {
    id: Uuid,
    email: String,
    name: Option<String>,
}

/// Builds a Credential Exchange Format (CXF) payload
pub(crate) fn build_cxf(account: Account, ciphers: Vec<Cipher>) -> Result<String, CxfError> {
    let items: Vec<Item> = ciphers
        .into_iter()
        .flat_map(|cipher| cipher.try_into())
        .collect();

    let account = CxfAccount {
        id: account.id.as_bytes().as_slice().into(),
        user_name: "".to_owned(),
        email: account.email,
        full_name: account.name,
        icon: None,
        collections: vec![], // TODO: Add support for folders
        items,
        extensions: None,
    };

    Ok(serde_json::to_string(&account)?)
}

impl TryFrom<Cipher> for Item {
    type Error = CxfError;

    fn try_from(value: Cipher) -> Result<Self, Self::Error> {
        let mut credentials: Vec<Credential> = value.r#type.clone().into();

        if let Some(note) = value.notes {
            credentials.push(Credential::Note(Box::new(NoteCredential { content: note })));
        }

        Ok(Self {
            id: value.id.as_bytes().as_slice().into(),
            creation_at: Some(value.creation_date.timestamp() as u64),
            modified_at: Some(value.revision_date.timestamp() as u64),
            ty: value.r#type.try_into()?,
            title: value.name,
            subtitle: None,
            favorite: Some(value.favorite),
            credentials,
            tags: None,
            extensions: None,
        })
    }
}

impl TryFrom<CipherType> for ItemType {
    type Error = CxfError;

    fn try_from(value: CipherType) -> Result<Self, Self::Error> {
        match value {
            CipherType::Login(_) => Ok(ItemType::Login),
            CipherType::Card(_) => Ok(ItemType::Identity),
            CipherType::Identity(_) => Ok(ItemType::Identity),
            CipherType::SecureNote(_) => Ok(ItemType::Document),
            CipherType::SshKey(_) => {
                // TODO(PM-15448): Add support for SSH Keys
                Err(CxfError::Internal("Unsupported CipherType: SshKey".into()))
            }
        }
    }
}

impl From<CipherType> for Vec<Credential> {
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Login(login) => (*login).into(),
            // TODO(PM-15450): Add support for credit cards.
            CipherType::Card(card) => (*card).into(),
            // TODO(PM-15451): Add support for identities.
            CipherType::Identity(_) => vec![],
            // Secure Notes only contains a note field which is handled by `TryFrom<Cipher> for
            // Item`.
            CipherType::SecureNote(_) => vec![],
            // TODO(PM-15448): Add support for SSH Keys.
            CipherType::SshKey(_) => vec![],
        }
    }
}

/// Convert a `Login` struct into the appropriate `Credential`s.
impl From<Login> for Vec<Credential> {
    fn from(login: Login) -> Self {
        let mut credentials = vec![];

        if login.username.is_some() || login.password.is_some() || !login.login_uris.is_empty() {
            credentials.push(Credential::BasicAuth(Box::new(login.clone().into())));
        }

        if let Some(totp) = login.totp.and_then(|t| t.parse::<Totp>().ok()) {
            credentials.push(Credential::Totp(Box::new(convert_totp(totp))));
        }

        if let Some(fido2_credentials) = login.fido2_credentials {
            credentials.extend(
                fido2_credentials
                    .into_iter()
                    .filter_map(|fido2_credential| fido2_credential.try_into().ok())
                    .map(|c| Credential::Passkey(Box::new(c))),
            );
        }

        credentials
    }
}

/// Convert a `Totp` struct into a `TotpCredential` struct
fn convert_totp(totp: Totp) -> TotpCredential {
    // TODO(PM-15389): Properly set username/issuer.
    TotpCredential {
        secret: totp.secret.into(),
        period: totp.period as u8,
        digits: totp.digits as u8,
        username: "".to_string(),
        algorithm: match totp.algorithm {
            TotpAlgorithm::Sha1 => OTPHashAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => OTPHashAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => OTPHashAlgorithm::Sha512,
            TotpAlgorithm::Steam => OTPHashAlgorithm::Unknown("steam".to_string()),
        },
        issuer: None,
    }
}

#[cfg(test)]
mod tests {
    use credential_exchange_types::format::FieldType;

    use super::*;
    use crate::{Fido2Credential, Field, LoginUri};

    #[test]
    fn test_convert_totp() {
        let totp = Totp {
            algorithm: TotpAlgorithm::Sha1,
            digits: 4,
            period: 60,
            secret: "secret".as_bytes().to_vec(),
        };

        let credential = convert_totp(totp);
        assert_eq!(String::from(credential.secret), "ONSWG4TFOQ");
        assert_eq!(credential.period, 60);
        assert_eq!(credential.digits, 4);
        assert_eq!(credential.username, "");
        assert_eq!(credential.algorithm, OTPHashAlgorithm::Sha1);
        assert_eq!(credential.issuer, None);
    }

    #[test]
    fn test_login_to_item() {
        let cipher = Cipher {
            id: "25c8c414-b446-48e9-a1bd-b10700bbd740".parse().unwrap(),
            folder_id: Some("942e2984-1b9a-453b-b039-b107012713b9".parse().unwrap()),

            name: "Bitwarden".to_string(),
            notes: Some("My note".to_string()),

            r#type: CipherType::Login(Box::new(Login {
                username: Some("test@bitwarden.com".to_string()),
                password: Some("asdfasdfasdf".to_string()),
                login_uris: vec![LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None,
                }],
                totp: Some("JBSWY3DPEHPK3PXP".to_string()),
                fido2_credentials: Some(vec![Fido2Credential {
                    credential_id: "e8d88789-e916-e196-3cbd-81dafae71bbc".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "AAECAwQFBg".to_string(),
                    rp_id: "123".to_string(),
                    user_handle: Some("AAECAwQFBg".to_string()),
                    user_name: None,
                    counter: 0,
                    rp_name: None,
                    user_display_name: None,
                    discoverable: "true".to_string(),
                    creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
                }]),
            })),

            favorite: true,
            reprompt: 0,

            fields: vec![
                Field {
                    name: Some("Text".to_string()),
                    value: Some("A".to_string()),
                    r#type: 0,
                    linked_id: None,
                },
                Field {
                    name: Some("Hidden".to_string()),
                    value: Some("B".to_string()),
                    r#type: 1,
                    linked_id: None,
                },
                Field {
                    name: Some("Boolean (true)".to_string()),
                    value: Some("true".to_string()),
                    r#type: 2,
                    linked_id: None,
                },
                Field {
                    name: Some("Boolean (false)".to_string()),
                    value: Some("false".to_string()),
                    r#type: 2,
                    linked_id: None,
                },
                Field {
                    name: Some("Linked".to_string()),
                    value: None,
                    r#type: 3,
                    linked_id: Some(101),
                },
            ],

            revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
            deleted_date: None,
        };

        let item: Item = cipher.try_into().unwrap();

        assert_eq!(item.id.to_string(), "JcjEFLRGSOmhvbEHALvXQA");
        assert_eq!(item.creation_at, Some(1706613834));
        assert_eq!(item.modified_at, Some(1706623773));
        assert_eq!(item.ty, ItemType::Login);
        assert_eq!(item.title, "Bitwarden");
        assert_eq!(item.subtitle, None);
        assert_eq!(item.tags, None);
        assert!(item.extensions.is_none());

        assert_eq!(item.credentials.len(), 4);

        let credential = &item.credentials[0];

        match credential {
            Credential::BasicAuth(basic_auth) => {
                let username = basic_auth.username.as_ref().unwrap();
                assert_eq!(username.field_type, FieldType::String);
                assert_eq!(username.value, "test@bitwarden.com");
                assert!(username.label.is_none());

                let password = basic_auth.password.as_ref().unwrap();
                assert_eq!(password.field_type, FieldType::ConcealedString);
                assert_eq!(password.value, "asdfasdfasdf");
                assert!(password.label.is_none());

                assert_eq!(
                    basic_auth.urls,
                    vec!["https://vault.bitwarden.com".to_string()]
                );
            }
            _ => panic!("Expected Credential::BasicAuth"),
        }

        let credential = &item.credentials[1];

        match credential {
            Credential::Totp(totp) => {
                assert_eq!(String::from(totp.secret.clone()), "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.period, 30);
                assert_eq!(totp.digits, 6);
                assert_eq!(totp.username, "");
                assert_eq!(totp.algorithm, OTPHashAlgorithm::Sha1);
                assert!(totp.issuer.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[2];

        match credential {
            Credential::Passkey(passkey) => {
                assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
                assert_eq!(passkey.rp_id, "123");
                assert_eq!(passkey.user_name, "");
                assert_eq!(passkey.user_display_name, "");
                assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
                assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
                assert!(passkey.fido2_extensions.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[3];

        match credential {
            Credential::Note(n) => {
                assert_eq!(n.content, "My note");
            }
            _ => panic!("Expected Credential::Passkey"),
        }
    }
}
