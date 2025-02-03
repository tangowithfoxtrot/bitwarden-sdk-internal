use std::path::Path;

use bitwarden_core::Client;
use bitwarden_crypto::{EncString, KeyDecryptable, KeyEncryptable, LocateKey};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{
    Attachment, AttachmentEncryptResult, AttachmentFile, AttachmentFileView, AttachmentView,
    Cipher, DecryptError, EncryptError, VaultClient,
};

pub struct ClientAttachments<'a> {
    pub(crate) client: &'a Client,
}

/// Generic error type for vault encryption errors.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EncryptFileError {
    #[error(transparent)]
    Encrypt(#[from] EncryptError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Generic error type for decryption errors
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptFileError {
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ClientAttachments<'_> {
    pub fn encrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        buffer: &[u8],
    ) -> Result<AttachmentEncryptResult, EncryptError> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = cipher.locate_key(&enc, &None)?;

        Ok(AttachmentFileView {
            cipher,
            attachment,
            contents: buffer,
        }
        .encrypt_with_key(key)?)
    }
    pub fn encrypt_file(
        &self,
        cipher: Cipher,
        attachment: AttachmentView,
        decrypted_file_path: &Path,
        encrypted_file_path: &Path,
    ) -> Result<Attachment, EncryptFileError> {
        let data = std::fs::read(decrypted_file_path)?;
        let AttachmentEncryptResult {
            attachment,
            contents,
        } = self.encrypt_buffer(cipher, attachment, &data)?;
        std::fs::write(encrypted_file_path, contents)?;
        Ok(attachment)
    }

    pub fn decrypt_buffer(
        &self,
        cipher: Cipher,
        attachment: Attachment,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = cipher.locate_key(&enc, &None)?;

        Ok(AttachmentFile {
            cipher,
            attachment,
            contents: EncString::from_buffer(encrypted_buffer)?,
        }
        .decrypt_with_key(key)?)
    }
    pub fn decrypt_file(
        &self,
        cipher: Cipher,
        attachment: Attachment,
        encrypted_file_path: &Path,
        decrypted_file_path: &Path,
    ) -> Result<(), DecryptFileError> {
        let data = std::fs::read(encrypted_file_path)?;
        let decrypted = self.decrypt_buffer(cipher, attachment, &data)?;
        std::fs::write(decrypted_file_path, decrypted)?;
        Ok(())
    }
}

impl<'a> VaultClient<'a> {
    pub fn attachments(&'a self) -> ClientAttachments<'a> {
        ClientAttachments {
            client: self.client,
        }
    }
}
