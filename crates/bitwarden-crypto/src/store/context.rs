use std::{
    cell::Cell,
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use rsa::Oaep;
use zeroize::Zeroizing;

use super::KeyStoreInner;
use crate::{
    derive_shareable_key, store::backend::StoreBackend, AsymmetricCryptoKey, AsymmetricEncString,
    CryptoError, EncString, KeyId, KeyIds, Result, SymmetricCryptoKey,
};

/// The context of a crypto operation using [super::KeyStore]
///
/// This will usually be accessed from an implementation of [crate::Decryptable] or
/// [crate::Encryptable], but can also be obtained through [super::KeyStore::context]
///
/// This context contains access to the user keys stored in the [super::KeyStore] (sometimes
/// referred to as `global keys`) and it also contains it's own individual secure backend for key
/// storage. Keys stored in this individual backend are usually referred to as `local keys`, they
/// will be cleared when this context goes out of scope and is dropped and they do not affect either
/// the global [super::KeyStore] or other instances of contexts.
///
/// This context-local storage is recommended for ephemeral and temporary keys that are decrypted
/// during the course of a decrypt/encrypt operation, but won't be used after the operation itself
/// is complete.
///
/// ```rust
/// # use bitwarden_crypto::*;
/// # key_ids! {
/// #     #[symmetric]
/// #     pub enum SymmKeyId {
/// #         User,
/// #         Local(&'static str),
/// #     }
/// #     #[asymmetric]
/// #     pub enum AsymmKeyId {
/// #         UserPrivate,
/// #     }
/// #     pub Ids => SymmKeyId, AsymmKeyId;
/// # }
/// struct Data {
///     key: EncString,
///     name: String,
/// }
/// # impl IdentifyKey<SymmKeyId> for Data {
/// #    fn key_identifier(&self) -> SymmKeyId {
/// #        SymmKeyId::User
/// #    }
/// # }
///
/// const LOCAL_KEY: SymmKeyId = SymmKeyId::Local("local_key_id");
///
/// impl Encryptable<Ids, SymmKeyId, EncString> for Data {
///     fn encrypt(&self, ctx: &mut KeyStoreContext<Ids>, key: SymmKeyId) -> Result<EncString, CryptoError> {
///         let local_key_id = ctx.decrypt_symmetric_key_with_symmetric_key(key, LOCAL_KEY, &self.key)?;
///         self.name.encrypt(ctx, local_key_id)
///     }
/// }
/// ```
#[must_use]
pub struct KeyStoreContext<'a, Ids: KeyIds> {
    pub(super) global_keys: GlobalKeys<'a, Ids>,

    pub(super) local_symmetric_keys: Box<dyn StoreBackend<Ids::Symmetric>>,
    pub(super) local_asymmetric_keys: Box<dyn StoreBackend<Ids::Asymmetric>>,

    // Make sure the context is !Send & !Sync
    pub(super) _phantom: std::marker::PhantomData<(Cell<()>, RwLockReadGuard<'static, ()>)>,
}

/// A KeyStoreContext is usually limited to a read only access to the global keys,
/// which allows us to have multiple read only contexts at the same time and do multitheaded
/// encryption/decryption. We also have the option to create a read/write context, which allows us
/// to modify the global keys, but only allows one context at a time. This is controlled by a
/// [std::sync::RwLock] on the global keys, and this struct stores both types of guards.
pub(crate) enum GlobalKeys<'a, Ids: KeyIds> {
    ReadOnly(RwLockReadGuard<'a, KeyStoreInner<Ids>>),
    ReadWrite(RwLockWriteGuard<'a, KeyStoreInner<Ids>>),
}

impl<Ids: KeyIds> GlobalKeys<'_, Ids> {
    pub fn get(&self) -> &KeyStoreInner<Ids> {
        match self {
            GlobalKeys::ReadOnly(keys) => keys,
            GlobalKeys::ReadWrite(keys) => keys,
        }
    }

    pub fn get_mut(&mut self) -> Result<&mut KeyStoreInner<Ids>> {
        match self {
            GlobalKeys::ReadOnly(_) => Err(CryptoError::ReadOnlyKeyStore),
            GlobalKeys::ReadWrite(keys) => Ok(keys),
        }
    }
}

impl<Ids: KeyIds> KeyStoreContext<'_, Ids> {
    /// Clears all the local keys stored in this context
    /// This will not affect the global keys even if this context has write access.
    /// To clear the global keys, you need to use [super::KeyStore::clear] instead.
    pub fn clear_local(&mut self) {
        self.local_symmetric_keys.clear();
        self.local_asymmetric_keys.clear();
    }

    /// Remove all symmetric keys from the context for which the predicate returns false
    /// This will also remove the keys from the global store if this context has write access
    pub fn retain_symmetric_keys(&mut self, f: fn(Ids::Symmetric) -> bool) {
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.symmetric_keys.retain(f);
        }
        self.local_symmetric_keys.retain(f);
    }

    /// Remove all asymmetric keys from the context for which the predicate returns false
    /// This will also remove the keys from the global store if this context has write access
    pub fn retain_asymmetric_keys(&mut self, f: fn(Ids::Asymmetric) -> bool) {
        if let Ok(keys) = self.global_keys.get_mut() {
            keys.asymmetric_keys.retain(f);
        }
        self.local_asymmetric_keys.retain(f);
    }

    // TODO: All these encrypt x key with x key look like they need to be made generic,
    // but I haven't found the best way to do that yet.

    /// Decrypt a symmetric key into the context by using an already existing symmetric key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to decrypt the `encrypted_key`. It must already exist
    ///   in the context
    /// * `new_key_id` - The key id where the decrypted key will be stored. If it already exists, it
    ///   will be overwritten
    /// * `encrypted_key` - The key to decrypt
    pub fn decrypt_symmetric_key_with_symmetric_key(
        &mut self,
        encryption_key: Ids::Symmetric,
        new_key_id: Ids::Symmetric,
        encrypted_key: &EncString,
    ) -> Result<Ids::Symmetric> {
        let mut new_key_material =
            self.decrypt_data_with_symmetric_key(encryption_key, encrypted_key)?;

        #[allow(deprecated)]
        self.set_symmetric_key(
            new_key_id,
            SymmetricCryptoKey::try_from(new_key_material.as_mut_slice())?,
        )?;

        // Returning the new key identifier for convenience
        Ok(new_key_id)
    }

    /// Encrypt and return a symmetric key from the context by using an already existing symmetric
    /// key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to encrypt the `key_to_encrypt`. It must already exist
    ///   in the context
    /// * `key_to_encrypt` - The key id to encrypt. It must already exist in the context
    pub fn encrypt_symmetric_key_with_symmetric_key(
        &self,
        encryption_key: Ids::Symmetric,
        key_to_encrypt: Ids::Symmetric,
    ) -> Result<EncString> {
        let key_to_encrypt = self.get_symmetric_key(key_to_encrypt)?;
        self.encrypt_data_with_symmetric_key(encryption_key, &key_to_encrypt.to_vec())
    }

    /// Decrypt a symmetric key into the context by using an already existing asymmetric key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to decrypt the `encrypted_key`. It must already exist
    ///   in the context
    /// * `new_key_id` - The key id where the decrypted key will be stored. If it already exists, it
    ///   will be overwritten
    /// * `encrypted_key` - The key to decrypt
    pub fn decrypt_symmetric_key_with_asymmetric_key(
        &mut self,
        encryption_key: Ids::Asymmetric,
        new_key_id: Ids::Symmetric,
        encrypted_key: &AsymmetricEncString,
    ) -> Result<Ids::Symmetric> {
        let mut new_key_material =
            self.decrypt_data_with_asymmetric_key(encryption_key, encrypted_key)?;

        #[allow(deprecated)]
        self.set_symmetric_key(
            new_key_id,
            SymmetricCryptoKey::try_from(new_key_material.as_mut_slice())?,
        )?;

        // Returning the new key identifier for convenience
        Ok(new_key_id)
    }

    /// Encrypt and return a symmetric key from the context by using an already existing asymmetric
    /// key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to encrypt the `key_to_encrypt`. It must already exist
    ///   in the context
    /// * `key_to_encrypt` - The key id to encrypt. It must already exist in the context
    pub fn encrypt_symmetric_key_with_asymmetric_key(
        &self,
        encryption_key: Ids::Asymmetric,
        key_to_encrypt: Ids::Symmetric,
    ) -> Result<AsymmetricEncString> {
        let key_to_encrypt = self.get_symmetric_key(key_to_encrypt)?;
        self.encrypt_data_with_asymmetric_key(encryption_key, &key_to_encrypt.to_vec())
    }

    /// Decrypt an asymmetric key into the context by using an already existing asymmetric key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to decrypt the `encrypted_key`. It must already exist
    ///   in the context
    /// * `new_key_id` - The key id where the decrypted key will be stored. If it already exists, it
    ///   will be overwritten
    /// * `encrypted_key` - The key to decrypt
    pub fn decrypt_asymmetric_key_with_asymmetric_key(
        &mut self,
        encryption_key: Ids::Asymmetric,
        new_key_id: Ids::Asymmetric,
        encrypted_key: &AsymmetricEncString,
    ) -> Result<Ids::Asymmetric> {
        let new_key_material =
            self.decrypt_data_with_asymmetric_key(encryption_key, encrypted_key)?;

        #[allow(deprecated)]
        self.set_asymmetric_key(
            new_key_id,
            AsymmetricCryptoKey::from_der(&new_key_material)?,
        )?;

        // Returning the new key identifier for convenience
        Ok(new_key_id)
    }

    /// Encrypt and return an asymmetric key from the context by using an already existing
    /// asymmetric key
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - The key id used to encrypt the `key_to_encrypt`. It must already exist
    ///   in the context
    /// * `key_to_encrypt` - The key id to encrypt. It must already exist in the context
    pub fn encrypt_asymmetric_key_with_asymmetric_key(
        &self,
        encryption_key: Ids::Asymmetric,
        key_to_encrypt: Ids::Asymmetric,
    ) -> Result<AsymmetricEncString> {
        let encryption_key = self.get_asymmetric_key(encryption_key)?;
        let key_to_encrypt = self.get_asymmetric_key(key_to_encrypt)?;

        AsymmetricEncString::encrypt_rsa2048_oaep_sha1(
            key_to_encrypt.to_der()?.as_slice(),
            encryption_key,
        )
    }

    /// Returns `true` if the context has a symmetric key with the given identifier
    pub fn has_symmetric_key(&self, key_id: Ids::Symmetric) -> bool {
        self.get_symmetric_key(key_id).is_ok()
    }

    /// Returns `true` if the context has an asymmetric key with the given identifier
    pub fn has_asymmetric_key(&self, key_id: Ids::Asymmetric) -> bool {
        self.get_asymmetric_key(key_id).is_ok()
    }

    /// Generate a new random symmetric key and store it in the context
    pub fn generate_symmetric_key(&mut self, key_id: Ids::Symmetric) -> Result<Ids::Symmetric> {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        #[allow(deprecated)]
        self.set_symmetric_key(key_id, key)?;
        Ok(key_id)
    }

    /// Derive a shareable key using hkdf from secret and name and store it in the context.
    ///
    /// A specialized variant of this function was called `CryptoService.makeSendKey` in the
    /// Bitwarden `clients` repository.
    pub fn derive_shareable_key(
        &mut self,
        key_id: Ids::Symmetric,
        secret: Zeroizing<[u8; 16]>,
        name: &str,
        info: Option<&str>,
    ) -> Result<Ids::Symmetric> {
        #[allow(deprecated)]
        self.set_symmetric_key(key_id, derive_shareable_key(secret, name, info))?;
        Ok(key_id)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn dangerous_get_symmetric_key(
        &self,
        key_id: Ids::Symmetric,
    ) -> Result<&SymmetricCryptoKey> {
        self.get_symmetric_key(key_id)
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn dangerous_get_asymmetric_key(
        &self,
        key_id: Ids::Asymmetric,
    ) -> Result<&AsymmetricCryptoKey> {
        self.get_asymmetric_key(key_id)
    }

    fn get_symmetric_key(&self, key_id: Ids::Symmetric) -> Result<&SymmetricCryptoKey> {
        if key_id.is_local() {
            self.local_symmetric_keys.get(key_id)
        } else {
            self.global_keys.get().symmetric_keys.get(key_id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{key_id:?}")))
    }

    fn get_asymmetric_key(&self, key_id: Ids::Asymmetric) -> Result<&AsymmetricCryptoKey> {
        if key_id.is_local() {
            self.local_asymmetric_keys.get(key_id)
        } else {
            self.global_keys.get().asymmetric_keys.get(key_id)
        }
        .ok_or_else(|| crate::CryptoError::MissingKeyId(format!("{key_id:?}")))
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn set_symmetric_key(
        &mut self,
        key_id: Ids::Symmetric,
        key: SymmetricCryptoKey,
    ) -> Result<()> {
        if key_id.is_local() {
            self.local_symmetric_keys.upsert(key_id, key);
        } else {
            self.global_keys
                .get_mut()?
                .symmetric_keys
                .upsert(key_id, key);
        }
        Ok(())
    }

    #[deprecated(note = "This function should ideally never be used outside this crate")]
    pub fn set_asymmetric_key(
        &mut self,
        key_id: Ids::Asymmetric,
        key: AsymmetricCryptoKey,
    ) -> Result<()> {
        if key_id.is_local() {
            self.local_asymmetric_keys.upsert(key_id, key);
        } else {
            self.global_keys
                .get_mut()?
                .asymmetric_keys
                .upsert(key_id, key);
        }
        Ok(())
    }

    pub(crate) fn decrypt_data_with_symmetric_key(
        &self,
        key: Ids::Symmetric,
        data: &EncString,
    ) -> Result<Vec<u8>> {
        let key = self.get_symmetric_key(key)?;

        match data {
            EncString::AesCbc256_B64 { iv, data } => {
                let dec = crate::aes::decrypt_aes256(iv, data.clone(), &key.key)?;
                Ok(dec)
            }
            EncString::AesCbc128_HmacSha256_B64 { iv, mac, data } => {
                // TODO: SymmetricCryptoKey is designed to handle 32 byte keys only, but this
                // variant uses a 16 byte key This means the key+mac are going to be
                // parsed as a single 32 byte key, at the moment we split it manually
                // When refactoring the key handling, this should be fixed.
                let enc_key = (&key.key[0..16]).into();
                let mac_key = (&key.key[16..32]).into();
                let dec = crate::aes::decrypt_aes128_hmac(iv, mac, data.clone(), mac_key, enc_key)?;
                Ok(dec)
            }
            EncString::AesCbc256_HmacSha256_B64 { iv, mac, data } => {
                let mac_key = key.mac_key.as_ref().ok_or(CryptoError::InvalidMac)?;
                let dec =
                    crate::aes::decrypt_aes256_hmac(iv, mac, data.clone(), mac_key, &key.key)?;
                Ok(dec)
            }
        }
    }

    pub(crate) fn encrypt_data_with_symmetric_key(
        &self,
        key: Ids::Symmetric,
        data: &[u8],
    ) -> Result<EncString> {
        let key = self.get_symmetric_key(key)?;
        EncString::encrypt_aes256_hmac(
            data,
            key.mac_key.as_ref().ok_or(CryptoError::InvalidMac)?,
            &key.key,
        )
    }

    pub(crate) fn decrypt_data_with_asymmetric_key(
        &self,
        key: Ids::Asymmetric,
        data: &AsymmetricEncString,
    ) -> Result<Vec<u8>> {
        let key = self.get_asymmetric_key(key)?;

        use AsymmetricEncString::*;
        match data {
            Rsa2048_OaepSha256_B64 { data } => key.key.decrypt(Oaep::new::<sha2::Sha256>(), data),
            Rsa2048_OaepSha1_B64 { data } => key.key.decrypt(Oaep::new::<sha1::Sha1>(), data),
            #[allow(deprecated)]
            Rsa2048_OaepSha256_HmacSha256_B64 { data, .. } => {
                key.key.decrypt(Oaep::new::<sha2::Sha256>(), data)
            }
            #[allow(deprecated)]
            Rsa2048_OaepSha1_HmacSha256_B64 { data, .. } => {
                key.key.decrypt(Oaep::new::<sha1::Sha1>(), data)
            }
        }
        .map_err(|_| CryptoError::KeyDecrypt)
    }

    pub(crate) fn encrypt_data_with_asymmetric_key(
        &self,
        key: Ids::Asymmetric,
        data: &[u8],
    ) -> Result<AsymmetricEncString> {
        let key = self.get_asymmetric_key(key)?;
        AsymmetricEncString::encrypt_rsa2048_oaep_sha1(data, key)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::{
        store::{tests::DataView, KeyStore},
        traits::tests::{TestIds, TestSymmKey},
        Decryptable, Encryptable, SymmetricCryptoKey,
    };

    #[test]
    fn test_set_keys_for_encryption() {
        let mut rng = rand::thread_rng();
        let store: KeyStore<TestIds> = KeyStore::default();

        // Generate and insert a key
        let key_a0_id = TestSymmKey::A(0);
        let key_a0 = SymmetricCryptoKey::generate(&mut rng);

        store
            .context_mut()
            .set_symmetric_key(TestSymmKey::A(0), key_a0.clone())
            .unwrap();

        assert!(store.context().has_symmetric_key(key_a0_id));

        // Encrypt some data with the key
        let data = DataView("Hello, World!".to_string(), key_a0_id);
        let _encrypted = data.encrypt(&mut store.context(), key_a0_id).unwrap();
    }

    #[test]
    fn test_key_encryption() {
        let mut rng = rand::thread_rng();
        let store: KeyStore<TestIds> = KeyStore::default();

        let mut ctx = store.context();

        // Generate and insert a key
        let key_1_id = TestSymmKey::C(1);
        let key_1 = SymmetricCryptoKey::generate(&mut rng);

        ctx.set_symmetric_key(key_1_id, key_1.clone()).unwrap();

        assert!(ctx.has_symmetric_key(key_1_id));

        // Generate and insert a new key
        let key_2_id = TestSymmKey::C(2);
        let key_2 = SymmetricCryptoKey::generate(&mut rng);

        ctx.set_symmetric_key(key_2_id, key_2.clone()).unwrap();

        assert!(ctx.has_symmetric_key(key_2_id));

        // Encrypt the new key with the old key
        let key_2_enc = ctx
            .encrypt_symmetric_key_with_symmetric_key(key_1_id, key_2_id)
            .unwrap();

        // Decrypt the new key with the old key in a different identifier
        let new_key_id = TestSymmKey::C(3);

        ctx.decrypt_symmetric_key_with_symmetric_key(key_1_id, new_key_id, &key_2_enc)
            .unwrap();

        // Now `key_2_id` and `new_key_id` contain the same key, so we should be able to encrypt
        // with one and decrypt with the other

        let data = DataView("Hello, World!".to_string(), key_2_id);
        let encrypted = data.encrypt(&mut ctx, key_2_id).unwrap();

        let decrypted1 = encrypted.decrypt(&mut ctx, key_2_id).unwrap();
        let decrypted2 = encrypted.decrypt(&mut ctx, new_key_id).unwrap();

        // Assert that the decrypted data is the same
        assert_eq!(decrypted1.0, decrypted2.0);
    }
}
