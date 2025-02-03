//!
//! This module contains all the necessary parts to create an in-memory key store that can be used
//! to securely store key and use them for encryption/decryption operations.
//!
//! ## Organization
//!
//! ### Key Identifiers
//! To avoid having to pass key materials over the crate boundaries, the key store API uses key
//! identifiers in its API. These key identifiers are user-defined types that contain no key
//! material, and are used to uniquely identify each key in the store. The key store doesn't specify
//! how these traits should be implemented, but we recommend using `enums`, and we provide an
//! optional macro ([key_ids](crate::key_ids)) that makes it easier to define them.
//!
//! ### Key Store
//! [KeyStore] is a thread-safe in-memory key store and the main entry point for using this module.
//! It provides functionality to encrypt and decrypt data using the keys stored in the store. The
//! store is designed to be used by a single user and should not be shared between users.
//!
//! ### Key Store Context
//! From a [KeyStore], you can also create an instance of [KeyStoreContext], which initializes a
//! temporary context-local key store for encryption/decryption operations that require the use of
//! per-item keys (like cipher keys or send keys, for example). Any keys stored in the context-local
//! store will be cleared when the context is dropped.

use std::sync::{Arc, RwLock};

use rayon::prelude::*;

use crate::{Decryptable, Encryptable, IdentifyKey, KeyId, KeyIds};

mod backend;
mod context;

use backend::{create_store, StoreBackend};
use context::GlobalKeys;
pub use context::KeyStoreContext;

/// An in-memory key store that provides a safe and secure way to store keys and use them for
/// encryption/decryption operations. The store API is designed to work only on key identifiers
/// ([KeyId]). These identifiers are user-defined types that contain no key material, which means
/// the API users don't have to worry about accidentally leaking keys.
///
/// Each store is designed to be used by a single user and should not be shared between users, but
/// the store itself is thread safe and can be cloned to share between threads.
///
/// ```rust
/// # use bitwarden_crypto::*;
///
/// // We need to define our own key identifier types. We provide a macro to make this easier.
/// key_ids! {
///     #[symmetric]
///     pub enum SymmKeyId {
///         User,
///         #[local]
///         Local(&'static str)
///     }
///     #[asymmetric]
///     pub enum AsymmKeyId {
///         UserPrivate,
///     }
///     pub Ids => SymmKeyId, AsymmKeyId;
/// }
///
/// // Initialize the store and insert a test key
/// let store: KeyStore<Ids> = KeyStore::default();
///
/// #[allow(deprecated)]
/// store.context_mut().set_symmetric_key(SymmKeyId::User, SymmetricCryptoKey::generate(rand::thread_rng()));
///
/// // Define some data that needs to be encrypted
/// struct Data(String);
/// impl IdentifyKey<SymmKeyId> for Data {
///    fn key_identifier(&self) -> SymmKeyId {
///        SymmKeyId::User
///    }
/// }
/// impl Encryptable<Ids, SymmKeyId, EncString> for Data {
///     fn encrypt(&self, ctx: &mut KeyStoreContext<Ids>, key: SymmKeyId) -> Result<EncString, CryptoError> {
///         self.0.encrypt(ctx, key)
///     }
/// }
///
/// // Encrypt the data
/// let decrypted = Data("Hello, World!".to_string());
/// let encrypted = store.encrypt(decrypted).unwrap();
/// ```
#[derive(Clone)]
pub struct KeyStore<Ids: KeyIds> {
    // We use an Arc<> to make it easier to pass this store around, as we can
    // clone it instead of passing references
    inner: Arc<RwLock<KeyStoreInner<Ids>>>,
}

/// [KeyStore] contains sensitive data, provide a dummy [Debug] implementation.
impl<Ids: KeyIds> std::fmt::Debug for KeyStore<Ids> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish()
    }
}

struct KeyStoreInner<Ids: KeyIds> {
    symmetric_keys: Box<dyn StoreBackend<Ids::Symmetric>>,
    asymmetric_keys: Box<dyn StoreBackend<Ids::Asymmetric>>,
}

/// Create a new key store with the best available implementation for the current platform.
impl<Ids: KeyIds> Default for KeyStore<Ids> {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(KeyStoreInner {
                symmetric_keys: create_store(),
                asymmetric_keys: create_store(),
            })),
        }
    }
}

impl<Ids: KeyIds> KeyStore<Ids> {
    /// Clear all keys from the store. This can be used to clear all keys from memory in case of
    /// lock/logout, and is equivalent to destroying the store and creating a new one.
    pub fn clear(&self) {
        let mut keys = self.inner.write().expect("RwLock is poisoned");
        keys.symmetric_keys.clear();
        keys.asymmetric_keys.clear();
    }

    /// <div class="warning">
    /// This is an advanced API, use with care. If you still need to use it, make sure you read this
    /// documentation to understand how to use it safely. </div>
    ///
    /// Initiate an encryption/decryption context. This context will have read only access to the
    /// global keys, and will have its own local key stores with read/write access. This
    /// context-local store will be cleared up when the context is dropped.
    ///
    /// Some possible use cases for this API and alternative recommendations are:
    /// - Decrypting one or more [crate::EncString]s directly. This was the pattern before the
    ///   introduction of  the [Encryptable] and [Decryptable] traits, but is now considered
    ///   obsolete. We recommend wrapping the values in a struct that implements these traits
    ///   instead, and then using [KeyStore::encrypt], [KeyStore::decrypt], [KeyStore::encrypt_list]
    ///   and [KeyStore::decrypt_list].
    /// - Decrypting or encrypting multiple [Decryptable] or [Encryptable] items while sharing any
    ///   local keys. This is not recommended as it can lead to fragile and flaky
    ///   decryption/encryption operations. We recommend any local keys to be used only in the
    ///   context of a single [Encryptable] or [Decryptable] implementation. In the future we might
    ///   enforce this.
    /// - Obtaining the key material directly. We strongly recommend against doing this as it can
    ///   lead to key material being leaked, but we need to support it for backwards compatibility.
    ///   If you want to access the key material to encrypt it or derive a new key from it, we
    ///   provide functions for that:
    ///     - [KeyStoreContext::encrypt_symmetric_key_with_symmetric_key]
    ///     - [KeyStoreContext::encrypt_symmetric_key_with_asymmetric_key]
    ///     - [KeyStoreContext::encrypt_asymmetric_key_with_asymmetric_key]
    ///     - [KeyStoreContext::derive_shareable_key]
    /// - Some other minor and safe operations, like checking if a key exists. This is not exposed
    ///   in the [KeyStore] directly as we haven't seen many use cases for it, but we can add it if
    ///   needed.
    ///
    /// One of the pitfalls of the current implementations is that keys stored in the context-local
    /// store only get cleared automatically when the context is dropped, and not between
    /// operations. This means that if you are using the same context for multiple operations,
    /// you may want to clear it manually between them.
    pub fn context(&'_ self) -> KeyStoreContext<'_, Ids> {
        KeyStoreContext {
            global_keys: GlobalKeys::ReadOnly(self.inner.read().expect("RwLock is poisoned")),
            local_symmetric_keys: create_store(),
            local_asymmetric_keys: create_store(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// <div class="warning">
    /// This is an advanced API, use with care and ONLY when needing to modify the global keys.
    ///
    /// The same pitfalls as [Self::context] apply here, but with the added risk of accidentally
    /// modifying the global keys and leaving the store in an inconsistent state.
    /// If you still need to use it, make sure you read this documentation to understand how to use
    /// it safely. </div>
    ///
    /// Initiate an encryption/decryption context. This context will have MUTABLE access to the
    /// global keys, and will have its own local key stores with read/write access. This
    /// context-local store will be cleared up when the context is dropped.
    ///
    /// The only supported use case for this API is initializing the store with the user's symetric
    /// and private keys, and setting the organization keys. This method will be marked as
    /// `pub(crate)` in the future, once we have a safe API for key initialization and updating.
    pub fn context_mut(&'_ self) -> KeyStoreContext<'_, Ids> {
        KeyStoreContext {
            global_keys: GlobalKeys::ReadWrite(self.inner.write().expect("RwLock is poisoned")),
            local_symmetric_keys: create_store(),
            local_asymmetric_keys: create_store(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Decript a single item using this key store. The key returned by `data.key_identifier()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item decryption.
    /// If you need to decrypt multiple items, use `decrypt_list` instead.
    pub fn decrypt<Key: KeyId, Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key>, Output>(
        &self,
        data: &Data,
    ) -> Result<Output, crate::CryptoError> {
        let key = data.key_identifier();
        data.decrypt(&mut self.context(), key)
    }

    /// Encrypt a single item using this key store. The key returned by `data.key_identifier()` must
    /// already be present in the store, otherwise this will return an error.
    /// This method is not parallelized, and is meant for single item encryption.
    /// If you need to encrypt multiple items, use `encrypt_list` instead.
    pub fn encrypt<Key: KeyId, Data: Encryptable<Ids, Key, Output> + IdentifyKey<Key>, Output>(
        &self,
        data: Data,
    ) -> Result<Output, crate::CryptoError> {
        let key = data.key_identifier();
        data.encrypt(&mut self.context(), key)
    }

    /// Decrypt a list of items using this key store. The keys returned by
    /// `data[i].key_identifier()` must already be present in the store, otherwise this will
    /// return an error. This method will try to parallelize the decryption of the items, for
    /// better performance on large lists.
    pub fn decrypt_list<
        Key: KeyId,
        Data: Decryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync,
        Output: Send + Sync,
    >(
        &self,
        data: &[Data],
    ) -> Result<Vec<Output>, crate::CryptoError> {
        let res: Result<Vec<_>, _> = data
            .par_chunks(batch_chunk_size(data.len()))
            .map(|chunk| {
                let mut ctx = self.context();

                let mut result = Vec::with_capacity(chunk.len());

                for item in chunk {
                    let key = item.key_identifier();
                    result.push(item.decrypt(&mut ctx, key));
                    ctx.clear_local();
                }

                result
            })
            .flatten()
            .collect();

        res
    }

    /// Encrypt a list of items using this key store. The keys returned by
    /// `data[i].key_identifier()` must already be present in the store, otherwise this will
    /// return an error. This method will try to parallelize the encryption of the items, for
    /// better performance on large lists. This method is not parallelized, and is meant for
    /// single item encryption.
    pub fn encrypt_list<
        Key: KeyId,
        Data: Encryptable<Ids, Key, Output> + IdentifyKey<Key> + Send + Sync,
        Output: Send + Sync,
    >(
        &self,
        data: &[Data],
    ) -> Result<Vec<Output>, crate::CryptoError> {
        let res: Result<Vec<_>, _> = data
            .par_chunks(batch_chunk_size(data.len()))
            .map(|chunk| {
                let mut ctx = self.context();

                let mut result = Vec::with_capacity(chunk.len());

                for item in chunk {
                    let key = item.key_identifier();
                    result.push(item.encrypt(&mut ctx, key));
                    ctx.clear_local();
                }

                result
            })
            .flatten()
            .collect();

        res
    }
}

/// Calculate the optimal chunk size for parallelizing encryption/decryption operations.
fn batch_chunk_size(len: usize) -> usize {
    // In an optimal scenario with no overhead, we would split the data evenly between
    // all available threads, rounding up to the nearest integer.
    let items_per_thread = usize::div_ceil(len, rayon::current_num_threads());

    // Because the addition of each chunk has some overhead (e.g. creating a new context, thread
    // synchronization), we want to split the data into chunks that are large enough to amortize
    // this overhead, but not too large that we get no benefit from multithreading. We've chosen
    // a value more or less arbitrarily, but it seems to work well in practice.
    const MINIMUM_CHUNK_SIZE: usize = 50;

    // As a result, we pick whichever of the two values is larger.
    usize::max(items_per_thread, MINIMUM_CHUNK_SIZE)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        store::{KeyStore, KeyStoreContext},
        traits::tests::{TestIds, TestSymmKey},
        EncString, SymmetricCryptoKey,
    };

    pub struct DataView(pub String, pub TestSymmKey);
    pub struct Data(pub EncString, pub TestSymmKey);

    impl crate::IdentifyKey<TestSymmKey> for DataView {
        fn key_identifier(&self) -> TestSymmKey {
            self.1
        }
    }

    impl crate::IdentifyKey<TestSymmKey> for Data {
        fn key_identifier(&self) -> TestSymmKey {
            self.1
        }
    }

    impl crate::Encryptable<TestIds, TestSymmKey, Data> for DataView {
        fn encrypt(
            &self,
            ctx: &mut KeyStoreContext<TestIds>,
            key: TestSymmKey,
        ) -> Result<Data, crate::CryptoError> {
            Ok(Data(self.0.encrypt(ctx, key)?, key))
        }
    }

    impl crate::Decryptable<TestIds, TestSymmKey, DataView> for Data {
        fn decrypt(
            &self,
            ctx: &mut KeyStoreContext<TestIds>,
            key: TestSymmKey,
        ) -> Result<DataView, crate::CryptoError> {
            Ok(DataView(self.0.decrypt(ctx, key)?, key))
        }
    }

    #[test]
    fn test_multithread_decrypt_keeps_order() {
        let mut rng = rand::thread_rng();
        let store: KeyStore<TestIds> = KeyStore::default();

        // Create a bunch of random keys
        for n in 0..15 {
            #[allow(deprecated)]
            store
                .context_mut()
                .set_symmetric_key(TestSymmKey::A(n), SymmetricCryptoKey::generate(&mut rng))
                .unwrap();
        }

        // Create some test data
        let data: Vec<_> = (0..300usize)
            .map(|n| DataView(format!("Test {}", n), TestSymmKey::A((n % 15) as u8)))
            .collect();

        // Encrypt the data
        let encrypted: Vec<_> = store.encrypt_list(&data).unwrap();

        // Decrypt the data
        let decrypted: Vec<_> = store.decrypt_list(&encrypted).unwrap();

        // Check that the data is the same, and in the same order as the original
        for (orig, dec) in data.iter().zip(decrypted.iter()) {
            assert_eq!(orig.0, dec.0);
            assert_eq!(orig.1, dec.1);
        }
    }
}
