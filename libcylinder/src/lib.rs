/*
 * Copyright 2017 Intel Corporation
 * Copyright 2018-2020 Cargill Incorporated
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

mod error;
mod hex;
mod key;
mod signature;
pub mod signing;

pub use error::{ContextError, SignatureParseError, SigningError, VerificationError};
pub use key::{KeyParseError, PrivateKey, PublicKey};
pub use signature::Signature;

/// A signer for arbitrary messages
pub trait Signer: Send {
    /// Signs the given message
    fn sign(&self, message: &[u8]) -> Result<Signature, SigningError>;

    /// Returns the signer's public key
    fn public_key(&self) -> Result<PublicKey, SigningError>;
}

/// Verifies message signatures
pub trait Verifier: Send {
    /// Verifies that the provided signature is valid for the given message and public key
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool, VerificationError>;
}

/// A context for creating signers and verifiers
pub trait Context {
    /// Creates a new signer with the given private key
    fn new_signer(&self, key: PrivateKey) -> Box<dyn Signer>;

    /// Creates a new signature verifier
    fn new_verifier(&self) -> Box<dyn Verifier>;

    /// Generates a new random private key
    fn new_random_private_key(&self) -> PrivateKey;

    /// Computes the public key that corresponds to the given private key
    fn get_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey, ContextError>;
}
