/*
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

use std::sync::Arc;
use std::thread;

use cylinder::{
    signing::{Context, CryptoFactory},
    PrivateKey,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_signing_multithreading<C: Context + 'static>(context: C) -> TestResult {
    let private_key = PrivateKey::new_from_hex(
        "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088",
    )
    .expect("Unable to parse private key");
    let arc_context = Arc::new(context);
    let factory = CryptoFactory::new(arc_context.clone());
    let signer = factory.new_signer(private_key.clone());

    let signer1 = signer.clone();
    let jh1: thread::JoinHandle<String> =
        thread::spawn(move || signer1.sign(b"Hello").expect("Unable to sign bytes"));

    let signer2 = signer.clone();
    let jh2: thread::JoinHandle<String> =
        thread::spawn(move || signer2.sign(b"Hello").expect("Unable to sign bytes"));

    let sig1 = jh1.join().expect("child thread 1 panicked");
    let sig2 = jh2.join().expect("child thread 2 panicked");

    assert_eq!(sig1, sig2);

    let public_key = arc_context.get_public_key(&private_key)?;
    assert!(arc_context.verify(&sig1, b"Hello", &public_key)?);
    assert!(arc_context.verify(&sig2, b"Hello", &public_key)?);

    Ok(())
}

mod secp256k1 {
    use super::*;

    use cylinder::signing::secp256k1::Secp256k1Context;

    #[test]
    fn test_signing_multithreading() -> TestResult {
        let context = Secp256k1Context::new();

        super::test_signing_multithreading(context)
    }
}
