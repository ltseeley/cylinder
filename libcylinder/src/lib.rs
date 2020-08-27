/*
 * Copyright 2017 Intel Corporation
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
pub mod signing;

use error::HexError;

/// Converts the given hex string to bytes
fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    for (i, ch) in s.chars().enumerate() {
        if !ch.is_digit(16) {
            return Err(HexError(format!("invalid character position {}", i)));
        }
    }

    let input: Vec<_> = s.chars().collect();

    let decoded: Vec<u8> = input
        .chunks(2)
        .map(|chunk| {
            ((chunk[0].to_digit(16).unwrap() << 4) | (chunk[1].to_digit(16).unwrap())) as u8
        })
        .collect();

    Ok(decoded)
}

/// Converts the given bytes to a hex string
fn bytes_to_hex_str(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
