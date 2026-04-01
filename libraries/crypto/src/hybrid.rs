// Copyright 2021-2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::ecdsa;
use alloc::vec::Vec;
#[cfg(feature = "mldsa44")]
use bouncycastle_mldsa::{MuBuilder, MLDSA44PublicKey, MLDSA44, MLDSA44_PK_LEN, MLDSA44_SIG_LEN};
#[cfg(feature = "mldsa65")]
use bouncycastle_mldsa::{MuBuilder, MLDSA65PublicKey, MLDSA65, MLDSA65_PK_LEN, MLDSA65_SIG_LEN};
#[cfg(feature = "mldsa87")]
use bouncycastle_mldsa::{MuBuilder, MLDSA87PublicKey, MLDSA87, MLDSA87_PK_LEN, MLDSA87_SIG_LEN};

#[cfg(feature = "mldsa44")]
pub const MLDSA_PK_LEN: usize = MLDSA44_PK_LEN;
#[cfg(feature = "mldsa44")]
pub const MLDSA_SIG_LEN: usize = MLDSA44_SIG_LEN;
#[cfg(feature = "mldsa44")]
pub type MLDSA = MLDSA44;
#[cfg(feature = "mldsa44")]
pub type MLDSAPublicKey = MLDSA44PublicKey;
#[cfg(feature = "mldsa65")]
pub const MLDSA_PK_LEN: usize = MLDSA65_PK_LEN;
#[cfg(feature = "mldsa65")]
pub const MLDSA_SIG_LEN: usize = MLDSA65_SIG_LEN;
#[cfg(feature = "mldsa65")]
pub type MLDSA = MLDSA65;
#[cfg(feature = "mldsa65")]
pub type MLDSAPublicKey = MLDSA65PublicKey;
#[cfg(feature = "mldsa87")]
pub const MLDSA_PK_LEN: usize = MLDSA87_PK_LEN;
#[cfg(feature = "mldsa87")]
pub const MLDSA_SIG_LEN: usize = MLDSA87_SIG_LEN;
#[cfg(feature = "mldsa87")]
pub type MLDSA = MLDSA87;
#[cfg(feature = "mldsa87")]
pub type MLDSAPublicKey = MLDSA87PublicKey;

// A label generated uniformly at random from the output space of SHA256.
const LABEL: [u8; 32] = [
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
    117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
];
const MLDSA_SEED_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecKey {
    mldsa_seed: [u8; MLDSA_SEED_BYTES],
    ecdsa_sk: ecdsa::SecKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey {
    pub mldsa_pk: [u8; MLDSA_PK_LEN],
    pub ecdsa_pk: ecdsa::PubKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub mldsa_sign: [u8; MLDSA_SIG_LEN],
    pub ecdsa_sign: ecdsa::Signature,
}

fn ecdsa_input_hash<H>(msg: &[u8]) -> [u8; 32]
where
    H: super::Hash256,
{
    let mut h = H::new();
    h.update(&LABEL);
    h.update(msg);
    h.finalize()
}

fn mldsa_signing_randomness<H>(msg: &[u8], ecdsa_der: &[u8]) -> [u8; 32]
where
    H: super::Hash256,
{
    let mut h = H::new();
    h.update(&LABEL);
    h.update(msg);
    h.update(ecdsa_der);
    h.finalize()
}

fn mldsa_mu(msg: &[u8], ecdsa_der: &[u8], tr: &[u8; 64]) -> [u8; 64] {
    let mut builder = MuBuilder::do_init(tr, b"").unwrap();
    builder.do_update(&LABEL);
    builder.do_update(msg);
    builder.do_update(ecdsa_der);
    builder.do_final()
}

impl SecKey {
    pub const BYTES_LENGTH: usize = 32 + MLDSA_SEED_BYTES;

    pub fn gensk<R>(rng: &mut R) -> SecKey
    where
        R: rng256::Rng256,
    {
        let mut seed = [0u8; MLDSA_SEED_BYTES];
        rng.fill_bytes(&mut seed);
        SecKey {
            mldsa_seed: seed,
            ecdsa_sk: ecdsa::SecKey::gensk(rng),
        }
    }

    pub fn gensk_with_pk<R>(rng: &mut R) -> (SecKey, PubKey)
    where
        R: rng256::Rng256,
    {
        let mut seed = [0u8; MLDSA_SEED_BYTES];
        rng.fill_bytes(&mut seed);
        let mldsa_pk = MLDSA::pk_encode_from_seed_bytes(&seed).unwrap();
        let ecdsa_sk = ecdsa::SecKey::gensk(rng);
        let ecdsa_pk = ecdsa_sk.genpk();

        let sk = SecKey {
            mldsa_seed: seed,
            ecdsa_sk,
        };
        let pk = PubKey {
            mldsa_pk,
            ecdsa_pk,
        };
        (sk, pk)
    }

    pub fn genpk(&self) -> PubKey {
        let mldsa_pk = MLDSA::pk_encode_from_seed_bytes(&self.mldsa_seed).unwrap();
        PubKey {
            mldsa_pk: mldsa_pk,
            ecdsa_pk: self.ecdsa_sk.genpk(),
        }
    }

    /// Returns only the ECDSA component public key. Makes it quicker to select.
    pub fn genpk_ecdsa(&self) -> ecdsa::PubKey {
        self.ecdsa_sk.genpk()
    }

    pub fn sign_rfc6979<H>(&self, msg: &[u8]) -> Signature
    where
        H: super::Hash256 + super::HashBlockSize64Bytes,
    {
        let ecdsa_sign = self
            .ecdsa_sk
            .sign_hash_rfc6979::<H>(&ecdsa_input_hash::<H>(msg));
        let mut ecdsa_der = [0u8; ecdsa::Signature::MAX_ASN1_DER_LENGTH];
        let ecdsa_der_len = ecdsa_sign.to_asn1_der_out(&mut ecdsa_der);
        let ecdsa_der = &ecdsa_der[..ecdsa_der_len];

        let mldsa_sk = MLDSA::private_key_from_seed_bytes(&self.mldsa_seed).unwrap();
        let mu = mldsa_mu(msg, ecdsa_der, &mldsa_sk.public_key_hash());
        let mldsa_signing_randomness = mldsa_signing_randomness::<H>(msg, ecdsa_der);
        let mut mldsa_sign = [0u8; MLDSA_SIG_LEN];
        MLDSA::sign_mu_deterministic_out(
            &mldsa_sk,
            &mu,
            mldsa_signing_randomness,
            &mut mldsa_sign,
        )
        .unwrap();

        Signature {
            ecdsa_sign,
            mldsa_sign: mldsa_sign,
        }
    }

    pub fn from_bytes(bytes: &[u8; SecKey::BYTES_LENGTH]) -> Option<SecKey> {
        let ecdsa_bytes = array_ref!(bytes, 0, 32);
        let ecdsa_sk = ecdsa::SecKey::from_bytes(&ecdsa_bytes)?;

        let mldsa_seed = array_ref!(bytes, 32, MLDSA_SEED_BYTES).clone();

        Some(SecKey {
            ecdsa_sk,
            mldsa_seed: mldsa_seed,
        })
    }

    pub fn to_bytes(&self, bytes: &mut [u8; SecKey::BYTES_LENGTH]) {
        let mut ecdsa_bytes = array_mut_ref!(bytes, 0, 32);
        self.ecdsa_sk.to_bytes(&mut ecdsa_bytes);
        let mldsa_bytes = array_mut_ref!(bytes, 32, MLDSA_SEED_BYTES);
        mldsa_bytes.copy_from_slice(&self.mldsa_seed);
    }
}

impl PubKey {
    pub const BYTES_LENGTH: usize = 2 * ecdsa::NBYTES + MLDSA_PK_LEN;

    pub fn from_bytes(bytes: &[u8; PubKey::BYTES_LENGTH]) -> Option<PubKey> {
        let ecdsa_x_bytes = array_ref!(bytes, 0, ecdsa::NBYTES);
        let ecdsa_y_bytes = array_ref!(bytes, ecdsa::NBYTES, ecdsa::NBYTES);

        let ecdsa_pk = ecdsa::PubKey::from_coordinates(&ecdsa_x_bytes, &ecdsa_y_bytes)?;

        let mldsa_pk = array_ref!(
            bytes,
            ecdsa::NBYTES + ecdsa::NBYTES,
            MLDSA_PK_LEN
        )
        .clone();

        Some(PubKey {
            ecdsa_pk,
            mldsa_pk: mldsa_pk,
        })
    }

    pub fn to_bytes(&self, bytes: &mut [u8; PubKey::BYTES_LENGTH]) {
        let mut ecdsa_x_bytes = [0; ecdsa::NBYTES];
        let mut ecdsa_y_bytes = [0; ecdsa::NBYTES];

        self.ecdsa_pk
            .to_coordinates(&mut ecdsa_x_bytes, &mut ecdsa_y_bytes);

        array_mut_ref!(bytes, 0, ecdsa::NBYTES).clone_from(&ecdsa_x_bytes);
        array_mut_ref!(bytes, ecdsa::NBYTES, ecdsa::NBYTES).clone_from(&ecdsa_y_bytes);

        let mldsa_bytes = array_mut_ref!(
            bytes,
            ecdsa::NBYTES + ecdsa::NBYTES,
            MLDSA_PK_LEN
        );
        mldsa_bytes.copy_from_slice(&self.mldsa_pk);
    }

    pub fn verify_vartime<H>(&self, msg: &[u8], sign: &Signature) -> bool
    where
        H: super::Hash256,
    {
        let mut ecdsa_der = [0u8; ecdsa::Signature::MAX_ASN1_DER_LENGTH];
        let ecdsa_der_len = sign.ecdsa_sign.to_asn1_der_out(&mut ecdsa_der);
        let ecdsa_der = &ecdsa_der[..ecdsa_der_len];
        let mldsa_pk = MLDSAPublicKey::from_pk_bytes(&self.mldsa_pk);
        let mu = mldsa_mu(msg, ecdsa_der, &mldsa_pk.compute_tr());

        self.ecdsa_pk
            .verify_hash_vartime(&ecdsa_input_hash::<H>(msg), &sign.ecdsa_sign)
            && MLDSA::verify_mu(&mldsa_pk, &mu, &sign.mldsa_sign).is_ok()
    }
}

impl Signature {
    pub const BYTES_LENGTH: usize = 64 + MLDSA_SIG_LEN;

    /// Converts a signature into the CBOR required byte array representation.
    ///
    /// This operation consumes the signature to efficiently use memory.
    pub fn to_asn1_der(self) -> Vec<u8> {
        let mut ecdsa_der = [0u8; ecdsa::Signature::MAX_ASN1_DER_LENGTH];
        let ecdsa_der_len = self.ecdsa_sign.to_asn1_der_out(&mut ecdsa_der);
        let mut bytes = Vec::with_capacity(ecdsa_der_len + MLDSA_SIG_LEN);
        bytes.extend_from_slice(&ecdsa_der[..ecdsa_der_len]);
        bytes.extend_from_slice(&self.mldsa_sign);
        bytes
    }
}

#[cfg(test)]
mod test {
    extern crate rng256;
    use super::super::sha256::Sha256;
    use super::*;
    use rng256::Rng256;

    pub const ITERATIONS: u32 = 500;

    #[test]
    fn test_hybrid_seckey_to_bytes_from_bytes() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let mut bytes = [0; SecKey::BYTES_LENGTH];
            sk.to_bytes(&mut bytes);
            let decoded_sk = SecKey::from_bytes(&bytes);
            assert_eq!(decoded_sk, Some(sk));
        }
    }

    #[test]
    fn test_hybrid_pubkey_to_bytes_from_bytes() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let mut bytes = [0; PubKey::BYTES_LENGTH];
            pk.to_bytes(&mut bytes);
            let decoded_pk = PubKey::from_bytes(&bytes);
            assert_eq!(decoded_pk, Some(pk));
        }
    }

    #[test]
    fn test_hybrid_sign_rfc6979_verify_vartime() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let msg = rng.gen_uniform_u8x32();
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let sign = sk.sign_rfc6979::<Sha256>(&msg);
            assert!(pk.verify_vartime::<Sha256>(&msg, &sign));
        }
    }
}
