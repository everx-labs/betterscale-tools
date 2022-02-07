use curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek_ng::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek_ng::scalar::Scalar;
use rand::Rng;
use sha2::{Digest, Sha512};
use tl_proto::*;

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub secret_key: ExpandedSecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    #[allow(unused)]
    #[inline(always)]
    pub fn generate() -> Self {
        Self::from(&SecretKey::generate())
    }

    #[inline(always)]
    pub fn sign<T: TlWrite>(&self, data: T) -> [u8; 64] {
        self.secret_key.sign(data, &self.public_key)
    }
}

impl From<ExpandedSecretKey> for KeyPair {
    fn from(secret_key: ExpandedSecretKey) -> Self {
        let public_key = PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}

impl From<&'_ SecretKey> for KeyPair {
    fn from(secret_key: &SecretKey) -> Self {
        let secret_key = secret_key.expand();
        let public_key = PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey(CompressedEdwardsY, EdwardsPoint);

impl PublicKey {
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let compressed = CompressedEdwardsY(bytes);
        let point = compressed.decompress()?;
        Some(PublicKey(compressed, -point))
    }

    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        &self.0 .0
    }

    #[inline(always)]
    fn from_scalar(bits: [u8; 32]) -> PublicKey {
        let point = &clamp_scalar(bits) * &ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();
        Self(compressed, -point)
    }
}

impl From<&'_ SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut h = Sha512::new();
        h.update(&secret_key.0);
        let hash: [u8; 64] = h.finalize().into();
        Self::from_scalar(hash[..32].try_into().unwrap())
    }
}

impl From<&'_ ExpandedSecretKey> for PublicKey {
    fn from(expanded_secret_key: &ExpandedSecretKey) -> Self {
        Self::from_scalar(expanded_secret_key.key.to_bytes())
    }
}

impl AsRef<[u8; 32]> for PublicKey {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl PartialEq for PublicKey {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.0 .0.eq(&other.0 .0)
    }
}

impl Eq for PublicKey {}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(&self.0 .0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

#[derive(Copy, Clone)]
pub struct ExpandedSecretKey {
    key: Scalar,
    nonce: [u8; 32],
}

impl ExpandedSecretKey {
    #[allow(non_snake_case)]
    pub fn sign<T: TlWrite>(&self, message: T, public_key: &PublicKey) -> [u8; 64] {
        let message = HashWrapper(message);

        let mut h = Sha512::new();
        h.update(&self.nonce);
        message.update_hasher(&mut h);

        let r = Scalar::from_hash(h);
        let R = (&r * &ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(public_key.as_bytes());
        message.update_hasher(&mut h);

        let k = Scalar::from_hash(h);
        let s = (k * self.key) + r;

        let mut result = [0u8; 64];
        result[..32].copy_from_slice(R.as_bytes().as_slice());
        result[32..].copy_from_slice(s.as_bytes().as_slice());
        result
    }
}

impl From<&'_ SecretKey> for ExpandedSecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut h = Sha512::new();
        h.update(&secret_key.0);
        let hash: [u8; 64] = h.finalize().into();

        let mut lower: [u8; 32] = hash[..32].try_into().unwrap();
        let nonce: [u8; 32] = hash[32..].try_into().unwrap();

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        Self {
            key: Scalar::from_bits(lower),
            nonce,
        }
    }
}

#[derive(Copy, Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[allow(unused)]
    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        &self.0
    }

    #[allow(unused)]
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    #[inline(always)]
    pub fn expand(&self) -> ExpandedSecretKey {
        ExpandedSecretKey::from(self)
    }
}

#[inline(always)]
fn clamp_scalar(mut bits: [u8; 32]) -> Scalar {
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;
    Scalar::from_bits(bits)
}
