use crate::crypto::{pubkey_to_address, CreateKey, Error, Message, PubKey, Sm2Privkey, Sm2Pubkey};
use crate::{Signature, H256, H512};
use efficient_sm2::{create_key_slice, KeyPair, PublicKey};
use hex::encode;
use std::fmt;
use std::ops::{Deref, DerefMut};
use types::Address;

const SIGNATURE_BYTES_LEN: usize = 128;

/// Sm2 key pair
#[derive(Default, Clone)]
pub struct Sm2KeyPair {
    privkey: Sm2Privkey,
    pubkey: Sm2Pubkey,
}

impl fmt::Display for Sm2KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "privkey:  {}", encode(self.privkey.0))?;
        writeln!(f, "pubkey:  {}", encode(self.pubkey.0))?;
        write!(f, "address:  {}", encode(self.address().0))
    }
}

impl CreateKey for Sm2KeyPair {
    type PrivKey = Sm2Privkey;
    type PubKey = Sm2Pubkey;
    type Error = Error;

    fn from_privkey(privkey: Self::PrivKey) -> Result<Self, Self::Error> {
        let key_pair = KeyPair::new(privkey.as_bytes()).map_err(|_| Error::InvalidPrivKey)?;
        Ok(Sm2KeyPair {
            privkey,
            pubkey: H512::from_slice(&key_pair.public_key().bytes_less_safe()[1..]),
        })
    }

    fn gen_keypair() -> Self {
        let private = H256(create_key_slice());
        Self::from_privkey(private).unwrap()
    }

    fn privkey(&self) -> &Self::PrivKey {
        &self.privkey
    }

    fn pubkey(&self) -> &Self::PubKey {
        &self.pubkey
    }

    fn address(&self) -> Address {
        pubkey_to_address(&PubKey::Sm2(self.pubkey))
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, Error> {
        let keypair = KeyPair::new(self.privkey.as_bytes()).map_err(|_| Error::InvalidPrivKey)?;
        let sig = keypair.sign(data).map_err(|_| Error::InvalidMessage)?;

        let mut sig_bytes = [0u8; SIGNATURE_BYTES_LEN];
        sig_bytes[..32].copy_from_slice(&sig.r());
        sig_bytes[32..64].copy_from_slice(&sig.s());
        sig_bytes[64..].copy_from_slice(&keypair.public_key().bytes_less_safe()[1..]);
        Ok(Signature::Sm2(Sm2Signature(sig_bytes)))
    }
}

/// Sm2 signature
pub struct Sm2Signature(pub [u8; 128]);

impl Sm2Signature {
    /// Get a slice into the 'r' portion of the data.
    #[inline]
    pub fn r(&self) -> &[u8] {
        &self.0[0..32]
    }
    /// Get a slice into the 's' portion of the data.
    #[inline]
    pub fn s(&self) -> &[u8] {
        &self.0[32..64]
    }
    /// Get a slice into the public key portion of the data.
    #[inline]
    pub fn pk(&self) -> &[u8] {
        &self.0[64..]
    }

    /// Recover public key
    pub fn recover(&self, message: &Message) -> Result<Sm2Pubkey, Error> {
        let pub_key = Sm2Pubkey::from_slice(self.pk());
        self.verify_public(&pub_key, message)?;

        Ok(pub_key)
    }

    /// Verify public key
    pub fn verify_public(&self, pubkey: &Sm2Pubkey, message: &Message) -> Result<bool, Error> {
        let pub_key = PublicKey::from_slice(pubkey.as_bytes());
        let sig = efficient_sm2::Signature::new(self.r(), self.s())
            .map_err(|_| Error::InvalidSignature)?;
        sig.verify(&pub_key, message.as_bytes())
            .map_err(|_| Error::RecoverError)
            .map(|_| true)
    }
}

/// Sign data with sm2
pub fn sm2_sign(privkey: &Sm2Privkey, message: &Message) -> Result<Sm2Signature, Error> {
    let keypair = KeyPair::new(privkey.as_bytes()).map_err(|_| Error::InvalidPrivKey)?;
    let sig = keypair
        .sign(message.as_bytes())
        .map_err(|_| Error::InvalidMessage)?;

    let mut sig_bytes = [0u8; SIGNATURE_BYTES_LEN];
    sig_bytes[..32].copy_from_slice(&sig.r());
    sig_bytes[32..64].copy_from_slice(&sig.s());
    sig_bytes[64..].copy_from_slice(&keypair.public_key().bytes_less_safe()[1..]);
    Ok(Sm2Signature(sig_bytes))
}

impl fmt::Debug for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Signature")
            .field("r", &encode(self.r()))
            .field("s", &encode(self.s()))
            .field("pk", &encode(self.pk()))
            .finish()
    }
}

impl fmt::Display for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", encode(&self.0[..]))
    }
}

impl Default for Sm2Signature {
    fn default() -> Self {
        Sm2Signature([0; 128])
    }
}

impl From<[u8; 128]> for Sm2Signature {
    fn from(s: [u8; 128]) -> Self {
        Sm2Signature(s)
    }
}

impl<'a> From<&'a [u8]> for Sm2Signature {
    fn from(slice: &'a [u8]) -> Sm2Signature {
        assert_eq!(slice.len(), SIGNATURE_BYTES_LEN);
        let mut bytes = [0u8; SIGNATURE_BYTES_LEN];
        bytes.copy_from_slice(slice);
        Sm2Signature(bytes)
    }
}

impl fmt::LowerHex for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in &self.0[..] {
            write!(f, "{i:02x}")?;
        }
        Ok(())
    }
}

impl Deref for Sm2Signature {
    type Target = [u8; 128];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Sm2Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recover() {
        let keypair = Sm2KeyPair::gen_keypair();
        let msg = Message::default();
        let sig = sm2_sign(keypair.privkey(), &msg).unwrap();
        assert_eq!(keypair.pubkey(), &sig.recover(&msg).unwrap());
    }
}
