use std::fs;
use std::io;
use std::path::Path;

use rand_core::OsRng;
use signature::{Keypair, Signer, Verifier};
use slh_dsa::{Sha2_128f, Signature, SigningKey, VerifyingKey};

pub type Params = Sha2_128f;

pub fn generate_keypair(secret_key_path: &Path) -> io::Result<Vec<u8>> {
    let mut rng = OsRng;
    let signing_key = SigningKey::<Params>::new(&mut rng);

    fs::write(secret_key_path, signing_key.to_bytes().as_slice())?;

    Ok(signing_key.verifying_key().to_bytes().to_vec())
}

pub fn sign_message(
    message: &[u8],
    secret_key_path: &Path,
    signature_path: &Path,
) -> io::Result<Vec<u8>> {
    let key_bytes = fs::read(secret_key_path)?;
    let signing_key = SigningKey::<Params>::try_from(key_bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid secret key at {}", secret_key_path.display()),
        )
    })?;

    let signature = signing_key
        .try_sign(message)
        .map_err(|e| io::Error::other(format!("signing failed: {e}")))?;
    let signature_bytes = signature.to_bytes().to_vec();

    fs::write(signature_path, &signature_bytes)?;

    Ok(signature_bytes)
}

pub fn verify_message(
    message: &[u8],
    signature_path: &Path,
    public_key: &[u8],
) -> io::Result<bool> {
    let signature_bytes = fs::read(signature_path)?;
    let verifying_key = VerifyingKey::<Params>::try_from(public_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public key"))?;
    let signature = Signature::<Params>::try_from(signature_bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid signature at {}", signature_path.display()),
        )
    })?;

    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod tests;
