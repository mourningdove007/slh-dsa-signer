use super::*;
use tempfile::tempdir;

#[test]
fn generate_keypair_writes_secret_key_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");

    let public_key = generate_keypair(&key_path).unwrap();

    assert!(key_path.exists());
    assert!(!public_key.is_empty());
}

#[test]
fn sign_message_produces_valid_signature() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let signature_path = dir.path().join("message.sig");

    let public_key_bytes = generate_keypair(&key_path).unwrap();
    sign_message(b"hello, post-quantum world", &key_path, &signature_path).unwrap();

    assert!(
        verify_message(
            b"hello, post-quantum world",
            &signature_path,
            &public_key_bytes,
        )
        .unwrap()
    );
}

#[test]
fn sign_message_writes_signature_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(&key_path).unwrap();
    let signature_bytes = sign_message(b"hello", &key_path, &signature_path).unwrap();

    assert!(signature_path.exists());
    assert_eq!(fs::read(&signature_path).unwrap(), signature_bytes);
}

#[test]
fn sign_message_fails_for_missing_key_file() {
    let dir = tempdir().unwrap();
    let missing_key_path = dir.path().join("does-not-exist.key");
    let signature_path = dir.path().join("message.sig");

    let result = sign_message(b"hello", &missing_key_path, &signature_path);

    assert!(result.is_err());
}

#[test]
fn sign_message_rejects_tampered_signature() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let signature_path = dir.path().join("message.sig");

    let public_key_bytes = generate_keypair(&key_path).unwrap();
    sign_message(b"original message", &key_path, &signature_path).unwrap();
    let mut signature_bytes = fs::read(&signature_path).unwrap();
    signature_bytes[0] ^= 0xff; // corrupt the signature
    fs::write(&signature_path, &signature_bytes).unwrap();

    assert!(!verify_message(b"original message", &signature_path, &public_key_bytes).unwrap());
}

#[test]
fn verify_message_rejects_wrong_message() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let signature_path = dir.path().join("message.sig");

    let public_key_bytes = generate_keypair(&key_path).unwrap();
    sign_message(b"original message", &key_path, &signature_path).unwrap();

    assert!(!verify_message(b"tampered message", &signature_path, &public_key_bytes).unwrap());
}

#[test]
fn verify_message_fails_for_invalid_public_key() {
    let dir = tempdir().unwrap();
    let signature_path = dir.path().join("message.sig");
    fs::write(&signature_path, [0u8; 64]).unwrap();

    let result = verify_message(b"hello", &signature_path, &[0u8; 4]);

    assert!(result.is_err());
}

#[test]
fn verify_message_fails_for_missing_signature_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let missing_signature_path = dir.path().join("does-not-exist.sig");

    let public_key_bytes = generate_keypair(&key_path).unwrap();
    let result = verify_message(b"hello", &missing_signature_path, &public_key_bytes);

    assert!(result.is_err());
}

#[test]
fn two_keypairs_are_different() {
    let dir = tempdir().unwrap();
    let key_path_a = dir.path().join("a.key");
    let key_path_b = dir.path().join("b.key");

    let public_key_a = generate_keypair(&key_path_a).unwrap();
    let public_key_b = generate_keypair(&key_path_b).unwrap();

    assert_ne!(public_key_a, public_key_b);
    assert_ne!(fs::read(&key_path_a).unwrap(), fs::read(&key_path_b).unwrap());
}
