use super::*;
use tempfile::tempdir;

#[test]
fn generate_keypair_writes_secret_key_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");

    let public_key = generate_keypair(ParamSet::DEFAULT, &key_path, None).unwrap();

    assert!(key_path.exists());
    assert!(!public_key.is_empty());
}

#[test]
fn sign_message_produces_valid_signature() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_128f, &key_path, Some(&public_key_path)).unwrap();
    sign_message(
        ParamSet::Sha2_128f,
        b"hello, post-quantum world",
        &key_path,
        &signature_path,
    )
    .unwrap();

    assert!(
        verify_message(
            ParamSet::Sha2_128f,
            b"hello, post-quantum world",
            &signature_path,
            &public_key_path,
        )
        .unwrap()
    );
}

#[test]
#[ignore = "slow: the s-variant parameter sets take well over a minute combined in an \
            unoptimized debug build, the same slowness TODO.md's benchmarking phase \
            avoids on-device; run explicitly with `cargo test -- --ignored` when \
            validating all six parameter sets end to end"]
fn sign_and_verify_round_trip_for_every_param_set() {
    
    for param_set in [
        ParamSet::Sha2_128s,
        ParamSet::Sha2_128f,
        ParamSet::Sha2_192s,
        ParamSet::Sha2_192f,
        ParamSet::Sha2_256s,
        ParamSet::Sha2_256f,
    ] {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("signing.key");
        let public_key_path = dir.path().join("verifying.key");
        let signature_path = dir.path().join("message.sig");

        generate_keypair(param_set, &key_path, Some(&public_key_path)).unwrap();
        sign_message(param_set, b"hello", &key_path, &signature_path).unwrap();

        assert!(
            verify_message(param_set, b"hello", &signature_path, &public_key_path).unwrap(),
            "round trip failed for {param_set:?}"
        );
    }
}

#[test]
fn sign_message_writes_signature_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_128f, &key_path, None).unwrap();
    let signature_bytes =
        sign_message(ParamSet::Sha2_128f, b"hello", &key_path, &signature_path).unwrap();

    assert!(signature_path.exists());
    assert_eq!(fs::read(&signature_path).unwrap(), signature_bytes);
}

#[test]
fn sign_message_fails_for_missing_key_file() {
    let dir = tempdir().unwrap();
    let missing_key_path = dir.path().join("does-not-exist.key");
    let signature_path = dir.path().join("message.sig");

    let result = sign_message(
        ParamSet::Sha2_128f,
        b"hello",
        &missing_key_path,
        &signature_path,
    );

    assert!(result.is_err());
}

#[test]
fn sign_message_rejects_tampered_signature() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_128f, &key_path, Some(&public_key_path)).unwrap();
    sign_message(
        ParamSet::Sha2_128f,
        b"original message",
        &key_path,
        &signature_path,
    )
    .unwrap();
    let mut signature_bytes = fs::read(&signature_path).unwrap();
    signature_bytes[0] ^= 0xff; // corrupt the signature
    fs::write(&signature_path, &signature_bytes).unwrap();

    assert!(!verify_message(
        ParamSet::Sha2_128f,
        b"original message",
        &signature_path,
        &public_key_path,
    )
    .unwrap());
}

#[test]
fn verify_message_rejects_wrong_message() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_128f, &key_path, Some(&public_key_path)).unwrap();
    sign_message(
        ParamSet::Sha2_128f,
        b"original message",
        &key_path,
        &signature_path,
    )
    .unwrap();

    assert!(!verify_message(
        ParamSet::Sha2_128f,
        b"tampered message",
        &signature_path,
        &public_key_path,
    )
    .unwrap());
}

#[test]
fn verify_message_fails_for_invalid_public_key() {
    let dir = tempdir().unwrap();
    let public_key_path = dir.path().join("verifying.key");
    let signature_path = dir.path().join("message.sig");
    fs::write(&signature_path, [0u8; 64]).unwrap();
    fs::write(&public_key_path, [0u8; 4]).unwrap();

    let result = verify_message(ParamSet::Sha2_128f, b"hello", &signature_path, &public_key_path);

    assert!(result.is_err());
}

#[test]
fn verify_message_fails_for_missing_public_key_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let missing_public_key_path = dir.path().join("does-not-exist.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_128f, &key_path, None).unwrap();
    sign_message(ParamSet::Sha2_128f, b"hello", &key_path, &signature_path).unwrap();
    let result = verify_message(
        ParamSet::Sha2_128f,
        b"hello",
        &signature_path,
        &missing_public_key_path,
    );

    assert!(result.is_err());
}

#[test]
fn verify_message_fails_for_missing_signature_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");
    let missing_signature_path = dir.path().join("does-not-exist.sig");

    generate_keypair(ParamSet::DEFAULT, &key_path, Some(&public_key_path)).unwrap();
    let result = verify_message(
        ParamSet::DEFAULT,
        b"hello",
        &missing_signature_path,
        &public_key_path,
    );

    assert!(result.is_err());
}

#[test]
fn two_keypairs_are_different() {
    let dir = tempdir().unwrap();
    let key_path_a = dir.path().join("a.key");
    let key_path_b = dir.path().join("b.key");

    let public_key_a = generate_keypair(ParamSet::DEFAULT, &key_path_a, None).unwrap();
    let public_key_b = generate_keypair(ParamSet::DEFAULT, &key_path_b, None).unwrap();

    assert_ne!(public_key_a, public_key_b);
    assert_ne!(fs::read(&key_path_a).unwrap(), fs::read(&key_path_b).unwrap());
}

#[test]
fn default_param_set_is_128s() {
    
    assert_eq!(ParamSet::DEFAULT, ParamSet::Sha2_128s);
}

#[test]
fn param_set_parse_accepts_all_six_short_names() {
    assert_eq!(ParamSet::parse("128s"), Some(ParamSet::Sha2_128s));
    assert_eq!(ParamSet::parse("128f"), Some(ParamSet::Sha2_128f));
    assert_eq!(ParamSet::parse("192s"), Some(ParamSet::Sha2_192s));
    assert_eq!(ParamSet::parse("192f"), Some(ParamSet::Sha2_192f));
    assert_eq!(ParamSet::parse("256s"), Some(ParamSet::Sha2_256s));
    assert_eq!(ParamSet::parse("256f"), Some(ParamSet::Sha2_256f));
}

#[test]
fn param_set_parse_rejects_unknown_name() {
    assert_eq!(ParamSet::parse("128"), None);
    assert_eq!(ParamSet::parse("SLH-DSA-SHA2-128f"), None);
    assert_eq!(ParamSet::parse(""), None);
}

#[test]
fn each_param_set_produces_its_documented_key_lengths() {
    
    let cases = [
        (ParamSet::Sha2_128s, 64, 32),
        (ParamSet::Sha2_128f, 64, 32),
        (ParamSet::Sha2_192s, 96, 48),
        (ParamSet::Sha2_192f, 96, 48),
        (ParamSet::Sha2_256s, 128, 64),
        (ParamSet::Sha2_256f, 128, 64),
    ];

    for (param_set, expected_sk_len, expected_pk_len) in cases {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.key");

        let public_key = generate_keypair(param_set, &key_path, None).unwrap();

        assert_eq!(
            fs::read(&key_path).unwrap().len(),
            expected_sk_len,
            "unexpected secret key length for {param_set:?}"
        );
        assert_eq!(
            public_key.len(),
            expected_pk_len,
            "unexpected public key length for {param_set:?}"
        );
    }
}

#[test]
fn generate_keypair_writes_public_key_file_when_path_given() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");

    let returned_public_key =
        generate_keypair(ParamSet::DEFAULT, &key_path, Some(&public_key_path)).unwrap();

    assert!(public_key_path.exists());
    assert_eq!(fs::read(&public_key_path).unwrap(), returned_public_key);
}

#[test]
fn generate_keypair_does_not_write_public_key_file_when_path_omitted() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");

    generate_keypair(ParamSet::DEFAULT, &key_path, None).unwrap();

    assert!(!public_key_path.exists());
}

#[test]
fn sign_message_accepts_but_does_not_verify_a_128s_key_signed_as_128f() {
    
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let public_key_path = dir.path().join("verifying.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_128s, &key_path, Some(&public_key_path)).unwrap();

    let sign_result = sign_message(ParamSet::Sha2_128f, b"hello", &key_path, &signature_path);
    assert!(sign_result.is_ok());

    let verify_result =
        verify_message(ParamSet::Sha2_128f, b"hello", &signature_path, &public_key_path);
    assert!(!verify_result.unwrap());
}

#[test]
fn sign_message_rejects_a_192s_key_signed_as_128f() {
    
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let signature_path = dir.path().join("message.sig");

    generate_keypair(ParamSet::Sha2_192s, &key_path, None).unwrap();

    let result = sign_message(ParamSet::Sha2_128f, b"hello", &key_path, &signature_path);
    assert!(result.is_err());
}
