use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} keygen <secret-key-path>");
    eprintln!("  {program} sign <secret-key-path> <message> <signature-path>");
    eprintln!("  {program} verify <public-key-hex> <message> <signature-path>");
}

fn main() -> ExitCode {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "cli".to_string());

    let Some(command) = args.next() else {
        print_usage(&program);
        return ExitCode::FAILURE;
    };

    match command.as_str() {
        "keygen" => {
            let Some(key_path) = args.next() else {
                print_usage(&program);
                return ExitCode::FAILURE;
            };

            match cli::generate_keypair(&PathBuf::from(&key_path)) {
                Ok(public_key) => {
                    println!("secret key written to {key_path}");
                    println!("public key (hex): {}", hex_encode(&public_key));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: failed to generate keypair: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "sign" => {
            let (Some(key_path), Some(message), Some(signature_path)) =
                (args.next(), args.next(), args.next())
            else {
                print_usage(&program);
                return ExitCode::FAILURE;
            };

            match cli::sign_message(
                message.as_bytes(),
                &PathBuf::from(&key_path),
                &PathBuf::from(&signature_path),
            ) {
                Ok(signature) => {
                    println!("signature written to {signature_path}");
                    println!("signature (hex): {}", hex_encode(&signature));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: failed to sign message: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "verify" => {
            let (Some(public_key_hex), Some(message), Some(signature_path)) =
                (args.next(), args.next(), args.next())
            else {
                print_usage(&program);
                return ExitCode::FAILURE;
            };

            let Some(public_key) = hex_decode(&public_key_hex) else {
                eprintln!("error: public key must be valid hex");
                return ExitCode::FAILURE;
            };

            match cli::verify_message(
                message.as_bytes(),
                &PathBuf::from(&signature_path),
                &public_key,
            ) {
                Ok(true) => {
                    println!("valid");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("invalid");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("error: failed to verify signature: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            print_usage(&program);
            ExitCode::FAILURE
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
