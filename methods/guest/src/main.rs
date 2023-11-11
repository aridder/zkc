#![no_main]

use ed25519_dalek::VerifyingKey;
use jwt_compact::{alg::*, prelude::*, Token, UntrustedToken};
// If you want to try std support, also update the guest Cargo.toml file
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct CredentialSubject {
    #[serde(rename = "dateOfBirth")]
    date_of_birth: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Issuer {
    id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    jwt: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct VerifiableCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject,
    issuer: Issuer,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "issuanceDate")]
    issuance_date: String,
    proof: Proof,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct VC {
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct VCClaims {
    vc: VC,
    sub: String,
    iss: String,
}


pub fn main() {
    // Decode the verifying key, message, and signature from the inputs.
    let (age, jwt, public_key): (u32, String, String) = env::read();
    let public_key_bytes: &[u8; 32] = &hex::decode(&public_key).unwrap().try_into().unwrap();

    // Verify the signature, panicking if verification fails.
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
    let token = UntrustedToken::new(&jwt).unwrap();
    let token: Token<VCClaims> = Ed25519.validator(&verifying_key).validate(&token).unwrap();
    println!("token: {:?}", token);

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(age));
}
