#![no_main]

use ed25519_dalek::VerifyingKey;
use jwt_compact::{alg::*, prelude::*, Token, UntrustedToken};
// If you want to try std support, also update the guests Cargo.toml file
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct GenericCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: serde_json::Value,
    // Flexible subject
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
struct Issuer {
    id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    jwt: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct CredentialClaims {
    vc: CredentialSubjectClaims,
    sub: String,
    iss: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct CredentialSubjectClaims {
    #[serde(rename = "credentialSubject")]
    credential_subject: serde_json::Value,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Condition {
    LT,
    GT,
    EQ,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Predicate {
    field: String,
    condition: Condition,
    value: u32,
}

fn check_predicate(claims: &CredentialClaims, predicate: &Predicate) -> bool {
    let credential_subject = &claims.vc.credential_subject;
    let field = &predicate.field;
    let value = &predicate.value;
    let condition = &predicate.condition;
    let credential_subject = credential_subject[field].as_u64().unwrap() as u32;
    match condition {
        Condition::LT => credential_subject < *value,
        Condition::GT => credential_subject > *value,
        Condition::EQ => credential_subject == *value,
    }
}

pub fn main() {
    let (jwt_credential, public_key_issuer, predicate): (String, String, Predicate) = env::read();

    let bytes_pk_eid_issuer: &[u8; 32] = &hex::decode(&public_key_issuer).unwrap().try_into().unwrap();

    // Verify the signature, panicking if verification fails.
    let verifying_key_eid_issuer = VerifyingKey::from_bytes(&bytes_pk_eid_issuer).unwrap();

    let untrusted_token_credential = UntrustedToken::new(&jwt_credential).unwrap();

    let credential_claims: Token<CredentialClaims> = Ed25519.validator(&verifying_key_eid_issuer).validate(&untrusted_token_credential).unwrap();
    let credential = &credential_claims.claims().custom;

    let date_of_birth = credential.vc.credential_subject["date_of_birth"].as_u64().unwrap() as u32;
    let predicate_date_of_birth = predicate.value;
    let predicate_condition = &predicate.condition;
    let predicate_field = &predicate.field;

    let is_valid = check_predicate(credential, &predicate);

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(is_valid));
}
