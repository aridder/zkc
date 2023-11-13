#![no_main]

use ed25519_dalek::VerifyingKey;
use jwt_compact::{alg::*, prelude::*, Token, UntrustedToken};
// If you want to try std support, also update the guest Cargo.toml file
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct PersonCredentialSubject {
    name: String,
    date_of_birth: String,
    nationality: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct HouseLoanCredentialSubject {
    loan_amount: u32,
    loan_purpose: String,
    expiration_date: String,
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
struct PersonCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: PersonCredentialSubject,
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
struct HouseLoanCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: HouseLoanCredentialSubject,
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
struct PersonCredentialSubjectClaims {
    #[serde(rename = "credentialSubject")]
    credential_subject: PersonCredentialSubject,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct HouseLoanCredentialSubjectClaims {
    #[serde(rename = "credentialSubject")]
    credential_subject: HouseLoanCredentialSubject,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct HouseLoanCredentialClaims{
    vc: HouseLoanCredentialSubjectClaims,
    sub: String,
    iss: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PersonCredentialClaims{
    vc: PersonCredentialSubjectClaims,
    sub: String,
    iss: String,
}


pub fn main() {

    let (bid_size, person_credential_jwt, house_loan_credential_jwt, eid_issuer_public_key, bank_public_key): (u32, String, String, String, String) = env::read();
    let bytes_pk_bank: &[u8; 32] = &hex::decode(&bank_public_key).unwrap().try_into().unwrap();
    let bytes_pk_eid_issuer: &[u8; 32] = &hex::decode(&eid_issuer_public_key).unwrap().try_into().unwrap();

    // Verify the signature, panicking if verification fails.
    let verifying_key_bank = VerifyingKey::from_bytes(&bytes_pk_bank).unwrap();
    let verifying_key_eid_issuer = VerifyingKey::from_bytes(&bytes_pk_eid_issuer).unwrap();

    let untrusted_token_person_credential = UntrustedToken::new(&person_credential_jwt).unwrap();
    let untrusted_token_house_loan_credential = UntrustedToken::new(&house_loan_credential_jwt).unwrap();

    let token_person: Token<PersonCredentialClaims> = Ed25519.validator(&verifying_key_eid_issuer).validate(&untrusted_token_person_credential).unwrap();
    let token_house_loan: Token<HouseLoanCredentialClaims> = Ed25519.validator(&verifying_key_bank).validate(&untrusted_token_house_loan_credential).unwrap();

    // check if bid_size is less than loan_amount
    let person_crededential = token_person.claims().clone();
    let person_did = &person_crededential.custom.sub;

    let house_loan_crededential = token_house_loan.claims().clone();
    let loan_amount = house_loan_crededential.custom.vc.credential_subject.loan_amount;

    let is_valid_bid = bid_size <= loan_amount;
    assert!(is_valid_bid);

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(is_valid_bid, person_did, bid_size));
}
