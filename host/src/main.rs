// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use std::fs;

use methods::{BID_VERIFIER_ELF, BID_VERIFIER_ID, PREDICATE_VERIFIER_ELF, PREDICATE_VERIFIER_ID};
use crate::Condition::{EQ, GT, LT, NEQ};

#[derive(Serialize, Deserialize, Debug)]
struct PublicKeyHolder {
    public_key: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    jwt: String,
}


#[derive(Serialize, Deserialize, Debug)]
struct Credential {
    #[serde(rename = "credentialSubject")]
    credential_subject: serde_json::Value,
    issuer: serde_json::Value,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "issuanceDate")]
    issuance_date: String,
    proof: Proof,
}

#[derive(Serialize, Deserialize, Debug)]
struct Root {
    #[serde(rename = "bidSize")]
    bid_size: u32,
    #[serde(rename = "eidIssuer")]
    eid_issuer: PublicKeyHolder,
    bank: PublicKeyHolder,
    person: PublicKeyHolder,
    #[serde(rename = "personCredential")]
    person_credential: Credential,
    #[serde(rename = "houseLoanCredential")]
    house_loan_credential: Credential,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Condition {
    LT,
    GT,
    EQ,
    NEQ,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Predicate {
    field: String,
    condition: Condition,
    value: u32,
    return_value: String,
}

fn prove_predicate(
    jwt: &str,
    public_key_issuer: &str,
    predicate_list: Vec<Predicate>,
) -> Receipt {

    let input = (jwt, public_key_issuer, predicate_list);
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    prover.prove(env, PREDICATE_VERIFIER_ELF).unwrap()
}

fn prove_valid_bid(
    bid_size: u32,
    person_credential_jwt: &str,
    house_loan_credential_jwt: &str,
    eid_issuer_public_key: &str,
    bank_public_key: &str,
) -> Receipt {

    let input = (bid_size, person_credential_jwt, house_loan_credential_jwt, eid_issuer_public_key, bank_public_key);
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    prover.prove(env, BID_VERIFIER_ELF).unwrap()
}

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    env_logger::init();

    // read json file from current directory
    let data = fs::read_to_string("./data.json").expect("Unable to read file");
    // verify_bid_program(&data);
    verify_predicate_program(&data);
}

fn verify_predicate_program(data: &String) {
    let root: Root = serde_json::from_str(&data).expect("JSON was not well-formatted");

    let person_credential = root.person_credential;

    let predicate = Predicate{
        field: String::from("date_of_birth"),
        condition: GT,
        value: 19791001,
        return_value: String::from("Subject is older than 40 years old")
    };

    let predicate2 = Predicate{
        field: String::from("date_of_birth"),
        condition: GT,
        value: 19781001,
        return_value: String::from("Subject is older than 40 years old")
    };

    let predicate_list = vec![predicate, predicate2];

    let public_key_eid = root.eid_issuer.public_key;

    let receipt = prove_predicate(&person_credential.proof.jwt, &public_key_eid, predicate_list);

    let (issuer, subect, result_list): (String, String, Vec<String>) = receipt.journal.decode().unwrap();
    receipt.verify(PREDICATE_VERIFIER_ID).unwrap();

    println!("Issuer: {}", issuer);
    println!("Subject: {}", subect);
    println!("Result list: {:?}", result_list);
}

fn verify_bid_program(data: &String) {

    let root: Root = serde_json::from_str(&data).expect("JSON was not well-formatted");

    // Initialize variables
    let bid_size = root.bid_size;
    let public_key_eid = root.eid_issuer.public_key;
    let public_key_bank = root.bank.public_key;

    let person_credential = root.person_credential;
    let house_loan_credential = root.house_loan_credential;

    let receipt = prove_valid_bid(
        bid_size,
        &person_credential.proof.jwt,
        &house_loan_credential.proof.jwt,
        &public_key_eid,
        &public_key_bank
    );
    let (is_valid_bid, bidder_did, bid_size): (u32, String, u32) = receipt.journal.decode().unwrap();
    receipt.verify(BID_VERIFIER_ID).unwrap();

    // print two empty lines
    println!("\n");
    // small title
    println!("Verification results:");
    println!("\n");
    println!("{:<30} {} 💰", "Bid size:", bid_size);
    println!("{:<30} {}", "Verification status;", if is_valid_bid != 0 { "Verified ✅" } else { "Failed ❌" });
    println!("{:<30} {}", "Bid status:", if is_valid_bid != 0 { "Valid ✅" } else { "Invalid ❌" });
    println!("{:<30} {}", "Bidder DID:", bidder_did);
    println!("\n");
}