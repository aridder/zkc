use jwt_compact::{alg::*, prelude::*, Token, UntrustedToken};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{VerifyingKey};

// Define your structs
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

// This is your JSON string
static VC: &str = r#"{
    "credentialSubject": {
        "dateOfBirth": "01.05.1988",
        "id": "did:key:z6Mkupors21MizHYzXxgvU3rPC7cWtSk9Papif2caQsfzX1T"
    },
    "issuer": { "id": "did:key:z6MkrbwwWbJMkExK7To2qdhKFv8KCd2nKAhopRgCyHWjH2bg" },
    "type": [ "VerifiableCredential", "PersonCredential" ],
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://veramo.io/contexts/profile/v1"
    ],
    "issuanceDate": "2023-11-11T09:14:07.000Z",
    "proof": {
        "type": "JwtProof2020",
        "jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdmVyYW1vLmlvL2NvbnRleHRzL3Byb2ZpbGUvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlBlcnNvbkNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGF0ZU9mQmlydGgiOiIwMS4wNS4xOTg4In19LCJzdWIiOiJkaWQ6a2V5Ono2TWt1cG9yczIxTWl6SFl6WHhndlUzclBDN2NXdFNrOVBhcGlmMmNhUXNmelgxVCIsIm5iZiI6MTY5OTY5NDA0NywiaXNzIjoiZGlkOmtleTp6Nk1rcmJ3d1diSk1rRXhLN1RvMnFkaEtGdjhLQ2QybktBaG9wUmdDeUhXakgyYmcifQ.76ksY2vmKksoV3N5b5zmBbaqLaT1Xcb45GIxAn9VhQX6iKzcDKFr-TG5x_7YhGuz5y02_7h7Qu2wuG04kEI0DA"
    }
}"#;


static PUBLIC_KEY: &str = "b485ffcb862a33c9709267794bf85192b44d059788fad133ed5d11fa62a6383f";

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

// Deserialize the JSON string to Rust struct

// Use the deserialized object
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_parse_vc() {
        let vc: VerifiableCredential = serde_json::from_str(VC).unwrap();
        assert_eq!(vc.credential_subject.date_of_birth, "01.05.1988");
    }

    #[test]
    fn decode_proof_test() {
        let is_valid_vc = verify_credential(VC, PUBLIC_KEY);
        assert_eq!(is_valid_vc, true);
    }
}

pub fn verify_credential(jwt: &str, public_key: &str) -> bool {
    let vc: VerifiableCredential = serde_json::from_str(jwt).unwrap();

    // Extract the JWT string
    let jwt_str = &vc.proof.jwt;
    let public_key_bytes:&[u8; 32] = &hex::decode(public_key).unwrap().try_into().unwrap();

    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
    let token = UntrustedToken::new(&jwt_str).unwrap();
    let token: Token<VCClaims> = Ed25519.validator(&verifying_key).validate(&token).unwrap();
    println!("token: {:?}", token);
    true
}