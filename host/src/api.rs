use axum::{
    routing::post,
    extract::Json,
    response::IntoResponse,
    Router,
};
use serde::{Deserialize, Serialize};
use crate::{ProofRequest, prove_predicate, PREDICATE_VERIFIER_ID};

#[derive(Serialize)]
pub struct VerifyPredicateResponse {
    issuer: String,
    subject: String,
    result_list: Vec<String>,
}

pub async fn verify_predicate_handler(Json(req): Json<ProofRequest>) -> impl IntoResponse {
    // log the received JSON for debugging
    println!("VERIFY_PREDICATE_HANDLER: Received JSON: {:?}", req);

    // For now, use the first credential and public key
    let credential = match req.credentials.get(0) {
        Some(c) => c,
        None => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };
    let public_key = match req.public_keys.get(0) {
        Some(k) => &k.public_key,
        None => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };
    let predicate_list = req.predicates;

    let receipt = prove_predicate(&credential.proof.jwt, public_key, predicate_list);

    let (issuer, subject, result_list): (String, String, Vec<String>) = match receipt.journal.decode() {
        Ok(res) => res,
        Err(_e) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if let Err(_) = receipt.verify(PREDICATE_VERIFIER_ID) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    axum::Json(VerifyPredicateResponse {
        issuer,
        subject,
        result_list,
    }).into_response()
}
pub fn app() -> Router {
    Router::new().route("/verify_predicate", post(verify_predicate_handler))
}