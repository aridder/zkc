# Enhanced Privacy in Real Estate Transactions with RISC Zero zkVM and Verifiable Credentials

This is a project for the [ZK Hack Istanbul](https://www.zkistanbul.com/) hackathon.

Thank you to the [RISC Zero](https://dev.risczero.com/) team for their support and guidance throughout the hackathon. 

Also, thank you to the [ZK Hack](https://zkhack.dev/) team for organizing this event. It was a great experience!

## Quick Start

The host program reads the `data.json` file and passes the data to the guest.
This is where bid_size is set. You can change this to see if the program fails is set above the loan amount.

First, make sure [rustup](https://rustup.rs/) is installed. The
[`rust-toolchain.toml`][rust-toolchain] file will be used by `cargo` to
automatically install the correct version.

To build all methods and execute the method within the zkVM, run the following
command:

To run in development mode, run the following command:

```bash
RISC0_DEV_MODE=true cargo run
````
*Caution - When running in DEV mode, the receipt is fake!*

To run for production, and get a real receipt, run the following command:

```bash
cargo run
```

## Overview

This project harnesses the power of RISC Zero's zkVM to demonstrate an enhanced privacy application in real estate
transactions.
It specifically explores the utilization of Verifiable Credentials from eIDAS 2.0 for EU citizens, showcasing how these
credentials
can be used in a more private manner through Zero-Knowledge Proofs (ZKP) in real-world scenarios.

## Objectives

- To demonstrate the effective use of RISC Zero's zkVM in privacy-centric applications.
- To explore the application of Verifiable Credentials in maintaining privacy in financial transactions.
- To investigate the potential of eIDAS 2.0 Verifiable Credentials in enhancing privacy for EU citizens, particularly in
  hiding sensitive information like maximum bid amounts in real estate bidding and social security numbers in other use
  cases.

## Implementation

The application employs two key Verifiable Credentials:

1. *PersonCredential*: A credential verified by a trusted electronic ID (eID) provider, affirming the identity of the
   individual.
2. *HouseLoanCredential*: A credential from a bank, detailing the maximum bid amount and the expiration date for the
   granted privilege.
   These credentials are signed by respective issuers and authenticated by the user.

## Core Process:

1. Credential Submission: Users submit signed JWTs for PersonCredential and HouseLoanCredential.
2. The RISC Zero zkVM runs the guest code, which performs the following checks:
    - Validation of JWT signatures and data.
    - Comparison of the bid size with the loan amount. If the bid exceeds the loan amount, the process fails.
3. Output Generation: Upon successful validation, the system generates:
    - A Receipt with a cryptographic seal.
    - A Journal containing the public output, accessible via receipt.journal.

## Technology Stack

[RISC Zero zkVM](https://dev.risczero.com/)
[Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) - All citizens will have a digital wallet that contains
their credentials from 2026/2027.

## Key Features

* Enhanced Privacy: Employs ZKP to verify transactions without exposing sensitive personal and financial details.
* Secure Transaction Validation: Ensures financial integrity by validating bid amounts against pre-approved loans.
* Versatile Application: Demonstrates the potential of Verifiable Credentials with ZK beyond real estate, such as
  providing proof of age without revealing full social security numbers.

## Running proofs remotely on Bonsai

_Note: The Bonsai proving service is still in early Alpha; an API key is
required for access. [Click here to request access][bonsai access]._

If you have access to the URL and API key to Bonsai you can run your proofs
remotely. To prove in Bonsai mode, invoke `cargo run` with two additional
environment variables:

```bash
BONSAI_API_KEY="YOUR_API_KEY" BONSAI_API_URL="BONSAI_URL" cargo run
```

## Directory Structure

It is possible to organize the files for these components in various ways.
However, in this starter template we use a standard directory structure for zkVM
applications, which we think is a good starting point for your applications.

```text
zkc
├── data.json                             <-- [Mock data - Verfiable Credentials, public keys, etc.]
├── Cargo.toml
├── host
│   ├── Cargo.toml
│   └── src
│       └── main.rs                        <-- [Host code for running the zkVM]
└── methods
    ├── Cargo.toml
    ├── build.rs
    ├── guest
    │   ├── Cargo.toml
    │   └── src
    │       └── main.rs                   <-- [Guest code for house bid, jwt validation, etc.]
    └── src
        └── lib.rs
```
