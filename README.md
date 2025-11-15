# monerochan.rs

<div align="center">

![Header](assets/header.gif)

[![Website][ico-website]][link-website]
[![Twitter][ico-twitter]][link-twitter]
[![Discord][ico-discord]][link-discord]
[![Telegram][ico-telegram]][link-telegram]
![GitHub top language](https://img.shields.io/github/languages/top/Monero-Chan-Foundation/monerochan.rs)

</div>

## Overview

> **THE RISC-V PRIVATE PROVING RUNTIME**

**MONEROCHAN.RS** is a **privacy runtime** for executing **RISC-V programs** under **verifiable confidentiality**.  
It uses **zkSNARK-based proof generation** to prove correct execution of programs without exposing inputs, state, or outputs.  

Inspired by **Monero** and **Zcash**, it extends privacy from *payments* to *computation*, enabling developers to build systems that are both **trustless** and **confidential**.

## Problem / Solution

### The Problem

Existing privacy technologies like **Monero** and **Zcash** protect *transactions*, not *computation*.  
They ensure confidential payments and balances, but they don’t support private logic, state transitions, or data processing.  

Developers today face hard limitations:
- Application logic and user data are fully visible during execution.  
- Privacy systems are domain-specific (e.g., shielded transactions) and non-generalizable.  
- Building verifiable private computation still requires deep cryptographic expertise.  

There is no open, general-purpose framework for **private, verifiable computation**.

### The Solution

**MONEROCHAN.RS** introduces a **RISC-V privacy runtime** that combines:
- **Deterministic program execution**, ensuring verifiable reproducibility.  
- **zkSNARK-based proofs**, guaranteeing correctness without revealing data.  
- **Optimized cryptographic precompiles**, enabling real-world performance for privacy workloads.  

This architecture allows developers to build applications such as:
- **Private data collaboration** — compute on encrypted data without disclosure.  
- **Private AI inference** — run models on confidential inputs verifiably.  
- **Private DeFi** — enable on-chain logic without revealing user state.  
- **Confidential rollups and bridges** — bridge ecosystems with strong privacy guarantees.  

MONEROCHAN.RS extends privacy from **value** to **computation**, forming the foundation for a new class of decentralized, private applications.

## Getting Started

1. **Install the CLI**:
   ```sh
   cargo install monerochan-cli
   ```

2. **Create an example project**:
   ```sh
   cargo monerochan new my-project
   cd my-project
   ```

3. **Read the project README** for detailed instructions:
   ```sh
   cat README.md
   ```

The project template includes a complete example with instructions for executing programs and generating proofs.

### Resources

- **Example Template**: [monerochan-project-template](https://github.com/Monero-Chan-Foundation/monerochan-project-template) — Get started with a ready-to-use project template
- **Published Crates**: [crates.io/users/monerochanorg](https://crates.io/users/monerochanorg) — View all published MONEROCHAN.RS crates

## Architecture

| Component | Description |
|------------|--------------|
| **RISC-V Runtime** | Deterministic execution environment for private workloads |
| **Proof Engine** | Generates zkSNARK proofs of correct execution |
| **Precompiles** | Optimized primitives for signature and hash verification |
| **Host Interface** | Rust API for program execution and proof verification |

## Cryptographic Capabilities

### Signature Verification
- **Secp256r1 / ECDSA** — Private verification for traditional signatures  
- **Ed25519** — Privacy-preserving signature verification  
- **RSA (BigInt)** — Confidential interoperability with legacy systems  

### Hash Functions
- **Keccak**, **SHA-256**, **Blake3** — Hash primitives optimized for proof systems

## Performance

MONEROCHAN.RS achieves **order-of-magnitude performance improvements** for privacy workloads through optimized arithmetic and RISC-V precompiles.  
The runtime is engineered for:
- Private rollups and bridges  
- Privacy-preserving DeFi  
- Private AI and data collaboration  
- Cross-domain confidential computation  

[ico-website]: https://img.shields.io/website?up_color=blue&up_message=monero-chan&url=https%3A%2F%2Fmonero-chan.org
[ico-twitter]: https://img.shields.io/badge/@MoneroChanSOL-1DA1F2.svg?style=flat-square&logo=x&label=Twitter
[ico-discord]: https://img.shields.io/badge/Discord-5865F2.svg?style=flat-square&logo=discord&label=Discord
[ico-telegram]: https://img.shields.io/badge/@MoneroChanSOL-2CA5E0.svg?style=flat-square&logo=telegram&label=Telegram

[link-website]: https://monero-chan.org/
[link-twitter]: https://twitter.com/MoneroChanSOL
[link-discord]: https://discord.gg/H7S5S9SEdZ
[link-telegram]: https://t.me/MoneroChanSOL
# monerochanrs-private
