# BlockBench: Blockchain Domain Expertise Benchmark Dataset

## Overview

BlockBench is a comprehensive benchmark dataset designed to evaluate AI scientist domain expertise across critical areas of blockchain development. This dataset contains carefully curated problems that test deep understanding of smart contract security, gas optimization, legal compliance, oracle integration, and cross-chain design patterns.

## Purpose

This benchmark suite aims to:

- Assess AI models' ability to identify and resolve complex blockchain vulnerabilities
- Evaluate understanding of Ethereum and other blockchain ecosystems
- Test knowledge of best practices across multiple blockchain domains
- Provide standardized problems for comparing AI performance in blockchain development

## Problem Categories

### 🔒 Security (Tasks 1-5)

The security category focuses on identifying and fixing vulnerabilities in smart contracts, including:

- Reentrancy attacks
- Access control issues
- Integer overflow/underflow vulnerabilities
- Logic errors and edge cases
- Cryptographic implementation flaws
- State manipulation vulnerabilities
- Cross-chain bridge security issues

**Current Tasks:**

- **Task-1**: Scroll Verifier Hooks Security Analysis (Rust)
- **Task-2**: Floating Point Library Security Review (Solidity)
- **Task-3**: Cross-Chain Token Bridge Security (Solidity)
- **Task-4**: Upgradeable Token Contract Security (Solidity)
- **Task-5**: Multi-Contract Security Analysis (Solidity)

### ⛽ Gas Optimization (Coming Soon)

Problems focusing on:

- Storage optimization
- Loop efficiency
- Function visibility and modifiers
- Assembly optimization
- Contract size reduction
- Transaction cost minimization

### ⚖️ Legal & Compliance (Coming Soon)

Scenarios covering:

- Regulatory compliance considerations
- Token classification issues
- Jurisdictional requirements
- AML/KYC integration patterns
- Terms of service enforcement
- Intellectual property concerns

### 🔮 Oracle Knowledge (Coming Soon)

Challenges involving:

- Oracle manipulation attacks
- Price feed reliability
- Data freshness and staleness
- Multi-oracle aggregation strategies
- Oracle failure handling
- Chainlink, Band Protocol, and other oracle integrations

### 🌉 Cross-Chain Design (Coming Soon)

Problems addressing:

- Bridge architecture patterns
- Message passing protocols
- State synchronization
- Interoperability standards
- Cross-chain asset management
- LayerZero, Wormhole, and other bridge technologies

## Dataset Structure

```
datasets/
├── Task-1/          # Security Problem 1
│   ├── problem.rs   # Problem code file
│   └── prompt_*.py  # Evaluation prompts
├── Task-2/          # Security Problem 2
│   ├── problem.sol  # Problem code file
│   └── prompt_*.py  # Evaluation prompts
├── Task-3/          # Security Problem 3
│   ├── problem.sol  # Problem code file
│   └── prompt_*.py  # Evaluation prompts
├── Task-4/          # Security Problem 4
│   ├── code.sol     # Problem code file
│   └── prompt*.py   # Evaluation prompts
├── Task-5/          # Security Problem 5
│   ├── codeblock*.sol  # Problem code files
│   └── prompt*.py      # Evaluation prompts
└── readme.md        # This file
```

## Usage

Each task directory contains:

- **Problem files**: Smart contract code (`.sol`) or Rust code (`.rs`) with intentional vulnerabilities or issues
- **Prompt files**: Python scripts containing evaluation prompts and test cases

### Evaluation Process

1. **Problem Analysis**: Review the provided code files
2. **Issue Identification**: Identify security vulnerabilities, optimization opportunities, or design flaws
3. **Solution Development**: Propose fixes or improvements
4. **Testing**: Use provided prompts to validate solutions

## Contributing

When adding new tasks:

- Ensure problems are realistic and based on real-world scenarios
- Include clear problem descriptions
- Provide evaluation criteria
- Test all prompts and solutions

## Language Support

- **Solidity**: Primary language for Ethereum smart contracts
- **Rust**: Used for blockchain infrastructure and verification systems

## Version Information

- **Current Version**: 1.0.0
- **Last Updated**: 2024

## License

[Specify your license here]

## Acknowledgments

This benchmark dataset is designed to advance AI capabilities in blockchain development and security analysis.
