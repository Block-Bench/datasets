# Blockbench Datasets

This repository contains a collection of smart contract security audit tasks designed to test domain knowledge across various blockchain and cryptographic concepts.

## Dataset Structure

Each task folder contains:

- **Problem files**: The smart contract code to be audited (`.sol` or `.rs` files)
- **Prompt files**: Python scripts containing the audit prompts and instructions
- **description.md**: A detailed description of the task's domain knowledge focus and main aspects

## Tasks Overview

### Task 1: Zero-Knowledge Proof Verification

**Domain**: Zero-knowledge proofs and cryptographic verification  
**File**: `Task-1/problem.rs`  
**Focus**: Tests knowledge of ZKP verification systems, Merkle tree traversal, Poseidon hash functions, and proof validation logic.

### Task 2: Floating Point Arithmetic Library

**Domain**: Numerical computation and precision handling  
**File**: `Task-2/problem.sol`  
**Focus**: Tests knowledge of floating-point arithmetic, precision management, mathematical operations, and assembly-level optimizations.

### Task 3: Cross-Chain Token Bridge

**Domain**: Cross-chain protocols and LayerZero integration  
**File**: `Task-3/problem.sol`  
**Focus**: Tests knowledge of cross-chain token bridging, LayerZero OFT standard, transfer restrictions, and access control mechanisms.

### Task 4: Staking Token Contract

**Domain**: Token staking and delegation systems  
**File**: `Task-4/code.sol`  
**Focus**: Tests knowledge of staking mechanisms, ERC20Votes delegation, upgradeable contracts, and reentrancy protection.

### Task 5: Staking Accounting System

**Domain**: Staking economics and exchange rate calculations  
**File**: `Task-5/mergedcode.sol`  
**Focus**: Tests knowledge of staking economics, dynamic exchange rates, withdrawal queue systems, and multi-manager coordination.

## Usage

Each task is designed to evaluate security auditing capabilities in specific blockchain domains. Review the `description.md` file in each task folder for detailed information about what domain knowledge is being tested.

## Playground

The `playground/` directory contains additional markdown files for testing and experimentation.
