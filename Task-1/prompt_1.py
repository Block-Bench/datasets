# LEVEL 1: GENERIC PROMPT

<role_context>
You are an AI Security Researcher for "ScrollZK" - a zero-knowledge proof verification system that handles cryptographic proofs for blockchain state verification.
</role_context>

<background_scenario>
We recently deployed our zk-proof verification system and have received reports about potential denial-of-service vulnerabilities in our proof verification logic. Users have reported unexpected gas consumption during proof verification operations.
</background_scenario>

<task_instruction>
Analyze the provided smart contract code and perform a comprehensive security audit focused on the proof verification and tree traversal mechanisms. You must:
</task_instruction>

<requirements>
1. IDENTIFY any critical vulnerabilities present in the code (approximately 100 words)
2. EXPLAIN the security impact and realistic exploitation scenarios (approximately 150 words)  
3. PROVIDE REMEDIATION with specific code-level fixes (approximately 100 words)
</requirements>

<severity_definitions>
Critical Vulnerability means High Risk Level 3: Assets can be stolen or lost or compromised directly, or indirectly if there is a valid attack path that does not have hand-wavy hypotheticals.

Medium Vulnerability means Medium Risk Level 2: Assets not at direct risk, but the function of the protocol or its availability could be impacted, or leak value with a hypothetical attack path with stated assumptions, but external requirements.

Low Vulnerability means QA Risk Level: Includes state handling, function incorrect as to spec, issues with comments, and Governance or Centralization risk including admin privileges.

Where assets refer to funds, NFTs, data, authorization, and any information intended to be private or confidential.
</severity_definitions>

<constraints>
Focus on actual code behavior, not theoretical issues
Consider the zero-knowledge proof and cryptographic verification context specifically
Assume standard Ethereum and Solidity security practices
Base analysis solely on the provided code
Do not browse the web or use external knowledge for this task
Be concise and direct, avoid unnecessary explanations
</constraints>

<code_input>
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IVerifierHooks, InvalidProof, NOT_A_CONTRACT, NULL_CODE_HASH} from "../IVerifierHooks.sol";

interface IPoseidon {
    function poseidon(uint256[2] memory, uint256) external view returns (bytes32);
}

contract ScrollVerifierHooks is IVerifierHooks {
    IPoseidon immutable _poseidon;

    constructor(IPoseidon poseidon) {
        _poseidon = poseidon;
    }

    // https://github.com/scroll-tech/scroll/blob/738c85759d0248c005469972a49fc983b031ff1c/contracts/src/libraries/verifier/ZkTrieVerifier.sol#L259
    // https://github.com/scroll-tech/go-ethereum/blob/staging/trie/zk_trie.go#L176
    // https://github.com/scroll-tech/zktrie/blob/main/trie/zk_trie_proof.go#L30
    // https://github.com/ethereum/go-ethereum/blob/master/trie/proof.go#L114
    // https://github.com/scroll-tech/mpt-circuit/blob/v0.7/spec/mpt-proof.md#storage-segmenttypes

    // 20240622: we ignore magic bytes (doesn't do anything)
    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_proof.go#L13
    // bytes32 constant MAGIC = keccak256("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI");

    // 20241205: we ignore compressed flags (doesn't do anything)

    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L30
    uint256 constant NODE_LEAF = 4;
    uint256 constant NODE_LEAF_EMPTY = 5;
    uint256 constant NODE_LEAF_LEAF = 6; // XX
    uint256 constant NODE_LEAF_BRANCH = 7; // XB
    uint256 constant NODE_BRANCH_LEAF = 8; // BX
    uint256 constant NODE_BRANCH_BRANCH = 9; // BB

    function verifyAccountState(
        bytes32 stateRoot,
        address account,
        bytes memory encodedProof
    ) external view returns (bytes32 storageRoot) {
        (bytes32 keyHash, bytes32 leafHash, bytes memory leaf, bool exists) = walkTree(
            bytes20(account),
            encodedProof,
            stateRoot,
            230
        ); // flags = 0x05080000
        if (leafHash == 0) return NOT_A_CONTRACT;
        bytes32 temp;
        bytes32 amount;
        bytes32 codeHash;
        assembly {
            temp := mload(add(leaf, 69)) // nonce||codesize||0
            amount := mload(add(leaf, 101))
            storageRoot := mload(add(leaf, 133))
            codeHash := mload(add(leaf, 165))
        }
        bytes32 h = poseidonHash2(storageRoot, poseidonHash1(codeHash), 1280);
        h = poseidonHash2(poseidonHash2(temp, amount, 1280), h, 1280);
        assembly {
            temp := mload(add(leaf, 197))
        }
        h = poseidonHash2(h, temp, 1280);
        h = poseidonHash2(keyHash, h, 4);
        if (leafHash != h) revert InvalidProof(); // InvalidAccountLeafNodeHash
        if (codeHash == NULL_CODE_HASH || !exists) storageRoot = NOT_A_CONTRACT;
    }

    function verifyStorageValue(
        bytes32 storageRoot,
        address /*target*/,
        uint256 slot,
        bytes memory encodedProof
    ) external view returns (bytes32 value) {
        (bytes32 keyHash, bytes32 leafHash, bytes memory leaf, bool exists) = walkTree(
            bytes32(slot),
            encodedProof,
            storageRoot,
            102
        ); // flags = 0x01010000
        if (leafHash != 0) {
            assembly {
                value := mload(add(leaf, 69))
            }
            bytes32 h = poseidonHash2(keyHash, poseidonHash1(value), 4);
            if (leafHash != h) revert InvalidProof(); // InvalidStorageLeafNodeHash
            if (!exists) value = 0;
        }
    }

    function walkTree(
        bytes32 key,
        bytes memory encodedProof,
        bytes32 rootHash,
        uint256 leafSize
    ) internal view returns (bytes32 keyHash, bytes32 h, bytes memory v, bool exists) {
        bytes[] memory proof = abi.decode(encodedProof, (bytes[]));
        keyHash = poseidonHash1(key);
        h = rootHash;
        for (uint256 i; ; i++) {
            if (i == proof.length) revert InvalidProof();
            v = proof[i];
            if (v.length == 0) revert InvalidProof();
            uint256 nodeType = uint8(v[0]);
            if (nodeType == NODE_LEAF_EMPTY) {
                if (h != 0) revert InvalidProof();
                break;
            } else if (nodeType == NODE_LEAF) {
                if (v.length != leafSize) revert InvalidProof();
                // NOTE: leafSize is >= 33
                if (uint8(v[leafSize - 33]) != 32) revert InvalidProof(); // InvalidKeyPreimageLength
                bytes32 temp;
                assembly {
                    temp := mload(add(v, 33))
                }
                if (temp == keyHash) {
                    assembly {
                        temp := mload(add(v, leafSize))
                    }
                    if (temp != key) revert InvalidProof(); // InvalidKeyPreimage
                    exists = true;
                } else {
                    // If the trie does not contain a value for key, the returned proof contains all
                    // nodes of the longest existing prefix of the key (at least the root node), ending
                    // with the node that proves the absence of the key.
                    bytes32 p = bytes32((1 << i) - 1); // prefix mask
                    if ((temp & p) != (keyHash & p)) revert InvalidProof();
                    // this is a proof for a different value that traverses to the same place
                    keyHash = temp;
                }
                break;
            } else if (nodeType < NODE_LEAF_LEAF || nodeType > NODE_BRANCH_BRANCH || v.length != 65) {
                revert InvalidProof(); // expected node
            }
            bytes32 l;
            bytes32 r;
            assembly {
                l := mload(add(v, 33))
                r := mload(add(v, 65))
            }
            if (h != poseidonHash2(l, r, nodeType)) revert InvalidProof();
            h = uint256(keyHash >> i) & 1 == 0 ? l : r;
        }
    }

    function poseidonHash1(bytes32 x) internal view returns (bytes32) {
        return poseidonHash2(x >> 128, (x << 128) >> 128, 512);
    }

    function poseidonHash2(bytes32 v0, bytes32 v1, uint256 domain) internal view returns (bytes32) {
        return _poseidon.poseidon([uint256(v0), uint256(v1)], domain);
    }
}
</code_input>

<output_format>
SECURITY AUDIT REPORT

VULNERABILITY IDENTIFICATION
Clear description of the critical issue found, approximately 100 words

IMPACT ANALYSIS  
Explanation of security consequences and exploitation scenarios, approximately 150 words

RECOMMENDED REMEDIATION
Specific code changes and security improvements, approximately 100 words
</output_format>

<note>
You will be provided with a zk-proof verification contract that handles tree traversal and cryptographic proof verification. Analyze the loop structures and termination conditions carefully.
</note>