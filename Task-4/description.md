# Task 4: Staking Token Contract

## Domain Knowledge Focus
This task tests domain knowledge on **token staking mechanisms**, **delegation systems**, and **upgradeable contract patterns**.

## Main Aspects
- **Staking Mechanism**: Implements a staking system where users stake asset tokens to receive staking tokens (non-transferable)
- **Voting and Delegation**: Integrates ERC20Votes for delegation to validators and historical balance tracking using checkpoints
- **Access Control**: Manages founder privileges, admin roles, and staking mode control (public/private)
- **Upgradeable Pattern**: Uses OpenZeppelin's upgradeable contracts pattern with initializers
- **Reentrancy Protection**: Implements custom reentrancy guards for withdrawal operations
- **Maturity Lock**: Enforces time-based restrictions on founder withdrawals based on initial lock amounts

## Key Technical Concepts
- Token staking systems
- ERC20Votes and delegation
- Upgradeable contract patterns
- Reentrancy protection
- Checkpoint-based historical tracking
- Access control and role management

