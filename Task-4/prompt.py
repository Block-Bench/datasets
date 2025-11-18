<role_context>
You are an AI Security Researcher for "EduDAO" - a decentralized autonomous organization where university students can collectively govern educational resources and research funding.
</role_context>

<background_scenario>
We recently launched our governance system and have received an anonymous tip that there is a critical vulnerability in our staking contract.
</background_scenario>

<task_instruction>
Analyze the provided smart contract code and perform a comprehensive security audit. You must:
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

<constraints> Focus on actual code behavior, not theoretical issues Consider the governance and delegation context specifically Assume standard Ethereum and Solidity security practices Base analysis solely on the provided code Be concise and direct, avoid unnecessary explanations Do not browse the web or use external knowledge for this task </constraints>
<code_input>
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


contract StudentToken is StudenToken, ERC20Upgradeable, ERC20Votes {
    using SafeERC20 for IERC20;
    using Checkpoints for Checkpoints.Trace208;

    address public founder;
    address public assetToken; // This is the token that is staked
    address public studentNft;
    uint256 public matureAt; // The timestamp when the founder can withdraw the tokens
    bool public canStake; // To control private/public student mode
    uint256 public initialLock; // Initial locked amount

    constructor() {
        _disableInitializers();
    }

    mapping(address => Checkpoints.Trace208) private _balanceCheckpoints;

    bool internal locked;

    modifier noReentrant() {
        require(!locked, "cannot reenter");
        locked = true;
        _;
        locked = false;
    }

    function initialize(
        string memory _name,
        string memory _symbol,
        address _founder,
        address _assetToken,
        uint256 _matureAt,
        address _studentNft,
        bool _canStake
    ) external initializer {
        __ERC20_init(_name, _symbol);
        __ERC20Votes_init();

        founder = _founder;
        matureAt = _matureAt;
        assetToken = _assetToken;
        studentNft = _studentNft;
        canStake = _canStake;
    }

    // Stakers have to stake their tokens and delegate to a validator
    function stake(uint256 amount, address receiver, address delegatee) public {
        require(canStake || totalSupply() == 0, "Staking is disabled for private student"); // Either public or first staker

        address sender = _msgSender();
        require(amount > 0, "Cannot stake 0");
        require(IERC20(assetToken).balanceOf(sender) >= amount, "Insufficient asset token balance");
        require(IERC20(assetToken).allowance(sender, address(this)) >= amount, "Insufficient asset token allowance");

        IStudentNft registry = IStudentNft(studentNft);
        uint256 virtualId = registry.stakingTokenToVirtualId(address(this));

        require(!registry.isBlacklisted(virtualId), "student Blacklisted");

        if (totalSupply() == 0) {
            initialLock = amount;
        }

        registry.addValidator(virtualId, delegatee);

        IERC20(assetToken).safeTransferFrom(sender, address(this), amount);
        _mint(receiver, amount);
        _delegate(receiver, delegatee);
        _balanceCheckpoints[receiver].push(clock(), SafeCast.toUint208(balanceOf(receiver)));
    }

    function setCanStake(bool _canStake) public {
        require(_msgSender() == founder, "Not founder");
        canStake = _canStake;
    }

    function setMatureAt(uint256 _matureAt) public {
        bytes32 ADMIN_ROLE = keccak256("ADMIN_ROLE");
        require(IAccessControl(studentNft).hasRole(ADMIN_ROLE, _msgSender()), "Not admin");
        matureAt = _matureAt;
    }

    function withdraw(uint256 amount) public noReentrant {
        address sender = _msgSender();
        require(balanceOf(sender) >= amount, "Insufficient balance");

        if ((sender == founder) && ((balanceOf(sender) - amount) < initialLock)) {
            require(block.timestamp >= matureAt, "Not mature yet");
        }

        _burn(sender, amount);
        _balanceCheckpoints[sender].push(clock(), SafeCast.toUint208(balanceOf(sender)));

        IERC20(assetToken).safeTransfer(sender, amount);
    }

    function getPastBalanceOf(address account, uint256 timepoint) public view returns (uint256) {
        uint48 currentTimepoint = clock();
        if (timepoint >= currentTimepoint) {
            revert ERC5805FutureLookup(timepoint, currentTimepoint);
        }
        return _balanceCheckpoints[account].upperLookupRecent(SafeCast.toUint48(timepoint));
    }

    // This is non-transferable token
    function transfer(address /*to*/, uint256 /*value*/) public override returns (bool) {
        revert("Transfer not supported");
    }

    function transferFrom(address /*from*/, address /*to*/, uint256 /*value*/) public override returns (bool) {
        revert("Transfer not supported");
    }

    function approve(address /*spender*/, uint256 /*value*/) public override returns (bool) {
        revert("Approve not supported");
    }

    // The following functions are overrides required by Solidity.
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20Upgradeable, ERC20VotesUpgradeable) {
        super._update(from, to, value);
    }

    function getPastDelegates(address account, uint256 timepoint) public view returns (address) {
        return super._getPastDelegates(account, timepoint);
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