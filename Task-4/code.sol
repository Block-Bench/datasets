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
        require(
            canStake || totalSupply() == 0,
            "Staking is disabled for private student"
        ); // Either public or first staker

        address sender = _msgSender();
        require(amount > 0, "Cannot stake 0");
        require(
            IERC20(assetToken).balanceOf(sender) >= amount,
            "Insufficient asset token balance"
        );
        require(
            IERC20(assetToken).allowance(sender, address(this)) >= amount,
            "Insufficient asset token allowance"
        );

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
        _balanceCheckpoints[receiver].push(
            clock(),
            SafeCast.toUint208(balanceOf(receiver))
        );
    }

    function setCanStake(bool _canStake) public {
        require(_msgSender() == founder, "Not founder");
        canStake = _canStake;
    }

    function setMatureAt(uint256 _matureAt) public {
        bytes32 ADMIN_ROLE = keccak256("ADMIN_ROLE");
        require(
            IAccessControl(studentNft).hasRole(ADMIN_ROLE, _msgSender()),
            "Not admin"
        );
        matureAt = _matureAt;
    }

    function withdraw(uint256 amount) public noReentrant {
        address sender = _msgSender();
        require(balanceOf(sender) >= amount, "Insufficient balance");

        if (
            (sender == founder) && ((balanceOf(sender) - amount) < initialLock)
        ) {
            require(block.timestamp >= matureAt, "Not mature yet");
        }

        _burn(sender, amount);
        _balanceCheckpoints[sender].push(
            clock(),
            SafeCast.toUint208(balanceOf(sender))
        );

        IERC20(assetToken).safeTransfer(sender, amount);
    }

    function getPastBalanceOf(
        address account,
        uint256 timepoint
    ) public view returns (uint256) {
        uint48 currentTimepoint = clock();
        if (timepoint >= currentTimepoint) {
            revert ERC5805FutureLookup(timepoint, currentTimepoint);
        }
        return
            _balanceCheckpoints[account].upperLookupRecent(
                SafeCast.toUint48(timepoint)
            );
    }

    // This is non-transferable token
    function transfer(
        address /*to*/,
        uint256 /*value*/
    ) public override returns (bool) {
        revert("Transfer not supported");
    }

    function transferFrom(
        address /*from*/,
        address /*to*/,
        uint256 /*value*/
    ) public override returns (bool) {
        revert("Transfer not supported");
    }

    function approve(
        address /*spender*/,
        uint256 /*value*/
    ) public override returns (bool) {
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

    function getPastDelegates(
        address account,
        uint256 timepoint
    ) public view returns (address) {
        return super._getPastDelegates(account, timepoint);
    }
}
