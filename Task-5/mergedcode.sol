// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ========== IMPORTS ========== */

import {AccessControlEnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IStakingAccountant} from "./interfaces/IStakingAccountant.sol";

/**
 * @title StakingAccountant
 * @notice Manages global staking accounting and exchange rate calculations
 * @dev Implements upgradeable patterns with role-based access control
 */
contract StakingAccountant is
    IStakingAccountant,
    Initializable,
    AccessControlEnumerableUpgradeable
{
    using EnumerableMap for EnumerableMap.AddressToAddressMap;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /* ========== STATE VARIABLES ========== */

    // Constants
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    // Global accounting
    uint256 public totalStaked;
    uint256 public totalClaimed;
    uint256 public totalRewards;
    uint256 public totalSlashing;

    // Map StakingManager to their kHYPE token
    EnumerableMap.AddressToAddressMap private _authorizedManagers;

    // Track unique kHYPE tokens
    EnumerableSet.AddressSet private _uniqueTokens;

    uint256 public totalQueuedWithdrawals;
    mapping(address => mapping(uint256 => WithdrawalRequest))
        private _withdrawalRequests;
    mapping(address => uint256) public nextWithdrawalId;

    uint256 public withdrawalDelay;
    uint256 public unstakeFeeRate;
    uint256 public constant BASIS_POINTS = 10000;

    /* ========== MODIFIERS ========== */

    modifier onlyAuthorizedManager() {
        require(_authorizedManagers.contains(msg.sender), "Not authorized");
        _;
    }

    /* ========== INITIALIZATION ========== */

    function initialize(address admin, address manager) public initializer {
        require(admin != address(0), "Invalid admin address");
        require(manager != address(0), "Invalid manager address");

        __AccessControlEnumerable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, manager);

        withdrawalDelay = 7 days;
        unstakeFeeRate = 10;
    }

    /* ========== MANAGER FUNCTIONS ========== */

    function authorizeStakingManager(
        address manager,
        address kHYPEToken
    ) external onlyRole(MANAGER_ROLE) {
        require(manager != address(0), "Invalid manager address");
        require(kHYPEToken != address(0), "Invalid kHYPE token address");
        require(!_authorizedManagers.contains(manager), "Already authorized");

        _authorizedManagers.set(manager, kHYPEToken);

        _uniqueTokens.add(kHYPEToken);

        emit StakingManagerAuthorized(manager, kHYPEToken);
    }

    function deauthorizeStakingManager(
        address manager
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool exists, address token) = _authorizedManagers.tryGet(manager);
        require(exists, "Manager not found");

        _authorizedManagers.remove(manager);

        bool tokenStillInUse = false;
        uint256 length = _authorizedManagers.length();

        for (uint256 i = 0; i < length; i++) {
            (, address otherToken) = _authorizedManagers.at(i);
            if (otherToken == token) {
                tokenStillInUse = true;
                break;
            }
        }

        if (!tokenStillInUse) {
            _uniqueTokens.remove(token);
        }

        emit StakingManagerDeauthorized(manager);
    }

    /* ========== MUTATIVE FUNCTIONS ========== */

    function recordStake(
        uint256 amount
    ) external override onlyAuthorizedManager {
        totalStaked += amount;
        emit StakeRecorded(msg.sender, amount);
    }

    function recordClaim(
        uint256 amount
    ) external override onlyAuthorizedManager {
        totalClaimed += amount;
        emit ClaimRecorded(msg.sender, amount);
    }

    /* ========== VIEW FUNCTIONS ========== */

    function isAuthorizedManager(
        address manager
    ) external view override returns (bool) {
        return _authorizedManagers.contains(manager);
    }

    function getManagerToken(address manager) external view returns (address) {
        (bool exists, address token) = _authorizedManagers.tryGet(manager);
        require(exists, "Manager not authorized");
        return token;
    }

    function getAuthorizedManagerCount() external view returns (uint256) {
        return _authorizedManagers.length();
    }

    function getAuthorizedManagerAt(
        uint256 index
    ) external view returns (address manager, address token) {
        require(index < _authorizedManagers.length(), "Index out of bounds");
        (manager, token) = _authorizedManagers.at(index);
    }

    function getUniqueTokenCount() external view returns (uint256) {
        return _uniqueTokens.length();
    }

    function getUniqueTokenAt(uint256 index) external view returns (address) {
        require(index < _uniqueTokens.length(), "Index out of bounds");
        return _uniqueTokens.at(index);
    }

    function totalRewards() external view override returns (uint256) {
        return totalRewards;
    }

    function totalSlashing() external view override returns (uint256) {
        return totalSlashing;
    }

    function kHYPEToHYPE(
        uint256 kHYPEAmount
    ) public view override returns (uint256) {
        return Math.mulDiv(kHYPEAmount, _getExchangeRatio(), 1e18);
    }

    function HYPEToKHYPE(
        uint256 HYPEAmount
    ) public view override returns (uint256) {
        uint256 exchangeRatio = _getExchangeRatio();
        require(exchangeRatio > 0, "Invalid exchange ratio");
        return Math.mulDiv(HYPEAmount, 1e18, exchangeRatio);
    }

    /* ========== INTERNAL FUNCTIONS ========== */

    function _getExchangeRatio() internal view returns (uint256) {
        uint256 totalKHYPESupply = 0;
        uint256 uniqueTokenCount = _uniqueTokens.length();

        for (uint256 i = 0; i < uniqueTokenCount; i++) {
            address tokenAddress = _uniqueTokens.at(i);
            totalKHYPESupply += IERC20(tokenAddress).totalSupply();
        }

        if (totalKHYPESupply == 0) {
            return 1e18;
        }

        uint256 rewardsAmount = totalRewards;
        uint256 slashingAmount = totalSlashing;
        uint256 totalHYPE = totalStaked +
            rewardsAmount -
            totalClaimed -
            slashingAmount;

        return Math.mulDiv(totalHYPE, 1e18, totalKHYPESupply);
    }

    function queueWithdrawal(uint256 kHYPEAmount) external {
        require(kHYPEAmount > 0, "Invalid amount");

        uint256 withdrawalId = nextWithdrawalId[msg.sender];

        uint256 kHYPEFee = Math.mulDiv(
            kHYPEAmount,
            unstakeFeeRate,
            BASIS_POINTS
        );
        uint256 postFeeKHYPE = kHYPEAmount - kHYPEFee;

        uint256 hypeAmount = kHYPEToHYPE(postFeeKHYPE);

        _withdrawalRequests[msg.sender][withdrawalId] = WithdrawalRequest({
            hypeAmount: hypeAmount,
            kHYPEAmount: postFeeKHYPE,
            kHYPEFee: kHYPEFee,
            timestamp: block.timestamp
        });

        nextWithdrawalId[msg.sender]++;
        totalQueuedWithdrawals += hypeAmount;

        emit WithdrawalQueued(
            msg.sender,
            withdrawalId,
            kHYPEAmount,
            hypeAmount,
            kHYPEFee
        );
    }

    function withdrawalRequests(
        address user,
        uint256 id
    ) external view returns (WithdrawalRequest memory) {
        return _withdrawalRequests[user][id];
    }

    function reportRewards(uint256 amount) external {
        totalRewards += amount;
    }

    function reportSlashing(uint256 amount) external {
        totalSlashing += amount;
    }

    struct WithdrawalRequest {
        uint256 hypeAmount;
        uint256 kHYPEAmount;
        uint256 kHYPEFee;
        uint256 timestamp;
    }

    event WithdrawalQueued(
        address indexed user,
        uint256 indexed withdrawalId,
        uint256 kHYPEAmount,
        uint256 hypeAmount,
        uint256 kHYPEFee
    );
}
