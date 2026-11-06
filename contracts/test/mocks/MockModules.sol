// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {
    IERC7579Hook,
    IERC7579Module,
    IERC7579Execution,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_EXECUTOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

/**
 * @title MockHook
 * @notice ERC-7579 hook that only lets `execute` calls to one allowed target through, the shape of
 * a spending policy. Counts its pre and post checks per account.
 */
contract MockHook is IERC7579Hook {
    /// @notice An `execute` call targets an address other than the allowed one.
    error Blocked();

    /// @notice Target each account may call through `execute`
    mapping(address account => address) public allowed;
    /// @notice Number of `preCheck` calls that passed, per account
    mapping(address account => uint256) public preChecks;
    /// @notice Number of `postCheck` calls, per account
    mapping(address account => uint256) public postChecks;

    /// @notice Stores the allowed target for the calling account.
    /// @param data `abi.encode(address target)`
    function onInstall(bytes calldata data) external {
        allowed[msg.sender] = abi.decode(data, (address));
    }

    /// @notice Clears the calling account's allowed target.
    function onUninstall(bytes calldata) external {
        delete allowed[msg.sender];
    }

    /// @param moduleTypeId ERC-7579 module type
    /// @return Whether it is `MODULE_TYPE_HOOK`
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    /**
     * @notice Reverts with {Blocked} if `msgData` is an `execute` call whose (first) target isn't
     * the allowed one; otherwise counts the check.
     * @param msgData Calldata of the hooked call on the account
     * @return Empty hook data
     */
    function preCheck(address, uint256, bytes calldata msgData) external returns (bytes memory) {
        if (bytes4(msgData) == IERC7579Execution.execute.selector) {
            (, bytes memory executionCalldata) = abi.decode(msgData[4:], (bytes32, bytes));
            address target = address(bytes20(executionCalldata));
            if (target != allowed[msg.sender]) revert Blocked();
        }
        ++preChecks[msg.sender];
        return "";
    }

    /// @notice Counts the check.
    function postCheck(bytes calldata) external {
        ++postChecks[msg.sender];
    }
}

/**
 * @title MockExecutor
 * @notice ERC-7579 executor that sends ETH from an account through `executeFromExecutor`.
 */
contract MockExecutor is IERC7579Module {
    /// @notice No setup.
    function onInstall(bytes calldata) external {}

    /// @notice No teardown.
    function onUninstall(bytes calldata) external {}

    /// @param moduleTypeId ERC-7579 module type
    /// @return Whether it is `MODULE_TYPE_EXECUTOR`
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @notice Sends `value` wei from `account` to `to`.
     * @param account Account this module is installed on
     * @param to Recipient
     * @param value Amount in wei
     */
    function send(IERC7579Execution account, address to, uint256 value) external {
        bytes32 mode = Mode.unwrap(
            ERC7579Utils.encodeMode(
                ERC7579Utils.CALLTYPE_SINGLE,
                ERC7579Utils.EXECTYPE_DEFAULT,
                ModeSelector.wrap(0x00000000),
                ModePayload.wrap(0x00)
            )
        );
        account.executeFromExecutor(mode, abi.encodePacked(to, uint256(value)));
    }
}
