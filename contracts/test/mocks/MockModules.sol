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

/// @dev Hook that only lets single calls to one allowed address through, the shape of a spending policy.
contract MockHook is IERC7579Hook {
    error Blocked();

    mapping(address account => address) public allowed;
    mapping(address account => uint256) public preChecks;
    mapping(address account => uint256) public postChecks;

    function onInstall(bytes calldata data) external {
        allowed[msg.sender] = abi.decode(data, (address));
    }

    function onUninstall(bytes calldata) external {
        delete allowed[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function preCheck(address, uint256, bytes calldata msgData) external returns (bytes memory) {
        if (bytes4(msgData) == IERC7579Execution.execute.selector) {
            (, bytes memory executionCalldata) = abi.decode(msgData[4:], (bytes32, bytes));
            address target = address(bytes20(executionCalldata));
            if (target != allowed[msg.sender]) revert Blocked();
        }
        ++preChecks[msg.sender];
        return "";
    }

    function postCheck(bytes calldata) external {
        ++postChecks[msg.sender];
    }
}

contract MockExecutor is IERC7579Module {
    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

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
