// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {W3pkAccountFactory} from "../src/W3pkAccountFactory.sol";

/// @notice Deploys the factory, and with it the implementation, at the same address on every chain.
contract Deploy is Script {
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 constant SALT = bytes32(0);

    function run() external returns (W3pkAccountFactory factory) {
        factory = W3pkAccountFactory(
            vm.computeCreate2Address(SALT, keccak256(type(W3pkAccountFactory).creationCode), CREATE2_DEPLOYER)
        );
        if (address(factory).code.length == 0) {
            vm.broadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
            new W3pkAccountFactory{salt: SALT}();
        }
        address implementation = address(factory.implementation());
        console.log("chain id      ", block.chainid);
        console.log("factory       ", address(factory));
        console.log("implementation", implementation);
        console.log("clone init code hash");
        console.logBytes32(
            keccak256(
                abi.encodePacked(
                    hex"3d602d80600a3d3981f3363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3"
                )
            )
        );
    }
}
