// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOracle {
    function getPrice() external view returns (uint256);
}

contract VulnerableLending {
    IOracle public oracle;
    mapping(address => uint256) public deposits;

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
    }

    // VULNERABILITY: flash loan without collateral check
    function flashLoan(uint256 amount, address target, bytes calldata data) external {
        uint256 balanceBefore = address(this).balance;
        (bool sent, ) = target.call{value: amount}("");
        require(sent, "Flash loan failed");
        require(address(this).balance >= balanceBefore, "Not repaid");
        // No fee, no collateral check
    }

    // VULNERABILITY: oracle manipulation — single source, no TWAP
    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice();
        uint256 collateralValue = deposits[msg.sender] * price;
        require(collateralValue >= amount, "Insufficient collateral");
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }

    // VULNERABILITY: governance attack — single owner can drain
    function emergencyWithdraw() external {
        (bool sent, ) = owner().call{value: address(this).balance}("");
        require(sent, "Withdraw failed");
    }

    function owner() internal view returns (address) {
        return address(this);
    }
}
