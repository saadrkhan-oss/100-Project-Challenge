// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: external call BEFORE state update (reentrancy)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;  // state update AFTER call
    }

    // VULNERABILITY: no access control
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // VULNERABILITY: integer overflow (no SafeMath in 0.7.x)
    function transfer(address to, uint256 amount) public {
        balances[to] += amount;
        balances[msg.sender] -= amount;
    }

    // VULNERABILITY: front-running — swap based on current balance ratio
    function swap(uint256 amountIn) public returns (uint256) {
        uint256 price = address(this).balance / 1000;
        return amountIn * price;
    }
}
