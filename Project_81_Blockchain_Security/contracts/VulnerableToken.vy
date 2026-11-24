# @version ^0.3.0
owner: public(address)
balances: public(HashMap[address, uint256])

@external
def __init__():
    self.owner = msg.sender

@external
def mint(to: address, amount: uint256):
    # VULNERABILITY: no onlyOwner check
    self.balances[to] += amount

@external
def transfer(to: address, amount: uint256):
    # VULNERABILITY: integer underflow (no validation)
    self.balances[msg.sender] -= amount
    self.balances[to] += amount
