Certainly! Below is a simple example of an ERC-20 token contract written in Solidity. It's a basic representation and should be used as a starting point. Before deploying any smart contract, it's crucial to have it reviewed and audited by professionals to ensure there are no vulnerabilities.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract EducationToken is IERC20 {
    string public constant name = "EducationToken";
    string public constant symbol = "EDUTKN";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply = 1000000 * 10 ** uint(decimals);  // 1 million tokens, for example

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function.");
        _;
    }

    constructor() {
        owner = msg.sender;
        _balances[owner] = _totalSupply;
        emit Transfer(address(0), owner, _totalSupply);
    }

    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public override returns (bool) {
        require(recipient != address(0), "Transfer to the zero address.");
        require(_balances[msg.sender] >= amount, "Insufficient balance.");

        _balances[msg.sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public override returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        require(sender != address(0), "Transfer from the zero address.");
        require(recipient != address(0), "Transfer to the zero address.");
        require(_balances[sender] >= amount, "Insufficient balance.");
        require(_allowances[sender][msg.sender] >= amount, "Transfer amount exceeds allowance.");

        _balances[sender] -= amount;
        _balances[recipient] += amount;
        _allowances[sender][msg.sender] -= amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }

    // Additional functions to mint more tokens or burn tokens can be added if needed.
}

```

This is a basic implementation of an ERC-20 token with a fixed supply. If you need advanced features like minting, burning, or pausing, you'll have to add additional logic to this contract. Always remember to test the contract extensively on a testnet before deploying to the mainnet.
