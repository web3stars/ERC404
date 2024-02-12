//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

abstract contract Ownable {
    event OwnershipTransferred(address indexed user, address indexed newOwner);

    error Unauthorized();
    error InvalidOwner();

    address public owner;

    modifier onlyOwner() virtual {
        if (msg.sender != owner) revert Unauthorized();

        _;
    }

    constructor(address _owner) {
        if (_owner == address(0)) revert InvalidOwner();

        owner = _owner;

        emit OwnershipTransferred(address(0), _owner);
    }

    function transferOwnership(address _owner) public virtual onlyOwner {
        if (_owner == address(0)) revert InvalidOwner();

        owner = _owner;

        emit OwnershipTransferred(msg.sender, _owner);
    }

    function revokeOwnership() public virtual onlyOwner {
        owner = address(0);

        emit OwnershipTransferred(msg.sender, address(0));
    }
}

abstract contract ERC721Receiver {
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC721Receiver.onERC721Received.selector;
    }
}

/// @notice ERC404
///         A gas-efficient, mixed ERC20 / ERC721 implementation
///         with native liquidity and fractionalization.
///
///         This is an experimental standard designed to integrate
///         with pre-existing ERC20 / ERC721 support as smoothly as
///         possible.
///
/// @dev    In order to support full functionality of ERC20 and ERC721
///         supply assumptions are made that slightly constraint usage.
///         Ensure decimals are sufficiently large (standard 18 recommended)
///         as ids are effectively encoded in the lowest range of amounts.
///
///         NFTs are spent on ERC20 functions in a FILO queue, this is by
///         design.
///
abstract contract ERC404 is Ownable {
    // Events
    event ERC20Transfer(
        address indexed from,
        address indexed to,
        uint256 amount
    );
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    );
    event Transfer(
        address indexed from,
        address indexed to,
        uint256 indexed id
    );
    event ERC721Approval(
        address indexed owner,
        address indexed spender,
        uint256 indexed id
    );
    event ApprovalForAll(
        address indexed owner,
        address indexed operator,
        bool approved
    );

    // Errors
    error NotFound();
    error AlreadyExists();
    error InvalidRecipient();
    error InvalidSender();
    error UnsafeRecipient();

    // Metadata
    /// @dev Token name
    string public name;

    /// @dev Token symbol
    string public symbol;

    /// @dev Decimals for fractional representation
    uint8 public immutable decimals;

    /// @dev Total supply in fractionalized representation
    uint256 public totalSupply;

    /// @dev Current mint counter, monotonically increasing to ensure accurate ownership
    uint256 public minted;

    // Mappings
    /// @dev Balance of user in fractional representation
    mapping(address => uint256) public balanceOf;

    /// @dev Allowance of user in fractional representation
    mapping(address => mapping(address => uint256)) public allowance;

    /// @dev Approval in native representaion
    mapping(uint256 => address) public getApproved;

    /// @dev Approval for all in native representation
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    /// @dev Owner of id in native representation
    mapping(uint256 => address) internal _ownerOf;

    /// @dev Array of owned ids in native representation
    mapping(address => uint256[]) internal _owned;

    /// @dev Tracks indices for the _owned mapping
    mapping(uint256 => uint256) internal _ownedIndex;

    /// @dev Addresses whitelisted from minting / burning for gas savings (pairs, routers, etc)
    mapping(address => bool) public whitelist;

    uint256 private _status;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        _status = _ENTERED;

        _;

        _status = _NOT_ENTERED;
    }

    // Constructor
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        uint256 _totalNativeSupply,
        address _owner
    ) Ownable(_owner) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalNativeSupply * (10 ** decimals);
        _status = _NOT_ENTERED;
    }

    /// @notice Initialization function to set pairs / etc
    ///         saving gas by avoiding mint / burn on unnecessary targets
    function setWhitelist(address target, bool state) public onlyOwner {
        whitelist[target] = state;
    }

    /// @notice Function to find owner of a given native token
    function ownerOf(uint256 id) public view virtual returns (address owner) {
        owner = _ownerOf[id];

        if (owner == address(0)) {
            revert NotFound();
        }
    }

    // @notice Function to get the id of the token at a given index and owner
    function tokenOfOwnerByIndex(
        address owner,
        uint256 index
    ) public view virtual returns (uint256) {
        require(
            index < _owned[owner].length,
            "ERC404: owner index out of bounds"
        );
        return _owned[owner][index];
    }

    // @notice Function get the total number of NFT owned by a given address
    function balanceOfNFT(address owner) public view virtual returns (uint256) {
        return _owned[owner].length;
    }

    /// @notice tokenURI must be implemented by child contract
    function tokenURI(uint256 id) public view virtual returns (string memory);

    /// @notice Function for token approvals
    /// @dev This function assumes id / native if amount less than or equal to current max id
    function approve(
        address spender,
        uint256 amountOrId
    ) public virtual returns (bool) {
        if (amountOrId <= minted && amountOrId > 0) {
            address owner = _ownerOf[amountOrId];

            if (msg.sender != owner && !isApprovedForAll[owner][msg.sender]) {
                revert Unauthorized();
            }

            getApproved[amountOrId] = spender;

            emit Approval(owner, spender, amountOrId);
        } else {
            allowance[msg.sender][spender] = amountOrId;

            emit Approval(msg.sender, spender, amountOrId);
        }

        return true;
    }

    /// @notice Function native approvals
    function setApprovalForAll(address operator, bool approved) public virtual {
        isApprovedForAll[msg.sender][operator] = approved;

        emit ApprovalForAll(msg.sender, operator, approved);
    }

    /// @notice Function for mixed transfers
    /// @dev This function assumes id / native if amount less than or equal to current max id
    function transferFrom(
        address from,
        address to,
        uint256 amountOrId
    ) public virtual nonReentrant {
        if (amountOrId <= minted) {
            if (from != _ownerOf[amountOrId]) {
                revert InvalidSender();
            }

            if (to == address(0)) {
                revert InvalidRecipient();
            }

            if (
                msg.sender != from &&
                !isApprovedForAll[from][msg.sender] &&
                msg.sender != getApproved[amountOrId]
            ) {
                revert Unauthorized();
            }

            balanceOf[from] -= _getUnit();

            unchecked {
                balanceOf[to] += _getUnit();
            }

            _ownerOf[amountOrId] = to;
            delete getApproved[amountOrId];

            // update _owned for sender
            uint256 updatedId = _owned[from][_owned[from].length - 1];
            _owned[from][_ownedIndex[amountOrId]] = updatedId;
            // pop
            _owned[from].pop();
            // update index for the moved id
            _ownedIndex[updatedId] = _ownedIndex[amountOrId];
            // push token to to owned
            _owned[to].push(amountOrId);
            // update index for to owned
            _ownedIndex[amountOrId] = _owned[to].length - 1;

            emit Transfer(from, to, amountOrId);
            emit ERC20Transfer(from, to, _getUnit());
        } else {
            uint256 allowed = allowance[from][msg.sender];

            if (allowed != type(uint256).max)
                allowance[from][msg.sender] = allowed - amountOrId;

            _transferMultipleNFT(from, to, amountOrId);
        }
    }

    /// @notice Function for fractional transfers
    function transfer(
        address to,
        uint256 amount
    ) public virtual nonReentrant returns (bool) {
        return _transferMultipleNFT(msg.sender, to, amount);
    }

    /// @notice Function for native transfers with contract support
    function safeTransferFrom(
        address from,
        address to,
        uint256 id
    ) public virtual {
        transferFrom(from, to, id);

        if (
            to.code.length != 0 &&
            ERC721Receiver(to).onERC721Received(msg.sender, from, id, "") !=
            ERC721Receiver.onERC721Received.selector
        ) {
            revert UnsafeRecipient();
        }
    }

    /// @notice Function for native transfers with contract support and callback data
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        bytes calldata data
    ) public virtual {
        transferFrom(from, to, id);

        if (
            to.code.length != 0 &&
            ERC721Receiver(to).onERC721Received(msg.sender, from, id, data) !=
            ERC721Receiver.onERC721Received.selector
        ) {
            revert UnsafeRecipient();
        }
    }

    /// @notice Internal function for fractional transfers
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal returns (bool) {
        uint256 unit = _getUnit();
        uint256 balanceBeforeSender = balanceOf[from];
        uint256 balanceBeforeReceiver = balanceOf[to];

        balanceOf[from] -= amount;

        unchecked {
            balanceOf[to] += amount;
        }

        // Skip burn for certain addresses to save gas
        if (!whitelist[from]) {
            uint256 tokens_to_burn = (balanceBeforeSender / unit) -
                (balanceOf[from] / unit);
            for (uint256 i = 0; i < tokens_to_burn; i++) {
                _burn(from);
            }
        }

        // Skip minting for certain addresses to save gas
        if (!whitelist[to]) {
            uint256 tokens_to_mint = (balanceOf[to] / unit) -
                (balanceBeforeReceiver / unit);
            for (uint256 i = 0; i < tokens_to_mint; i++) {
                _mint(to);
            }
        }

        emit ERC20Transfer(from, to, amount);
        return true;
    }

    // Assuming the existence of a vault mechanism within the contract
    // FIFO queue for vault
    uint256[] private vault;

    /// @notice Internal function for fractional transfers without mint / burn
    function _transferMultipleNFT(
        address from,
        address to,
        uint256 amount
    ) internal returns (bool) {
        uint256 unit = _getUnit();
        uint256 balanceBeforeSender = balanceOf[from];
        uint256 balanceBeforeReceiver = balanceOf[to];

        balanceOf[from] -= amount;

        unchecked {
            balanceOf[to] += amount;
        }
        uint256 left = 0;

        uint256 tokens_to_transfer = (balanceOf[to] / unit) -
            (balanceBeforeReceiver / unit);
        for (uint256 i = 0; i < tokens_to_transfer; i++) {
            uint256 id = _owned[from][_owned[from].length - 1];
            if (id >= 1) {
                _transferNFT(from, to, id);
            }
        }
        left = amount - tokens_to_transfer * unit;
        // If `from` has NFTs to deposit and `left` amount is not sufficient for a full NFT
        if (left > 0 && left < unit && _owned[from].length > 0 && (balanceBeforeSender / unit != (balanceBeforeSender - left) / unit)) {
            uint256 id = _owned[from][_owned[from].length - 1];
            // Transfer the NFT to the contract (vault)
            _transferNFT(from, address(this), id);
            // Add the NFT to the vault queue
            vault.push(id);
            getApproved[id] = address(this);
            emit Approval(from, address(this), id);
        }

        if (balanceOf[to] / unit >= 1 && vault.length > 0 && (balanceBeforeReceiver / unit != (balanceBeforeReceiver + left) / unit)) {
            // Withdraw the first NFT from the vault
            uint256 vaultId = vault[0];
            // Remove the first NFT from the vault queue
            _removeFirstFromVault();
            _transferNFT(address(this), to, vaultId);
        }

        emit ERC20Transfer(from, to, amount);
        return true;
    }

    function _removeFirstFromVault() internal {
        require(vault.length > 0, "Vault is empty");

        // Shift all elements to the left by one position
        for (uint256 i = 0; i < vault.length - 1; i++) {
            vault[i] = vault[i + 1];
        }
        // Remove the last element by decrementing the array length
        vault.pop();
    }

    // @notice Internal function for fractional transfers a single NFT
    function _transferNFT(address from, address to, uint256 tokenId) internal {
        delete getApproved[tokenId];

        _ownerOf[tokenId] = to;

        uint256 lastIndex = _owned[from].length - 1;
        uint256 tokenIndex = _ownedIndex[tokenId];
        if (tokenIndex != lastIndex) {
            uint256 lastTokenId = _owned[from][lastIndex];
            _owned[from][tokenIndex] = lastTokenId;
            _ownedIndex[lastTokenId] = tokenIndex;
        }
        _owned[from].pop();
        delete _ownedIndex[tokenId];

        _owned[to].push(tokenId);
        _ownedIndex[tokenId] = _owned[to].length - 1;

        emit Transfer(from, to, tokenId);
        emit ERC20Transfer(from, to, _getUnit());
    }

    // Internal utility logic
    function _getUnit() internal view returns (uint256) {
        return 10 ** decimals;
    }

    function _mint(address to) internal virtual {
        if (to == address(0)) {
            revert InvalidRecipient();
        }

        unchecked {
            minted++;
        }

        uint256 id = minted;

        if (_ownerOf[id] != address(0)) {
            revert AlreadyExists();
        }

        _ownerOf[id] = to;
        _owned[to].push(id);
        _ownedIndex[id] = _owned[to].length - 1;

        emit Transfer(address(0), to, id);
    }

    function _burn(address from) internal virtual {
        if (from == address(0)) {
            revert InvalidSender();
        }

        uint256 id = _owned[from][_owned[from].length - 1];
        _owned[from].pop();
        delete _ownedIndex[id];
        delete _ownerOf[id];
        delete getApproved[id];

        emit Transfer(from, address(0), id);
    }

    function _setNameSymbol(
        string memory _name,
        string memory _symbol
    ) internal {
        name = _name;
        symbol = _symbol;
    }
}

contract ExampleToken is ERC404 {
    uint256 public constant MINT_PRICE = 0.0404 ether;
    uint256 public constant MAX_SUPPLY = 10000 * 10 ** 18;
    uint256 public constant MAX_ID = 10000;

    event BaseTokenURIUpdated(address indexed owner, string indexed tokenURI);

    string public dataURI;
    string public baseTokenURI;

    /// @dev Addresses whitelisted for free mint
    mapping(address => bool) public mint_whitelist;

    constructor(address _owner) ERC404("ExampleToken", "Exam", 18, 0, _owner) {
        balanceOf[_owner] = 0;
    }

    /// @notice Initialization function to set pairs / etc
    ///         saving gas for free minting
    function setMintWhitelist(address target, bool state) public onlyOwner {
        mint_whitelist[target] = state;
    }

    /// @notice Initialization function to set pairs / etc
    ///         saving gas for free minting
    function setMintWhitelists(
        address[] calldata targets,
        bool state
    ) public onlyOwner {
        for (uint256 i = 0; i < targets.length; i++) {
            mint_whitelist[targets[i]] = state;
        }
    }

    function setDataURI(string memory _dataURI) public onlyOwner {
        dataURI = _dataURI;
    }

    function setTokenURI(string memory _tokenURI) public onlyOwner {
        baseTokenURI = _tokenURI;
        emit BaseTokenURIUpdated(msg.sender, _tokenURI);
    }

    function tokenURI(uint256 id) public view override returns (string memory) {
        uint256 tokenId = id % 10000;
        if (tokenId == 0) {
            tokenId = 10000;
        }
        return
            string(
                abi.encodePacked(
                    baseTokenURI,
                    Strings.toString(tokenId),
                    ".json"
                )
            );
    }

    function setNameSymbol(
        string memory _name,
        string memory _symbol
    ) public onlyOwner {
        _setNameSymbol(_name, _symbol);
    }

    function getFullPrice(uint256 count) public view returns (uint256) {
        uint256 unit = _getUnit();
        uint256 price = 0;
        if (mint_whitelist[msg.sender] || totalSupply / unit + count <= 2000) {
            price = 0;
        } else if (totalSupply / unit + count <= 3000) {
            price = MINT_PRICE / 4;
        } else if (totalSupply / unit + count <= 4000) {
            price = MINT_PRICE / 2;
        } else {
            price = MINT_PRICE;
        }
        return price;
    }

    function getPrice(
        address referer,
        uint256 count
    ) public view returns (uint256) {
        
        uint256 price = getFullPrice(count);
        if (
            referer != msg.sender &&
            referer != address(0x0) &&
            _owned[referer].length > 0
        ) {
            price = (price * 90) / 100;
        }
        return price;
    }

    function mint(address referer) external payable nonReentrant {
        
        require(totalSupply <= MAX_SUPPLY, "No mint capacity left");
        uint256 unit = _getUnit();
        if (referer == msg.sender) {
            referer = address(0x0);
        }
        uint256 price = getPrice(referer, 1);

        if (msg.value < price) {
            revert("Insufficient funds sent for minting.");
        }
        _mint(msg.sender);
        balanceOf[msg.sender] += unit;
        totalSupply += unit;

        if (msg.value > price) {
            payable(msg.sender).transfer(msg.value - price);
            if (referer != address(0x0) && _owned[referer].length > 0) {
                payable(referer).transfer((getFullPrice(1) * 10) / 100);
            }
        }
    }

    function mintBatch(
        uint256 numTokens,
        address referer
    ) external payable nonReentrant {
       
        uint256 unit = _getUnit();
        require(numTokens > 0 && numTokens <=100, "Number of tokens must be greater than 0 and less than or equal to 100");
        require(
            totalSupply + (numTokens * unit) <= MAX_SUPPLY,
            "Exceeds maximum supply"
        );

        if (referer == msg.sender) {
            referer = address(0);
        }

        uint256 totalPrice = 0;
        for (uint256 i = 0; i < numTokens; i++) {
            totalPrice += getPrice(referer, numTokens);
        }

        require(
            msg.value >= totalPrice,
            "Insufficient funds sent for minting."
        );

        for (uint256 i = 0; i < numTokens; i++) {
            _mint(msg.sender);
            balanceOf[msg.sender] += unit;
            totalSupply += unit;
        }

        if (referer != address(0) && _owned[referer].length > 0) {
            // Assuming the referer's reward is 10% of the total price
            uint256 refererReward = (totalPrice * 10) / 90;
            payable(referer).transfer(refererReward);
        }

        if (msg.value > totalPrice) {
            payable(msg.sender).transfer(msg.value - totalPrice);
        }
    }

    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        payable(owner).transfer(balance);
    }
}

library Strings {
    function toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
