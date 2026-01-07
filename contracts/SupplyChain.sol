// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title SupplyChain
 * @dev Manages product lifecycle in supply chain with blockchain transparency
 */
contract SupplyChain is AccessControl, ReentrancyGuard, Pausable {
    
    bytes32 public constant MANUFACTURER_ROLE = keccak256("MANUFACTURER_ROLE");
    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");
    bytes32 public constant RETAILER_ROLE = keccak256("RETAILER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    
    enum ProductState {
        Manufactured,
        InTransit,
        Warehoused,
        Delivered,
        Sold,
        Recalled
    }
    
    struct Product {
        uint256 id;
        string name;
        string description;
        address manufacturer;
        uint256 manufacturingDate;
        uint256 expiryDate;
        string batchNumber;
        string ipfsHash;
        ProductState state;
        bool exists;
    }
    
    struct Checkpoint {
        address handler;
        string location;
        uint256 timestamp;
        ProductState state;
        string notes;
        int256 temperature; // For cold chain tracking
        string ipfsHash; // Photos/documents
    }
    
    struct Payment {
        uint256 amount;
        address payer;
        address payee;
        uint256 timestamp;
        bool released;
    }
    
    // Mappings
    mapping(uint256 => Product) public products;
    mapping(uint256 => Checkpoint[]) public productCheckpoints;
    mapping(uint256 => address[]) public productOwnershipHistory;
    mapping(uint256 => Payment) public productPayments;
    mapping(uint256 => bool) public productVerified;
    
    // Counters
    uint256 public productCount;
    uint256 public totalCheckpoints;
    
    // Events
    event ProductRegistered(
        uint256 indexed productId,
        string name,
        address indexed manufacturer,
        uint256 timestamp
    );
    
    event OwnershipTransferred(
        uint256 indexed productId,
        address indexed from,
        address indexed to,
        uint256 timestamp
    );
    
    event CheckpointAdded(
        uint256 indexed productId,
        address indexed handler,
        ProductState state,
        string location,
        uint256 timestamp
    );
    
    event PaymentEscrowed(
        uint256 indexed productId,
        uint256 amount,
        address indexed payer,
        address indexed payee
    );
    
    event PaymentReleased(
        uint256 indexed productId,
        uint256 amount,
        address indexed payee
    );
    
    event ProductRecalled(
        uint256 indexed productId,
        string reason,
        uint256 timestamp
    );
    
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);
    }
    
    /**
     * @dev Register a new product in the supply chain
     */
    function registerProduct(
        string memory _name,
        string memory _description,
        uint256 _expiryDate,
        string memory _batchNumber,
        string memory _ipfsHash
    ) external onlyRole(MANUFACTURER_ROLE) whenNotPaused returns (uint256) {
        require(bytes(_name).length > 0, "Product name required");
        require(_expiryDate > block.timestamp, "Invalid expiry date");
        
        productCount++;
        uint256 productId = productCount;
        
        products[productId] = Product({
            id: productId,
            name: _name,
            description: _description,
            manufacturer: msg.sender,
            manufacturingDate: block.timestamp,
            expiryDate: _expiryDate,
            batchNumber: _batchNumber,
            ipfsHash: _ipfsHash,
            state: ProductState.Manufactured,
            exists: true
        });
        
        // Add initial checkpoint
        productCheckpoints[productId].push(Checkpoint({
            handler: msg.sender,
            location: "Manufacturing Facility",
            timestamp: block.timestamp,
            state: ProductState.Manufactured,
            notes: "Product manufactured",
            temperature: 0,
            ipfsHash: _ipfsHash
        }));
        
        // Initialize ownership history
        productOwnershipHistory[productId].push(msg.sender);
        
        totalCheckpoints++;
        
        emit ProductRegistered(productId, _name, msg.sender, block.timestamp);
        
        return productId;
    }
    
    /**
     * @dev Transfer product ownership to next party in supply chain
     */
    function transferOwnership(
        uint256 _productId,
        address _newOwner,
        string memory _location,
        ProductState _newState
    ) external whenNotPaused {
        require(products[_productId].exists, "Product does not exist");
        require(_newOwner != address(0), "Invalid new owner");
        require(
            hasRole(MANUFACTURER_ROLE, msg.sender) ||
            hasRole(DISTRIBUTOR_ROLE, msg.sender) ||
            hasRole(RETAILER_ROLE, msg.sender),
            "Unauthorized"
        );
        
        Product storage product = products[_productId];
        address previousOwner = productOwnershipHistory[_productId][
            productOwnershipHistory[_productId].length - 1
        ];
        
        require(previousOwner == msg.sender, "Not current owner");
        
        // Update product state
        product.state = _newState;
        
        // Add checkpoint
        productCheckpoints[_productId].push(Checkpoint({
            handler: msg.sender,
            location: _location,
            timestamp: block.timestamp,
            state: _newState,
            notes: "Ownership transferred",
            temperature: 0,
            ipfsHash: ""
        }));
        
        // Update ownership history
        productOwnershipHistory[_productId].push(_newOwner);
        
        totalCheckpoints++;
        
        emit OwnershipTransferred(_productId, msg.sender, _newOwner, block.timestamp);
        emit CheckpointAdded(_productId, msg.sender, _newState, _location, block.timestamp);
    }
    
    /**
     * @dev Add checkpoint for product tracking
     */
    function addCheckpoint(
        uint256 _productId,
        string memory _location,
        ProductState _state,
        string memory _notes,
        int256 _temperature,
        string memory _ipfsHash
    ) external whenNotPaused {
        require(products[_productId].exists, "Product does not exist");
        require(
            hasRole(MANUFACTURER_ROLE, msg.sender) ||
            hasRole(DISTRIBUTOR_ROLE, msg.sender) ||
            hasRole(RETAILER_ROLE, msg.sender),
            "Unauthorized"
        );
        
        productCheckpoints[_productId].push(Checkpoint({
            handler: msg.sender,
            location: _location,
            timestamp: block.timestamp,
            state: _state,
            notes: _notes,
            temperature: _temperature,
            ipfsHash: _ipfsHash
        }));
        
        products[_productId].state = _state;
        totalCheckpoints++;
        
        emit CheckpointAdded(_productId, msg.sender, _state, _location, block.timestamp);
    }
    
    /**
     * @dev Escrow payment for product delivery
     */
    function escrowPayment(
        uint256 _productId,
        address _payee
    ) external payable whenNotPaused {
        require(products[_productId].exists, "Product does not exist");
        require(msg.value > 0, "Payment amount must be greater than 0");
        require(_payee != address(0), "Invalid payee");
        
        productPayments[_productId] = Payment({
            amount: msg.value,
            payer: msg.sender,
            payee: _payee,
            timestamp: block.timestamp,
            released: false
        });
        
        emit PaymentEscrowed(_productId, msg.value, msg.sender, _payee);
    }
    
    /**
     * @dev Release escrowed payment upon delivery confirmation
     */
    function releasePayment(uint256 _productId) external nonReentrant whenNotPaused {
        Payment storage payment = productPayments[_productId];
        require(payment.amount > 0, "No payment escrowed");
        require(!payment.released, "Payment already released");
        require(
            msg.sender == payment.payer || hasRole(AUDITOR_ROLE, msg.sender),
            "Unauthorized"
        );
        
        payment.released = true;
        
        (bool success, ) = payment.payee.call{value: payment.amount}("");
        require(success, "Payment transfer failed");
        
        emit PaymentReleased(_productId, payment.amount, payment.payee);
    }
    
    /**
     * @dev Recall product from supply chain
     */
    function recallProduct(
        uint256 _productId,
        string memory _reason
    ) external onlyRole(MANUFACTURER_ROLE) whenNotPaused {
        require(products[_productId].exists, "Product does not exist");
        
        products[_productId].state = ProductState.Recalled;
        
        productCheckpoints[_productId].push(Checkpoint({
            handler: msg.sender,
            location: "Recalled",
            timestamp: block.timestamp,
            state: ProductState.Recalled,
            notes: _reason,
            temperature: 0,
            ipfsHash: ""
        }));
        
        totalCheckpoints++;
        
        emit ProductRecalled(_productId, _reason, block.timestamp);
    }
    
    /**
     * @dev Verify product authenticity
     */
    function verifyProduct(uint256 _productId) external view returns (bool) {
        return products[_productId].exists && 
               products[_productId].state != ProductState.Recalled;
    }
    
    /**
     * @dev Get product details
     */
    function getProduct(uint256 _productId) external view returns (Product memory) {
        require(products[_productId].exists, "Product does not exist");
        return products[_productId];
    }
    
    /**
     * @dev Get product checkpoints
     */
    function getCheckpoints(uint256 _productId) external view returns (Checkpoint[] memory) {
        return productCheckpoints[_productId];
    }
    
    /**
     * @dev Get ownership history
     */
    function getOwnershipHistory(uint256 _productId) external view returns (address[] memory) {
        return productOwnershipHistory[_productId];
    }
    
    /**
     * @dev Pause contract (emergency)
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }
    
    /**
     * @dev Unpause contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}