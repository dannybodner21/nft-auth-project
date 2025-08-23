// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// Minimal EIP-5192 interface (soulbound signalling)
interface IERC5192 {
    event Locked(uint256 tokenId);
    event Unlocked(uint256 tokenId);

    function locked(uint256 tokenId) external view returns (bool);
}

/// PersonaAuth (custodial-only, permanently soulbound)
/// Users do not interact on-chain. Only backend roles can mint/reissue/update/revoke.
/// EIP-712 domain: name="PersonaAuth", version="1", chainId=<net>, verifyingContract=<address>
contract PersonaAuth is ERC721, AccessControl, Pausable, EIP712, IERC5192 {
    using ECDSA for bytes32;

    // ---------- Roles ----------
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE"); // signs MintAuth
    bytes32 public constant REISSUER_ROLE = keccak256("REISSUER_ROLE"); // signs ReissueAuth
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE"); // can revoke (burn)
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE"); // pause/unpause

    // ---------- Identity payload (no PII on-chain) ----------
    struct Identity {
        bytes32 userIdHash; // salted commitment to user's identifier (e.g., email); salt stays off-chain
        bytes32 deviceHash; // commitment to device key/identifier; salt stays off-chain
        bool valid; // false after revoke/burn
    }

    mapping(uint256 => Identity) private _id; // tokenId => identity
    mapping(address => uint256) private _tokenOf; // one-per-wallet (0 if none)
    mapping(bytes32 => uint256) private _tokenByUser; // one-per-identity (0 if none)
    uint256 private _nextId = 1;

    // ---------- EIP-712 typed data (no PIN anywhere) ----------
    // Mint authorization (signed by MINTER_ROLE)
    bytes32 private constant MINT_TYPEHASH =
        keccak256(
            "MintAuth(address to,bytes32 userIdHash,bytes32 deviceHash,bytes32 salt,uint256 deadline)"
        );
    // Atomic reissue authorization (signed by REISSUER_ROLE)
    bytes32 private constant REISSUE_TYPEHASH =
        keccak256(
            "ReissueAuth(uint256 oldTokenId,address newOwner,bytes32 userIdHash,bytes32 newDeviceHash,bytes32 salt,uint256 deadline)"
        );
    mapping(bytes32 => bool) public usedSalt; // replay protection

    constructor(
        address admin,
        address minter,
        address reissuer
    ) ERC721("PersonaAuth", "PAUTH") EIP712("PersonaAuth", "1") {
        require(admin != address(0), "admin=0");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, minter);
        _grantRole(REISSUER_ROLE, reissuer);
        _grantRole(REVOKER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // ---------- Soulbound enforcement ----------
    // While paused: burns (revokes) are still allowed; mints are blocked.
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override returns (address) {
        address from = _ownerOf(tokenId);
        bool isMint = (from == address(0));
        bool isBurn = (to == address(0));

        if (paused()) {
            if (!isBurn) revert("Pausable: paused");
        }
        if (!isMint && !isBurn) revert("SBT: non-transferable");

        return super._update(to, tokenId, auth);
    }

    function locked(uint256 tokenId) external view returns (bool) {
        require(_ownerOf(tokenId) != address(0), "No token");
        return true; // permanently locked
    }

    // Disable approvals to avoid UX confusion (transfers are impossible anyway)
    function approve(address, uint256) public pure override {
        revert("SBT: approvals disabled");
    }

    function setApprovalForAll(address, bool) public pure override {
        revert("SBT: approvals disabled");
    }

    // ---------- Mint (EIP-712; relayer pays gas; signer must have MINTER_ROLE) ----------
    function mintWithSig(
        address to,
        bytes32 userIdHash,
        bytes32 deviceHash,
        bytes32 salt,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(to != address(0), "to=0");
        require(block.timestamp <= deadline, "expired");
        require(!usedSalt[salt], "salt used");
        require(!paused(), "Pausable: paused");
        usedSalt[salt] = true;

        // Uniqueness
        require(_tokenOf[to] == 0, "wallet already has token");
        require(_tokenByUser[userIdHash] == 0, "identity already issued");

        // Recover and check role
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MINT_TYPEHASH,
                    to,
                    userIdHash,
                    deviceHash,
                    salt,
                    deadline
                )
            )
        );
        address signer = ECDSA.recover(digest, sig);
        require(hasRole(MINTER_ROLE, signer), "bad signer");

        uint256 tokenId = _nextId++;
        _safeMint(to, tokenId);

        _id[tokenId] = Identity(userIdHash, deviceHash, true);
        _tokenOf[to] = tokenId;
        _tokenByUser[userIdHash] = tokenId;

        emit Locked(tokenId);
        emit Minted(to, tokenId, userIdHash, deviceHash);
    }

    // ---------- Admin device update (no holder actions) ----------
    function adminSetDeviceHash(
        uint256 tokenId,
        bytes32 newDeviceHash
    ) external onlyRole(REISSUER_ROLE) {
        require(_ownerOf(tokenId) != address(0), "missing token");
        require(!paused(), "Pausable: paused");
        _id[tokenId].deviceHash = newDeviceHash;
        emit RotatedDevice(tokenId, newDeviceHash);
    }

    // ---------- Admin revoke (burn) – allowed even while paused ----------
    function revoke(uint256 tokenId) external onlyRole(REVOKER_ROLE) {
        address owner = ownerOf(tokenId);
        bytes32 uid = _id[tokenId].userIdHash;

        _burn(tokenId);
        _id[tokenId].valid = false;

        if (_tokenOf[owner] == tokenId) _tokenOf[owner] = 0;
        if (_tokenByUser[uid] == tokenId) _tokenByUser[uid] = 0;

        emit Revoked(tokenId, owner);
    }

    // ---------- Atomic reissue: revoke old + mint new (EIP-712; signer must have REISSUER_ROLE) ----------
    function reissueWithSig(
        uint256 oldTokenId,
        address newOwner,
        bytes32 userIdHash,
        bytes32 newDeviceHash,
        bytes32 salt,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(newOwner != address(0), "newOwner=0");
        require(block.timestamp <= deadline, "expired");
        require(!usedSalt[salt], "salt used");
        require(!paused(), "Pausable: paused");
        usedSalt[salt] = true;

        // Recover and check role
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REISSUE_TYPEHASH,
                    oldTokenId,
                    newOwner,
                    userIdHash,
                    newDeviceHash,
                    salt,
                    deadline
                )
            )
        );
        address signer = ECDSA.recover(digest, sig);
        require(hasRole(REISSUER_ROLE, signer), "bad signer");

        // Old token must exist, match identity, and be valid
        require(_ownerOf(oldTokenId) != address(0), "old token missing");
        require(_id[oldTokenId].valid, "old token invalid");
        require(_id[oldTokenId].userIdHash == userIdHash, "identity mismatch");

        // Burn old (allowed even if paused by _update logic)
        address oldOwner = ownerOf(oldTokenId);
        _burn(oldTokenId);
        _id[oldTokenId].valid = false;
        if (_tokenOf[oldOwner] == oldTokenId) _tokenOf[oldOwner] = 0;
        if (_tokenByUser[userIdHash] == oldTokenId)
            _tokenByUser[userIdHash] = 0;

        // Enforce uniqueness for new wallet
        require(_tokenOf[newOwner] == 0, "new wallet already has token");
        require(_tokenByUser[userIdHash] == 0, "identity already issued");

        // Mint new
        uint256 tokenId = _nextId++;
        _safeMint(newOwner, tokenId);

        _id[tokenId] = Identity(userIdHash, newDeviceHash, true);
        _tokenOf[newOwner] = tokenId;
        _tokenByUser[userIdHash] = tokenId;

        emit Locked(tokenId);
        emit Reissued(oldTokenId, tokenId, oldOwner, newOwner, userIdHash);
    }

    // ---------- Pause controls ----------
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ---------- Views ----------
    function identityOf(
        uint256 tokenId
    ) external view returns (Identity memory) {
        return _id[tokenId];
    }

    function tokenOf(address user) external view returns (uint256) {
        return _tokenOf[user];
    }

    function tokenByUser(bytes32 userIdHash) external view returns (uint256) {
        return _tokenByUser[userIdHash];
    }

    // ---------- ERC165 ----------
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, AccessControl) returns (bool) {
        return
            interfaceId == type(IERC5192).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ---------- Events ----------
    event Minted(
        address indexed to,
        uint256 indexed tokenId,
        bytes32 userIdHash,
        bytes32 deviceHash
    );
    event RotatedDevice(uint256 indexed tokenId, bytes32 newDeviceHash);
    event Revoked(uint256 indexed tokenId, address indexed owner);
    event Reissued(
        uint256 indexed oldTokenId,
        uint256 indexed newTokenId,
        address indexed oldOwner,
        address newOwner,
        bytes32 userIdHash
    );
}
