// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract PersonaAuth is ERC721Enumerable, Ownable {
    uint256 public nextTokenId;

    struct Metadata {
        bytes32[3] emailHashes;
        bytes32[3] deviceIdHashes;
        uint256 createdAt;
    }

    mapping(uint256 => Metadata) public tokenData;

    constructor(
        address initialOwner
    ) ERC721("PersonaAuth", "PNA") Ownable(initialOwner) {}

    function safeMint(
        address to,
        bytes32[3] calldata emailHashes,
        bytes32[3] calldata deviceIdHashes
    ) public onlyOwner {
        uint256 tokenId = nextTokenId++;
        _safeMint(to, tokenId);
        tokenData[tokenId] = Metadata(
            emailHashes,
            deviceIdHashes,
            block.timestamp
        );
    }

    function burnAndReissue(
        uint256 tokenId,
        bytes32[3] calldata newEmailHashes,
        bytes32[3] calldata newDeviceIdHashes
    ) public {
        require(ownerOf(tokenId) == msg.sender, "Not your NFT");

        _burn(tokenId);

        uint256 newTokenId = nextTokenId++;
        _safeMint(msg.sender, newTokenId);
        tokenData[newTokenId] = Metadata(
            newEmailHashes,
            newDeviceIdHashes,
            block.timestamp
        );
    }

    // === Soulbound Enforcement ===
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override(ERC721Enumerable) returns (address) {
        if (_ownerOf(tokenId) != address(0) && to != address(0)) {
            revert("Soulbound: transfer not allowed");
        }
        return super._update(to, tokenId, auth);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721Enumerable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
