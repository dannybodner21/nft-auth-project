// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract NFTAuth is ERC721URIStorage, Ownable {
    uint256 public nextTokenId;
    mapping(uint256 => address) public devicePublicKeys;

    constructor(
        address initialOwner
    ) ERC721("NFTAuth", "NFA") Ownable(initialOwner) {}

    function safeMint(
        address to,
        string memory uri,
        address devicePublicKey
    ) public {
        require(msg.sender == to, "Can only mint to your own address");

        uint256 tokenId = nextTokenId++;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
        devicePublicKeys[tokenId] = devicePublicKey;
    }

    function burnAndReissue(
        uint256 tokenId,
        address newDevicePublicKey
    ) public {
        require(ownerOf(tokenId) == msg.sender, "Not your NFT");
        _burn(tokenId);
        uint256 newTokenId = nextTokenId++;
        _safeMint(msg.sender, newTokenId);
        devicePublicKeys[newTokenId] = newDevicePublicKey;
    }
}
