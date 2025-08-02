require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-verify");
require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    amoy: {
      url: process.env.ALCHEMY_API_URL, // must be Amoy endpoint
      accounts: [process.env.PRIVATE_KEY], // no 0x prefix
      gasPrice: 3000000000, // 3 Gwei
      gas: 3_000_000        // Should be plenty for an ERC721
    },
    polygon: {
      url: "https://polygon-rpc.com",
      accounts: [process.env.PRIVATE_KEY],
      gasPrice: 100_000_000_000  // 100 Gwei — adjust if needed
    },
  },
  etherscan: {
    apiKey: process.env.POLYGONSCAN_API_KEY,
  },
};
