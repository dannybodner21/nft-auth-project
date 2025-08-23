require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-verify");
require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.24",                 // <-- contract uses ^0.8.24
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    polygon: {
      url: "https://polygon-rpc.com",
      accounts: [process.env.PRIVATE_KEY], // keep same format you already use
      gasPrice: 100_000_000_000           // 100 gwei; bump if needed
    },
  },
  etherscan: {
    apiKey: process.env.POLYGONSCAN_API_KEY,
  },
};
