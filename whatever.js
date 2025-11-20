const { ethers } = require("hardhat");

async function main() {
  const deployedBytecode = await ethers.provider.getCode("0xd5eD67Df70f37d7D8d3181cd557DF82dFB7656d6");
  console.log("Deployed Bytecode:", deployedBytecode);
}

main();

























