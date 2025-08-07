const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  console.log("Deploying contract with:", deployer.address);

  const PersonaAuth = await hre.ethers.getContractFactory("PersonaAuth");

  // Set a high gas price (e.g. 200 Gwei)
  const gasPrice = hre.ethers.utils.parseUnits("200", "gwei");

  const contract = await PersonaAuth.deploy(deployer.address, {
    gasPrice: gasPrice,
  });

  console.log("Transaction hash:", contract.deployTransaction.hash);

  await contract.deployed();

  console.log("PersonaAuth deployed to:", contract.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
