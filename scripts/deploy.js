const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  // Read role addresses from env
  const ADMIN    = process.env.ADMIN_ADDRESS;
  const MINTER   = process.env.MINTER_ADDRESS;
  const REISSUER = process.env.REISSUER_ADDRESS;

  if (!ADMIN || !MINTER || !REISSUER) {
    throw new Error("Missing envs: ADMIN_ADDRESS / MINTER_ADDRESS / REISSUER_ADDRESS");
  }

  console.log("Deployer:", deployer.address);
  console.log("ADMIN:   ", ADMIN);
  console.log("MINTER:  ", MINTER);
  console.log("REISSUER:", REISSUER);

  const PersonaAuth = await hre.ethers.getContractFactory("PersonaAuth");

  // Adjust if the network is congested
  const gasPrice = hre.ethers.utils.parseUnits("100", "gwei");

  // NEW: constructor is (admin, minter, reissuer)
  const contract = await PersonaAuth.deploy(ADMIN, MINTER, REISSUER, { gasPrice });

  console.log("Deploy tx:", contract.deployTransaction.hash);

  await contract.deployed();
  console.log("PersonaAuth deployed to:", contract.address);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
