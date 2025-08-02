require('dotenv').config();
const { ethers } = require('ethers');
const CONTRACT_ABI = require('./artifacts/contracts/NFTAuth.sol/NFTAuth.json').abi;

(async () => {
  const provider = new ethers.providers.JsonRpcProvider(process.env.ALCHEMY_API_URL);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
  const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, CONTRACT_ABI, wallet);

  const tokenURI = "ipfs://bafybeibbvbnjkolqfdqhka776q7eg2z57yrsx6gz4dlhaqwegr7ryfkpqq";
  const devicePublicKey = "0xYOUR_PHONE_WALLET"; // ← Replace with your actual phone wallet

  try {
    console.log("Minting to self...");
    const tx = await contract.safeMint(
      wallet.address,
      tokenURI,
      devicePublicKey,
      {
        maxPriorityFeePerGas: ethers.utils.parseUnits("30", "gwei"),
        maxFeePerGas: ethers.utils.parseUnits("50", "gwei"),
        gasLimit: 300000
      }
    );

    console.log("TX sent:", tx.hash);
    const receipt = await tx.wait();
    console.log("✅ Minted. Token ID:", receipt.events[0].args.tokenId.toString());

  } catch (err) {
    console.error("❌ Mint failed:", err);
  }
})();
