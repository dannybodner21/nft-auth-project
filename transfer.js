require('dotenv').config();
const { ethers } = require('ethers');
const CONTRACT_ABI = require('./artifacts/contracts/NFTAuth.sol/NFTAuth.json').abi;

const provider = new ethers.providers.JsonRpcProvider("https://polygon-mainnet.g.alchemy.com/v2/3QTktG3ajpVUnNsciJQEI");
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, CONTRACT_ABI, wallet);

async function transferNFT() {
  try {
    const from = wallet.address;
    const to = "0xc8Dc869831E7ec69feb163D48D8032ce9F382aB4"; // destination address (app wallet)
    const tokenId = 1;

    const tx = await contract['safeTransferFrom(address,address,uint256)'](
      from,
      to,
      tokenId,
      {
        maxPriorityFeePerGas: ethers.utils.parseUnits('30', 'gwei'),
        maxFeePerGas: ethers.utils.parseUnits('50', 'gwei'),
      }
    );

    console.log("🚀 Transfer TX sent:", tx.hash);
    await tx.wait();
    console.log("✅ Transfer confirmed!");
  } catch (err) {
    console.error("❌ Transfer failed:", err);
  }
}

transferNFT();
