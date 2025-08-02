require('dotenv').config();
const express = require('express');
const { ethers } = require('ethers');
const app = express();
app.use(express.json());

const CONTRACT_ABI = require('./artifacts/contracts/NFTAuth.sol/NFTAuth.json').abi;

// 🟢 MAINNET RPC
const provider = new ethers.providers.JsonRpcProvider("https://polygon-mainnet.g.alchemy.com/v2/3QTktG3ajpVUnNsciJQEI");
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, CONTRACT_ABI, wallet);

app.post('/mint', async (req, res) => {
  try {
    const { address, tokenURI, devicePublicKey } = req.body;

    const tempAddress = wallet.address;

    if (!address || !tokenURI || !devicePublicKey) {
      return res.status(400).json({ success: false, error: "Missing address, tokenURI, or devicePublicKey" });
    }

    if (!ethers.utils.isAddress(address) || !ethers.utils.isAddress(devicePublicKey)) {
      return res.status(400).json({ success: false, error: "Invalid Ethereum address format" });
    }

    console.log("Minting to:", address);

    const tx = await contract.safeMint(
      tempAddress,
      tokenURI,
      devicePublicKey,
      {
        maxPriorityFeePerGas: ethers.utils.parseUnits('30', 'gwei'),
        maxFeePerGas: ethers.utils.parseUnits('50', 'gwei'),
      }
    );

    console.log("TX sent:", tx.hash);
    await tx.wait();

    return res.json({ success: true, txHash: tx.hash });

  } catch (err) {
    console.error("Mint failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/transfer', async (req, res) => {
  try {
    const { to, tokenId } = req.body;

    if (!to || tokenId === undefined) {
      return res.status(400).json({ success: false, error: "Missing 'to' or 'tokenId'" });
    }

    const from = wallet.address; // owner wallet

    const tx = await contract['safeTransferFrom(address,address,uint256)'](
      from,
      to,
      tokenId,
      {
        maxPriorityFeePerGas: ethers.utils.parseUnits('30', 'gwei'),
        maxFeePerGas: ethers.utils.parseUnits('50', 'gwei'),
      }
    );

    console.log("Transfer TX:", tx.hash);
    await tx.wait();

    return res.json({ success: true, txHash: tx.hash });
  } catch (err) {
    console.error("Transfer failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});


app.listen(3000, () => {
  console.log('✅ Mint server live at http://localhost:3000');
});
