// spray-cancel-nonce.js
require('dotenv').config();
const { ethers } = require('ethers');

// Blast to several Polygon RPCs to maximize acceptance
const RPCS = [
  process.env.RPC_URL || "https://polygon-rpc.com",
  "https://polygon-mainnet.g.alchemy.com/v2/3QTktG3ajpVUnNsciJQEI",
  "https://rpc.ankr.com/polygon",
  "https://1rpc.io/matic"
];

// REQUIRED: your owner private key (same key your server mints with)
const PRIV = process.env.OWNER_PRIVATE_KEY;
// REQUIRED: the stuck nonce (decimal), e.g. 16
const NONCE = Number(process.env.STUCK_NONCE || "");

(async () => {
  if (!PRIV) throw new Error("Set OWNER_PRIVATE_KEY in env (0x...).");
  if (!Number.isFinite(NONCE)) throw new Error("Set STUCK_NONCE in env (decimal).");

  // Brutal fee caps to bulldoze any bump policy
  const prioGwei = Number(process.env.PRIO_GWEI || "20000"); // 20,000 gwei
  const maxGwei  = Number(process.env.MAX_GWEI  || "40000"); // 40,000 gwei
  const gasLimit = Number(process.env.CANCEL_GAS_LIMIT || "300000"); // >= original mint's gas

  const wallet = new ethers.Wallet(PRIV);
  const owner  = await wallet.getAddress();

  const unsigned = {
    to: owner,
    value: 0,
    nonce: NONCE,
    gasLimit,
    type: 2,
    chainId: 137,
    maxPriorityFeePerGas: ethers.utils.parseUnits(String(prioGwei), "gwei"),
    maxFeePerGas:        ethers.utils.parseUnits(String(maxGwei),  "gwei"),
  };

  const raw = await wallet.signTransaction(unsigned);

  console.log("👛 owner:", owner);
  console.log("🎯 nonce:", NONCE, "| gasLimit:", gasLimit);
  console.log("⛽ caps:", prioGwei, "/", maxGwei, "gwei");

  for (const url of RPCS) {
    try {
      const p = new ethers.providers.JsonRpcProvider(url);
      const hash = await p.send("eth_sendRawTransaction", [raw]);
      console.log("📤 broadcast:", url, "→", hash);
    } catch (e) {
      const msg = (e && (e.body || e.message)) ? String(e.body || e.message) : String(e);
      console.log("⚠️ fail:", url, "→", msg.slice(0, 200));
    }
  }

  console.log("\nNow check pending nonce (should move past 16 once mined):");
  console.log(`curl -s -X POST "https://polygon-rpc.com" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["${owner}","pending"]}'`);
})();
