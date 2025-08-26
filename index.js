// Minimum sweep amounts per chain, in asset units (TRX, BTC, ETH, SOL)
const MIN_SWEEP_AMOUNTS = Object.freeze({
  TRX: 1,      // 1 TRX
  BTC: 0.0001, // 0.0001 BTC
  ETH: 0.001,  // 0.001 ETH
  SOL: 0.01    // 0.01 SOL
});
require("dotenv").config();
const TelegramBot = require("node-telegram-bot-api");
const { db } = require("./db/db");
const { wallets, transactions, users } = require("./db/schema");
const { eq } = require("drizzle-orm");
const { TronWeb } = require("tronweb");
const bitcoin = require("bitcoinjs-lib");
const ecc = require("tiny-secp256k1");
const { ECPairFactory } = require("ecpair");
const bip39 = require("bip39");
const hdkey = require("hdkey");
const { ethers } = require("ethers");
const { Connection, Keypair, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL, sendAndConfirmTransaction } = require("@solana/web3.js");

const ECPair = ECPairFactory(ecc);

// Create bot instance with error handling
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, {
  polling: {
    interval: 1000,
    autoStart: true,
    params: {
      timeout: 10
    }
  }
});

// Handle polling errors
bot.on('polling_error', (error) => {
  console.error('Telegram polling error:', error.message);
  // Don't exit the process, just log the error
});

// Global userStates for interactive wallet setup
const userStates = new Map();

// List of supported BTC derivation paths
const supportedBTCPaths = [
  "m/44'/0'/0'/0/0",   // Legacy
  "m/49'/0'/0'/0/0",   // SegWit (P2SH)
  "m/84'/0'/0'/0/0",   // Native SegWit (bech32)
];

//
// Utility: Derive a BTC wallet from a seed phrase using multiple derivation paths
//
async function deriveBTCWallet(seedPhrase) {
  const normalizedSeed = seedPhrase.trim().replace(/\s+/g, " ").toLowerCase();

  if (!bip39.validateMnemonic(normalizedSeed)) {
    throw new Error("Invalid seed phrase. Please check your words and try again.");
  }

  const seed = await bip39.mnemonicToSeed(normalizedSeed);
  const root = hdkey.fromMasterSeed(seed);
  let derivedWallet = null;

  for (const path of supportedBTCPaths) {
    try {
      // Use hdkey's derive method (not derivePath)
      const child = root.derive(path);
      if (!child.privateKey) continue;

      const { address } = bitcoin.payments.p2pkh({
        pubkey: Buffer.from(child.publicKey),
        network: bitcoin.networks.bitcoin,
      });
      if (address) {
        derivedWallet = {
          address,
          privateKey: child.toWIF(),
          derivationPath: path,
        };
        console.log(`Wallet derived using path: ${path} => Address: ${address}`);
        break;
      }
    } catch (err) {
      console.error(`Error with derivation path ${path}:`, err);
      continue;
    }
  }
  if (!derivedWallet) {
    throw new Error("Unsupported wallet derivation path or unknown seed phrase type.");
  }
  return derivedWallet;
}

//
// TELEGRAM BOT COMMANDS & FLOW
//

bot.setMyCommands([
  { command: "start", description: "Start the bot and get registered" },
  { command: "setwallet", description: "Add a new wallet for monitoring" },
  { command: "listwallets", description: "View all your configured wallets" },
  { command: "checkbalance", description: "Check your wallet balance" },
  { command: "deletewallet", description: "Delete a configured wallet" }
]);

// /start command – register user if necessary
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const username = msg.from.username || "Unknown";
  try {
    const existingUser = await db.select().from(users)
      .where(eq(users.telegramUserId, chatId.toString()))
      .then((res) => res[0]);

    if (!existingUser) {
      await db.insert(users).values({
        telegramUserId: chatId.toString(),
        telegramUsername: username,
      });
      bot.sendMessage(chatId, `✅ You have been registered for TRX transaction alerts!`);
    } else {
      bot.sendMessage(chatId, `⚡ You are already registered.`);
    }
    bot.sendMessage(
      chatId,
      "Welcome to the TRX Transaction Bot! 🚀\n\n" +
      "I'll help you monitor your crypto wallets and automatically transfer funds when they reach your specified threshold.\n\n" +
      "Use the menu button (/) to see all available commands, or click the button below:",
      {
        parse_mode: "Markdown",
        reply_markup: {
          keyboard: [["/start", "/setwallet"], ["/listwallets", "/checkbalance"]],
          resize_keyboard: true,
          one_time_keyboard: true,
        },
      }
    );
  } catch (error) {
    console.error("Error handling /start:", error);
    bot.sendMessage(chatId, "❌ An error occurred. Please try again.");
  }
});

// /listwallets command – show user’s saved wallets
bot.onText(/\/listwallets/, async (msg) => {
  const chatId = msg.chat.id;
  try {
    const user = await db.select().from(users)
      .where(eq(users.telegramUserId, chatId.toString()))
      .then((res) => res[0]);
    if (!user) return bot.sendMessage(chatId, "❌ Please use /start first.");
    const userWallets = await db.select().from(wallets)
      .where(eq(wallets.userId, user.id));
    if (userWallets.length === 0)
      return bot.sendMessage(chatId, "❌ No wallets found. Use /setwallet to add a wallet!");
    let message = "📋 *Your Wallets:*\n\n";
    for (const wallet of userWallets) {
      message += `*Wallet ${wallet.id}*\n`;
      message += `Blockchain: ${wallet.blockchain}\n`;
      message += `Address: \`${wallet.address}\`\n`;
      message += `Receiver: \`${wallet.receiverAddress}\`\n\n`;
    }
    bot.sendMessage(chatId, message, { parse_mode: "Markdown" });
  } catch (error) {
    console.error("Error listing wallets:", error);
    bot.sendMessage(chatId, "❌ Failed to list wallets.");
  }
});

// /setwallet command – interactive flow to add wallet
bot.onText(/\/setwallet/, (msg) => {
  const chatId = msg.chat.id;
  userStates.set(chatId, { step: "blockchain", data: {} });
  bot.sendMessage(
    chatId,
    "Let's set up your wallet. First, please select the blockchain:",
    {
      reply_markup: {
        inline_keyboard: [
          [{ text: "TRX", callback_data: "blockchain_TRX" }],
          [{ text: "BTC", callback_data: "blockchain_BTC" }],
          [{ text: "ETH", callback_data: "blockchain_ETH" }],
          [{ text: "SOL", callback_data: "blockchain_SOL" }],
        ],
      },
    }
  );
});

// Unified callback query handler for wallet setup and deletion
bot.on("callback_query", async (callbackQuery) => {
  const chatId = callbackQuery.message.chat.id;
  const data = callbackQuery.data;

  if (data.startsWith("blockchain_")) {
    const blockchain = data.split("_")[1];
    userStates.set(chatId, { step: "auth_method", data: { blockchain } });
    await bot.editMessageText("How would you like to authenticate your wallet?", {
      chat_id: chatId,
      message_id: callbackQuery.message.message_id,
      reply_markup: {
        inline_keyboard: [
          [{ text: "Private Key", callback_data: "auth_privateKey" }],
          [{ text: "Seed Phrase", callback_data: "auth_seedPhrase" }],
        ],
      },
    });
  } else if (data.startsWith("auth_")) {
    const authMethod = data.split("_")[1];
    const state = userStates.get(chatId);
    state.step = "address";
    state.data.authMethod = authMethod;
    userStates.set(chatId, state);
    
    let addressPrompt;
    switch (state.data.blockchain) {
      case "BTC":
        addressPrompt = "Please enter your Bitcoin wallet address:\n\n• Example: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n• Or: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
        break;
      case "ETH":
        addressPrompt = "Please enter your Ethereum wallet address:\n\n• Example: 0x742d35Cc6634C0532925a3b8D4C0C8b3C2e1e3e3";
        break;
      case "SOL":
        addressPrompt = "Please enter your Solana wallet address:\n\n• Example: 7pgQDk79dG9ToAUrV9vCCj5DHUo5XkCoimuG2M7mRths";
        break;
      case "TRX":
        addressPrompt = "Please enter your TRON wallet address:\n\n• Example: TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH";
        break;
      default:
        addressPrompt = `Please enter your ${state.data.blockchain} wallet address:`;
    }
    
    await bot.editMessageText(
      addressPrompt,
      { chat_id: chatId, message_id: callbackQuery.message.message_id }
    );
  } else if (data.startsWith("delete_wallet_")) {
    const walletId = parseInt(data.split("_")[2]);
    try {
      await db.delete(transactions).where(eq(transactions.walletId, walletId));
      await db.delete(wallets).where(eq(wallets.id, walletId));
      await bot.editMessageText("✅ Wallet deleted successfully!", {
        chat_id: chatId,
        message_id: callbackQuery.message.message_id,
        reply_markup: { inline_keyboard: [] },
      });
      bot.sendMessage(chatId, "The wallet has been removed from monitoring. Use /listwallets to see your remaining wallets.");
    } catch (error) {
      console.error("Error deleting wallet:", error);
      await bot.editMessageText("❌ Failed to delete wallet. Please try again.", {
        chat_id: chatId,
        message_id: callbackQuery.message.message_id,
        reply_markup: { inline_keyboard: [] },
      });
    }
  }
});

// Continue interactive wallet setup flow
bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const state = userStates.get(chatId);
  if (!state) return;

  if (state.step === "address") {
    state.data.address = msg.text.trim();
    state.step = "key";
    userStates.set(chatId, state);
    
    let keyPrompt;
    if (state.data.authMethod === "privateKey") {
      switch (state.data.blockchain) {
        case "BTC":
          keyPrompt = 'Please enter your BTC private key:\n\n• Must be 64 hexadecimal characters (0-9, a-f)\n• Do not include "0x" prefix\n• Example: 1234...abcd';
          break;
        case "ETH":
          keyPrompt = 'Please enter your ETH private key:\n\n• 64 hex characters with or without 0x prefix\n• Example: 0x1234...abcd';
          break;
        case "SOL":
          keyPrompt = 'Please enter your SOL private key:\n\n• Supported formats:\n• Base58 (88 chars)\n• Hex (128 chars)\n• Comma-separated array of 64 numbers';
          break;
        case "TRX":
          keyPrompt = 'Please enter your TRX private key:\n\n• 64 hexadecimal characters';
          break;
        default:
          keyPrompt = "Please enter your private key:";
      }
    } else {
      keyPrompt = 'Please enter your seed phrase:\n\n• 12 or 24 words separated by spaces\n• Example: word1 word2 word3 ... word12';
    }
    
    bot.sendMessage(chatId, `${keyPrompt}\n\n⚠️ This will be stored securely but please be careful when sharing sensitive information.`);
  } else if (state.step === "key") {
    state.data.key = msg.text;
    state.step = "receiver";
    userStates.set(chatId, state);
    bot.sendMessage(chatId, "Please enter the receiver address where funds should be sent.");
  } else if (state.step === "receiver") {
    state.data.receiver = msg.text;
    try {
      // Apply chain-specific minimum threshold for auto-sweeps
      await setupWallet(
        chatId,
        state.data.blockchain,
        state.data.key,
        state.data.receiver,
        MIN_SWEEP_AMOUNTS[state.data.blockchain] || 0,
        state.data.authMethod === "privateKey" ? "privateKey" : "seedPhrase"
      );
      userStates.delete(chatId);
    } catch (error) {
      bot.sendMessage(chatId, `❌ ${error.message}`);
    }
  }
});

// Function to set up a wallet and save it to the database
async function setupWallet(chatId, blockchain, key, receiver, threshold, keyType, manualAddress = null) {
  const user = await db.select().from(users)
    .where(eq(users.telegramUserId, chatId.toString()))
    .then((res) => res[0]);
  if (!user) {
    return bot.sendMessage(chatId, "❌ Please use /start command first to register.");
  }

  // Use the manually entered address from the user state
  const state = userStates.get(chatId);
  const address = state?.data?.address || manualAddress;
  
  if (!address) {
    return bot.sendMessage(chatId, "❌ No wallet address provided. Please try again.");
  }

  // Validate the private key/seed phrase format but don't derive address
  let processedKey = key;
  switch (blockchain) {
    case "TRX": {
      // Just validate the key format, don't derive address
      if (keyType === "privateKey") {
        if (!/^[0-9a-f]{64}$/i.test(key.replace(/^0x/i, ""))) {
          throw new Error("Invalid TRX private key format. Must be 64 hexadecimal characters.");
        }
        processedKey = key.replace(/^0x/i, "");
      } else {
        const normalizedKey = key.trim().replace(/\s+/g, " ").toLowerCase();
        if (!bip39.validateMnemonic(normalizedKey)) {
          throw new Error("Invalid seed phrase. Please check your words and try again.");
        }
        processedKey = normalizedKey;
      }
      break;
    }
    case "BTC":
      try {
        if (keyType === "privateKey") {
          const cleanKey = key.trim().toLowerCase().replace("0x", "");
          if (!/^[0-9a-f]{64}$/.test(cleanKey)) {
            throw new Error(
              "Invalid private key format.\n• Must be exactly 64 hexadecimal characters (0-9, a-f)\n• Do not include '0x' prefix\n• Example: 1234...abcd"
            );
          }
          // Convert to WIF format for storage
          const keyPair = ECPair.fromPrivateKey(Buffer.from(cleanKey, "hex"), { network: bitcoin.networks.bitcoin });
          processedKey = keyPair.toWIF();
        } else {
          const normalizedKey = key.trim().replace(/\s+/g, " ").toLowerCase();
          const words = normalizedKey.split(" ");
          if (words.length !== 12 && words.length !== 24) {
            throw new Error(
              "Invalid seed phrase length.\n• Must be exactly 12 or 24 words\n• Words must be separated by single spaces"
            );
          }
          if (!bip39.validateMnemonic(normalizedKey)) {
            throw new Error("Invalid seed phrase. Please check your words and try again.");
          }
          processedKey = normalizedKey;
        }
      } catch (error) {
        console.error("BTC wallet validation error:", error);
        throw new Error("Failed to validate BTC wallet: " + error.message);
      }
      break;
    case "ETH":
      try {
        if (keyType === "privateKey") {
          const cleanKey = key.trim().toLowerCase();
          const privateKey = cleanKey.startsWith("0x") ? cleanKey : `0x${cleanKey}`;
          if (!/^0x[0-9a-f]{64}$/i.test(privateKey)) {
            throw new Error("Invalid ETH private key format. Must be 64 hex characters with or without 0x prefix.");
          }
          processedKey = privateKey;
        } else {
          const normalizedKey = key.trim().replace(/\s+/g, " ").toLowerCase();
          if (!bip39.validateMnemonic(normalizedKey)) {
            throw new Error("Invalid seed phrase. Please check your words and try again.");
          }
          // For seed phrases, we'll derive the private key for storage
          const wallet = ethers.Wallet.fromPhrase(normalizedKey);
          processedKey = wallet.privateKey;
        }
      } catch (error) {
        console.error("ETH wallet validation error:", error);
        throw new Error("Failed to validate ETH wallet: " + error.message);
      }
      break;
    case "SOL":
      try {
        if (keyType === "privateKey") {
          const cleanKey = key.trim().replace(/[\[\],\s]/g, "");
          let privateKeyBytes;

          if (cleanKey.length === 128) {
            // Hex format
            privateKeyBytes = Buffer.from(cleanKey, "hex");
          } else if (cleanKey.length === 88) {
            // Base58 format
            const bs58 = require("bs58");
            privateKeyBytes = bs58.decode(cleanKey);
          } else {
            // Try to parse as comma-separated numbers
            try {
              const keyArray = cleanKey.split(",").map(n => parseInt(n.trim()));
              if (keyArray.length !== 64) throw new Error("Invalid length");
              privateKeyBytes = new Uint8Array(keyArray);
            } catch {
              throw new Error("Invalid SOL private key format. Supported formats: hex (128 chars), base58 (88 chars), or comma-separated array of 64 numbers.");
            }
          }

          if (privateKeyBytes.length !== 64) {
            throw new Error("SOL private key must be exactly 64 bytes");
          }
          
          // Validate the keypair can be created
          const keypair = Keypair.fromSecretKey(privateKeyBytes);
          processedKey = Array.from(keypair.secretKey).join(",");
        } else {
          const normalizedKey = key.trim().replace(/\s+/g, " ").toLowerCase();
          if (!bip39.validateMnemonic(normalizedKey)) {
            throw new Error("Invalid seed phrase. Please check your words and try again.");
          }
          
          // For seed phrases, we'll use the direct seed method as default
          // User has already provided their address manually
          const seed = await bip39.mnemonicToSeed(normalizedKey, "");
          const keypair = Keypair.fromSeed(seed.slice(0, 32));
          processedKey = Array.from(keypair.secretKey).join(",");
        }
      } catch (error) {
        console.error("SOL wallet validation error:", error);
        throw new Error("Failed to validate SOL wallet: " + error.message);
      }
      break;
    default:
      throw new Error("Unsupported blockchain");
  }

  console.log(`✅ Wallet validated for ${blockchain}: ${address}`);

  await db.insert(wallets).values({
    userId: user.id,
    blockchain,
    privateKey: processedKey,
    address,
    threshold: 0, // Always 0 - sweep any balance
    receiverAddress: receiver,
  });

  bot.sendMessage(
    chatId,
    `✅ Wallet set up successfully!\n\n**Blockchain:** ${blockchain}\n**Address:** \`${address}\`\n**Receiver:** \`${receiver}\`\n\n🔄 The bot will automatically sweep any funds found in this wallet to the receiver address.`,
    { parse_mode: "Markdown" }
  );
}

// /checkbalance command – show current balances
bot.onText(/\/checkbalance/, async (msg) => {
  const chatId = msg.chat.id;
  try {
    const user = await db.select().from(users)
      .where(eq(users.telegramUserId, chatId.toString()))
      .then((res) => res[0]);
    if (!user) return bot.sendMessage(chatId, "❌ Please use /start first.");

    const userWallets = await db.select().from(wallets)
      .where(eq(wallets.userId, user.id));
    if (userWallets.length === 0)
      return bot.sendMessage(chatId, "❌ No wallets found. Use /setwallet to add a wallet!");

    let message = "💰 *Wallet Balances:*\n\n";

    for (const wallet of userWallets) {
      if (wallet.blockchain === "TRX") {
        const tronWeb = new TronWeb({
          fullHost: "https://api.trongrid.io",
          privateKey: wallet.privateKey,
        });
        const balance = await tronWeb.trx.getBalance(wallet.address);
        message += `*Wallet ${wallet.id}*\n`;
        message += `Address: \`${wallet.address}\`\n`;
        message += `Balance: ${balance / 1e6} TRX\n\n`;
      } else if (wallet.blockchain === "BTC") {
        try {
          const res = await fetch(`https://blockchain.info/unspent?active=${wallet.address}`);
          if (!res.ok) {
            message += `*Wallet ${wallet.id}*\nAddress: \`${wallet.address}\`\nBalance: 0 BTC (no UTXOs)\n\n`;
            continue;
          }
          const jsonData = await res.json();
          if (!jsonData.unspent_outputs || jsonData.unspent_outputs.length === 0) {
            message += `*Wallet ${wallet.id}*\nAddress: \`${wallet.address}\`\nBalance: 0 BTC (no UTXOs)\n\n`;
          } else {
            const balanceSats = jsonData.unspent_outputs.reduce((acc, utxo) => acc + utxo.value, 0);
            const balanceBtc = balanceSats / 1e8;
            message += `*Wallet ${wallet.id}*\n`;
            message += `Address: \`${wallet.address}\`\n`;
            message += `Balance: ${balanceBtc} BTC\n\n`;
          }
        } catch (error) {
          console.error("Error fetching BTC UTXOs:", error);
          message += `*Wallet ${wallet.id}*\nAddress: \`${wallet.address}\`\nBalance: Unknown (API error)\n\n`;
        }
      } else if (wallet.blockchain === "ETH") {
        try {
          // Using a free Ethereum RPC endpoint
          const provider = new ethers.JsonRpcProvider("https://eth.llamarpc.com");
          const balance = await provider.getBalance(wallet.address);
          const balanceEth = ethers.formatEther(balance);
          message += `*Wallet ${wallet.id}*\n`;
          message += `Address: \`${wallet.address}\`\n`;
          message += `Balance: ${balanceEth} ETH\n\n`;
        } catch (error) {
          console.error("Error fetching ETH balance:", error);
          message += `*Wallet ${wallet.id}*\nAddress: \`${wallet.address}\`\nBalance: Unknown (API error)\n\n`;
        }
      } else if (wallet.blockchain === "SOL") {
        try {
          // Use multiple RPC endpoints for better reliability
          const rpcEndpoints = [
            "https://api.mainnet-beta.solana.com",
            "https://solana-api.projectserum.com",
            "https://rpc.ankr.com/solana"
          ];

          let balance = 0;
          let connected = false;

          for (const endpoint of rpcEndpoints) {
            try {
              const connection = new Connection(endpoint, { commitment: 'confirmed' });
              const publicKey = new PublicKey(wallet.address);
              balance = await connection.getBalance(publicKey);
              connected = true;
              break;
            } catch (err) {
              console.log(`SOL balance check failed for ${endpoint}:`, err.message);
              continue;
            }
          }

          if (connected) {
            const balanceSol = balance / LAMPORTS_PER_SOL;
            message += `*Wallet ${wallet.id}*\n`;
            message += `Address: \`${wallet.address}\`\n`;
            message += `Balance: ${balanceSol} SOL\n\n`;
          } else {
            message += `*Wallet ${wallet.id}*\nAddress: \`${wallet.address}\`\nBalance: Unknown (RPC error)\n\n`;
          }
        } catch (error) {
          console.error("Error fetching SOL balance:", error);
          message += `*Wallet ${wallet.id}*\nAddress: \`${wallet.address}\`\nBalance: Unknown (API error)\n\n`;
        }
      } else {
        message += `*Wallet ${wallet.id}*\n`;
        message += `Blockchain: ${wallet.blockchain}\nStatus: Unsupported blockchain\n\n`;
      }
    }

    bot.sendMessage(chatId, message, { parse_mode: "Markdown" });
  } catch (error) {
    console.error("Error checking balance:", error);
    bot.sendMessage(chatId, "❌ Failed to check balance.");
  }
});

// Function to check and send funds for all supported wallets
async function checkAndSendFunds(wallet) {
  try {
    let balance = 0;
    let amountToSend = 0;
    let response;

    switch (wallet.blockchain) {
      case "TRX": {
        const tronWeb = new TronWeb({
          fullHost: "https://api.trongrid.io",
          privateKey: wallet.privateKey,
        });
        balance = await tronWeb.trx.getBalance(wallet.address);
        const balanceTrx = balance / 1e6;

        if (balanceTrx > 0) {
          const estimatedFee = 100000; // 0.1 TRX in sun
          amountToSend = balance - estimatedFee;
          if (amountToSend <= 0) return;
          const transaction = await tronWeb.transactionBuilder.sendTrx(
            wallet.receiverAddress,
            amountToSend,
            wallet.address
          );
          const signedTransaction = await tronWeb.trx.sign(transaction);
          response = await tronWeb.trx.sendRawTransaction(signedTransaction);
          amountToSend = amountToSend / 1e6; // Convert to TRX for display
        }
        break;
      }

      case "BTC":
        try {
          const network = bitcoin.networks.bitcoin;
          // Reconstruct keyPair from the stored WIF
          const keyPair = ECPair.fromWIF(wallet.privateKey, network);
          const utxoResponse = await fetch(`https://blockchain.info/unspent?active=${wallet.address}`);
          const utxoData = await utxoResponse.json();
          if (utxoData.unspent_outputs && utxoData.unspent_outputs.length > 0) {
            const utxos = utxoData.unspent_outputs;
            balance = utxos.reduce((acc, utxo) => acc + utxo.value, 0);
            const balanceBtc = balance / 1e8;

            if (balanceBtc > 0) {
              const feeRate = 10; // satoshis/byte
              const estimatedSize = 180; // approximate
              const fee = estimatedSize * feeRate;
              amountToSend = balance - fee;
              if (amountToSend <= 0) return;
              const psbt = new bitcoin.Psbt({ network });
              utxos.forEach((utxo) => {
                psbt.addInput({
                  hash: utxo.tx_hash_big_endian,
                  index: utxo.tx_output_n,
                  nonWitnessUtxo: Buffer.from(utxo.script, "hex"),
                });
              });
              psbt.addOutput({
                address: wallet.receiverAddress,
                value: amountToSend,
              });
              utxos.forEach((_, i) => {
                psbt.signInput(i, keyPair);
                psbt.validateSignaturesOfInput(i);
              });
              psbt.finalizeAllInputs();
              const tx = psbt.extractTransaction();
              const txHex = tx.toHex();
              const broadcastResponse = await fetch("https://blockchain.info/pushtx", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `tx=${txHex}`,
              });
              if (broadcastResponse.ok) {
                response = { result: true, txid: tx.getId() };
                amountToSend = amountToSend / 1e8; // Convert to BTC for display
              }
            }
          }
        } catch (error) {
          console.error("Error processing BTC transaction:", error);
        }
        break;

      case "ETH":
        try {
          const provider = new ethers.JsonRpcProvider("https://eth.llamarpc.com");
          const ethWallet = new ethers.Wallet(wallet.privateKey, provider);

          balance = await provider.getBalance(wallet.address);
          const balanceEth = parseFloat(ethers.formatEther(balance));

          if (balanceEth > 0) {
            // Get current gas price
            const feeData = await provider.getFeeData();
            const gasPrice = feeData.gasPrice;
            const gasLimit = 21000n; // Standard ETH transfer
            const gasCost = gasPrice * gasLimit;

            // Calculate amount to send (balance - gas fees)
            const amountToSendWei = balance - gasCost;

            if (amountToSendWei > 0n) {
              const tx = {
                to: wallet.receiverAddress,
                value: amountToSendWei,
                gasLimit: gasLimit,
                gasPrice: gasPrice,
              };

              const sentTx = await ethWallet.sendTransaction(tx);
              await sentTx.wait(); // Wait for confirmation

              amountToSend = parseFloat(ethers.formatEther(amountToSendWei));
              response = { result: true, txid: sentTx.hash };
            }
          }
        } catch (error) {
          console.error("Error processing ETH transaction:", error);
        }
        break;

      case "SOL":
        try {
          // Use multiple RPC endpoints for better reliability
          const rpcEndpoints = [
            "https://api.mainnet-beta.solana.com",
            "https://solana-api.projectserum.com",
            "https://rpc.ankr.com/solana"
          ];

          let connection = null;
          let connectionError = null;

          // Try different RPC endpoints
          for (const endpoint of rpcEndpoints) {
            try {
              connection = new Connection(endpoint, {
                commitment: 'confirmed',
                confirmTransactionInitialTimeout: 60000
              });

              // Test connection with a simple call
              await connection.getSlot();
              console.log(`SOL: Connected to ${endpoint}`);
              break;
            } catch (err) {
              console.log(`SOL: Failed to connect to ${endpoint}:`, err.message);
              connectionError = err;
              continue;
            }
          }

          if (!connection) {
            throw new Error(`Failed to connect to any Solana RPC: ${connectionError?.message}`);
          }

          // Reconstruct keypair from stored private key
          let privateKeyBytes;
          if (wallet.privateKey.includes(",")) {
            // Comma-separated format
            privateKeyBytes = new Uint8Array(wallet.privateKey.split(",").map(n => parseInt(n)));
          } else {
            // Try other formats
            const bs58 = require("bs58");
            privateKeyBytes = bs58.decode(wallet.privateKey);
          }

          const keypair = Keypair.fromSecretKey(privateKeyBytes);
          const publicKey = keypair.publicKey;

          // Add retry logic for balance check
          let retries = 3;
          while (retries > 0) {
            try {
              balance = await connection.getBalance(publicKey);
              break;
            } catch (err) {
              retries--;
              if (retries === 0) throw err;
              console.log(`SOL: Retrying balance check, ${retries} attempts left`);
              await new Promise(resolve => setTimeout(resolve, 2000));
            }
          }

          const balanceSol = balance / LAMPORTS_PER_SOL;

          if (balanceSol > 0) {
            // Get recent blockhash with retry
            let blockhash;
            retries = 3;
            while (retries > 0) {
              try {
                const result = await connection.getLatestBlockhash();
                blockhash = result.blockhash;
                break;
              } catch (err) {
                retries--;
                if (retries === 0) throw err;
                console.log(`SOL: Retrying blockhash fetch, ${retries} attempts left`);
                await new Promise(resolve => setTimeout(resolve, 2000));
              }
            }

            // Estimate transaction fee (typically 5000 lamports)
            const fee = 5000;
            amountToSend = balance - fee;

            if (amountToSend > 0) {
              const transaction = new Transaction().add(
                SystemProgram.transfer({
                  fromPubkey: publicKey,
                  toPubkey: new PublicKey(wallet.receiverAddress),
                  lamports: amountToSend,
                })
              );

              transaction.recentBlockhash = blockhash;
              transaction.feePayer = publicKey;

              // Sign and send transaction with retry
              let signature;
              retries = 3;
              while (retries > 0) {
                try {
                  signature = await sendAndConfirmTransaction(
                    connection,
                    transaction,
                    [keypair],
                    {
                      commitment: 'confirmed',
                      maxRetries: 3
                    }
                  );
                  break;
                } catch (err) {
                  retries--;
                  if (retries === 0) throw err;
                  console.log(`SOL: Retrying transaction, ${retries} attempts left`);
                  await new Promise(resolve => setTimeout(resolve, 3000));
                }
              }

              amountToSend = amountToSend / LAMPORTS_PER_SOL; // Convert to SOL for display
              response = { result: true, txid: signature };
            }
          }
        } catch (error) {
          console.error("Error processing SOL transaction:", error.message);
          // Don't throw, just log and continue
        }
        break;
    }

    if (response && response.result) {
      await db.insert(transactions).values({
        walletId: wallet.id,
        blockchain: wallet.blockchain,
        amount: amountToSend,
        status: "success",
        txHash: response.txid,
      });
      const user = await db.select().from(users)
        .where(eq(users.id, wallet.userId))
        .then((res) => res[0]);
      if (user) {
        // Create explorer URL based on blockchain
        let explorerUrl;
        switch (wallet.blockchain) {
          case "BTC":
            explorerUrl = `https://blockchain.com/btc/tx/${response.txid}`;
            break;
          case "ETH":
            explorerUrl = `https://etherscan.io/tx/${response.txid}`;
            break;
          case "SOL":
            explorerUrl = `https://explorer.solana.com/tx/${response.txid}`;
            break;
          case "TRX":
          default:
            explorerUrl = `https://tronscan.org/#/transaction/${response.txid}`;
            break;
        }

        const message = `🚀 *Transaction Alert!*\n\n✅ *${amountToSend} ${wallet.blockchain}* sent to *${wallet.receiverAddress}*\n📌 *Tx Hash:* ${response.txid}\n\n🔗 [View on Explorer](${explorerUrl})`;
        bot.sendMessage(user.telegramUserId, message, { parse_mode: "Markdown" });
      }
    }
  } catch (error) {
    console.error(`❌ Error processing ${wallet.blockchain} transaction:`, error.message);
  }
}

// Periodic check for all supported wallets every 2 minutes (reduced frequency to avoid rate limits)
setInterval(async () => {
  try {
    console.log("🔍 Starting wallet monitoring cycle...");
    const userWallets = await db.select().from(wallets);
    console.log(`Found ${userWallets.length} wallets to monitor`);

    for (const wallet of userWallets) {
      if (["TRX", "BTC", "ETH", "SOL"].includes(wallet.blockchain)) {
        try {
          console.log(`Checking ${wallet.blockchain} wallet: ${wallet.address.slice(0, 8)}...`);
          await checkAndSendFunds(wallet);
          // Add small delay between wallet checks to avoid overwhelming APIs
          await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`Error checking wallet ${wallet.id} (${wallet.blockchain}):`, error.message);
          // Continue with next wallet instead of stopping
        }
      }
    }
    console.log("✅ Wallet monitoring cycle completed");
  } catch (error) {
    console.error("Error in monitoring cycle:", error.message);
  }
}, 120000); // Changed to 2 minutes

// /deletewallet command – remove wallet and associated transactions
bot.onText(/\/deletewallet/, async (msg) => {
  const chatId = msg.chat.id;
  try {
    const user = await db.select().from(users)
      .where(eq(users.telegramUserId, chatId.toString()))
      .then((res) => res[0]);
    if (!user) return bot.sendMessage(chatId, "❌ Please use /start first.");
    const userWallets = await db.select().from(wallets)
      .where(eq(wallets.userId, user.id));
    if (userWallets.length === 0)
      return bot.sendMessage(chatId, "❌ No wallets found. Use /setwallet to add a wallet!");
    const keyboard = userWallets.map((wallet) => [
      {
        text: `Wallet ${wallet.id} (${wallet.address.slice(0, 8)}...)`,
        callback_data: `delete_wallet_${wallet.id}`,
      },
    ]);
    bot.sendMessage(chatId, "Select the wallet you want to delete:", {
      reply_markup: { inline_keyboard: keyboard },
    });
  } catch (error) {
    console.error("Error listing wallets for deletion:", error);
    bot.sendMessage(chatId, "❌ Failed to list wallets.");
  }
});



// Add graceful shutdown handling
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT. Gracefully shutting down...');
  bot.stopPolling();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM. Gracefully shutting down...');
  bot.stopPolling();
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  // Don't exit the process, just log the error
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit the process, just log the error
});

console.log("🔄 Neone Bot Activated");
console.log("📊 Monitoring wallets every 2 minutes");
console.log("🔗 Supported blockchains: TRX, BTC, ETH, SOL");
