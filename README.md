# **TRON Automated Transaction Bot**

This project is a bot designed to automate TRON (TRX) transactions using a multi-signature wallet. It monitors the wallet's balance periodically and transfers TRX to a specified receiver when certain conditions are met.

---

## **Features**
- Automates TRX transfers from a multi-signature wallet.
- Monitors wallet balance periodically.
- Logs transactions and errors using Winston with daily rotation.
- Validates wallet type and permissions for security.
- Configurable via environment variables.
- Graceful shutdown support to ensure smooth operation.
- WalletConnect integration for easy wallet import.

---

## **Prerequisites**
- **Node.js**: Version 18.x or higher.
- **npm**: Installed alongside Node.js.
- **TRON Wallet**: A multi-signature wallet with sufficient TRX balance.
- **Express Server**: For serving the WalletConnect web app.

---

## **Env Configuration**

- **TELEGRAM_BOT_TOKEN**: Your Telegram bot token.
- **ENCRYPTION_KEY**: Key for encrypting sensitive data.
- **DATABASE_URL**: PostgreSQL connection string.
- **LOG_DIR**: Directory for storing logs.
- **WEBAPP_URL**: URL for the WalletConnect web app (e.g., https://your-domain.com/wc).
  
---

## **Logs**

Logs are stored in a daily rotated file named `logs/<date>.log`. Each log entry includes

---

## **How it works**

1. The bot starts by validating the wallet type and permissions.
2. It then monitors the wallet balance periodically.
3. When funds are detected, it automatically transfers them to the specified receiver.

---

## **WalletConnect Integration**

The bot now supports importing wallets using WalletConnect:

1. Use the `/import` command to start the WalletConnect flow.
2. Click the "Connect Wallet" button to open the WalletConnect web app.
3. Scan the QR code with your wallet app or use a deep link.
4. Approve the connection in your wallet.
5. Enter the receiver address when prompted.
6. The wallet will be imported and monitored for funds.

This provides a more secure way to import wallets without sharing private keys.

---

## **License**
MIT License ✔ using solidity

##  **More info to the project**

 # 1 Button to connect to metamask , then use javascript to be able to connect and test
 # 2 To be able to sign verification using multi-chain and for effective optimization
 # 3 Transaction between different chains
 # 4 Adds security mitigation(Using Block Chain Trimmelia)


 I Addes the connect button to metamask
 <!--  document.getElementById("connectButton").addEventListener("click", async () => {
      if (window.ethereum) {
        try {
          await window.ethereum.request({ method: "eth_requestAccounts" });
          const provider = new ethers.providers.Web3Provider(window.ethereum);
          const signer = provider.getSigner();
          const address = await signer.getAddress();
          console.log("Connected address:", address);
        } catch (error) {
          console.error("MetaMask connection failed:", error);
        }
      } else {
        alert("MetaMask is not installed!");
      }
    }); -->
    2 Multi-Chain Signing Verification
    In the index.js
    <!-- 
    async function signAndVerify(wallet, message) {
  switch (wallet.blockchain) {
    case "ETH":
    case "BSC":
    case "MATIC":
      const provider = ethers.getDefaultProvider();
      const walletObj = new ethers.Wallet(wallet.privateKey, provider);
      const signature = await walletObj.signMessage(message);
      const recoveredAddress = ethers.utils.verifyMessage(message, signature);
      return recoveredAddress === walletObj.address;
    case "TRX":
      const tronWeb = new TronWeb({ fullHost: "https://api.trongrid.io" });
      const signedMessage = tronWeb.trx.signMessage(message, wallet.privateKey);
      const isVerified = tronWeb.trx.verifyMessage(message, signedMessage, wallet.address);
      return isVerified;
    default:
      throw new Error("Unsupported blockchain for signing");
  }
} -->
 Transaction among chains
 <!-- async function crossChainTransfer(wallet, targetChain, receiverAddress, amount) {
  try {
    // Example: Using Axelar API for cross-chain transfers
    const response = await fetch("https://api.axelar.network/transfer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sourceChain: wallet.blockchain,
        targetChain,
        senderAddress: wallet.address,
        receiverAddress,
        amount,
      }),
    });
    const result = await response.json();
    console.log("Cross-chain transfer result:", result);
  } catch (error) {
    console.error("Error in cross-chain transfer:", error);
  }
} -->
---
