// Initialize WalletConnect
let connector = null;
// DOM elements
const connectButton = document.getElementById('connect-button');
const statusElement = document.getElementById('status');

// Initialize Telegram WebApp
const tg = window.Telegram.WebApp;
tg.expand();
// to be able to use the button to send to metamask
const connectToMetaMask = document.get
// Import IPFS client
import { create } from 'ipfs-http-client';


// Initialize IPFS client
const ipfs = create({ host: 'ipfs.infura.io', port: 5001, protocol: 'https' });

// Function to upload data to IPFS
async function uploadToIPFS(data) {
  try {
    const { path } = await ipfs.add(JSON.stringify(data));
    console.log('Data uploaded to IPFS:', path);
    return path; // Returns the IPFS hash
  } catch (error) {
    console.error('Error uploading to IPFS:', error);
    throw error;
  }
}

// Connect button click handler
connectButton.addEventListener('click', async () => {
  try {
    debugLog('Connecting to wallet...');
    
    // Create a new connector
    connector = new WalletConnect.default({
      bridge: 'https://bridge.walletconnect.org',
      qrcodeModal: WalletConnectQRCodeModal.default
    });

    debugLog('WalletConnect connector created');

    // Subscribe to connection events
    connector.on('connect', (error, payload) => {
      if (error) {
        debugLog(`Connection error: ${error.message}`);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.classList.add('error');
        return;
      }

      debugLog('Wallet connected successfully');
      
      // Get connected accounts and chain ID
      const { accounts, chainId } = payload.params[0];
      const account = accounts[0];

      debugLog(`Account: ${account}, Chain ID: ${chainId}`);

      // Update UI
      statusElement.textContent = `Connected: ${account}`;
      statusElement.classList.add('connected');
      statusElement.classList.remove('error');
      connectButton.textContent = 'Connected';
      connectButton.disabled = true;

      // Send data back to Telegram bot
      const data = {
        account,
        chainId,
        ipfsHash
      };

      debugLog('Sending data to Telegram bot: ' + JSON.stringify(data));
      
      // Send data to Telegram bot
      tg.sendData(JSON.stringify(data));
      
      // Close the web app after a short delay to ensure data is sent
      setTimeout(() => {
        debugLog('Closing Telegram WebApp');
        tg.close();
      }, 1000);
    });

    connector.on('disconnect', (error, payload) => {
      if (error) {
        debugLog(`Disconnect error: ${error.message}`);
      } else {
        debugLog('Wallet disconnected');
      }
      
      // Reset UI
      statusElement.textContent = 'Disconnected';
      statusElement.classList.remove('connected');
      statusElement.classList.remove('error');
      connectButton.textContent = 'Connect Wallet';
      connectButton.disabled = false;
    });

    connector.on('error', (error) => {
      debugLog(`WalletConnect error: ${error.message}`);
      statusElement.textContent = `Error: ${error.message}`;
      statusElement.classList.add('error');
    });

    // Create a new session
    if (!connector.connected) {
      debugLog('Creating new WalletConnect session');
      await connector.createSession();
    }
  } catch (error) {
    debugLog(`Error connecting to wallet: ${error.message}`);
    statusElement.textContent = `Error: ${error.message}`;
    statusElement.classList.add('error');
  }
});

// Handle page unload
window.addEventListener('beforeunload', () => {
  if (connector && connector.connected) {
    debugLog('Killing WalletConnect session');
    connector.killSession();
  }
}); 