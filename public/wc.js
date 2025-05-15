// Initialize WalletConnect
let signClient;
let web3Modal;

// DOM elements
const connectButton = document.getElementById('connect-button');
const statusElement = document.getElementById('status');
const errorElement = document.getElementById('error');

// Initialize Telegram WebApp
const tg = window.Telegram.WebApp;
tg.expand();

async function initWalletConnect() {
  try {
    debugLog('Initializing WalletConnect v2...');
    
    // Initialize SignClient
    signClient = await SignClient.init({
      projectId: '3bf85969ef80e641764cbd59fd1a37da', 
      metadata: {
        name: 'TRON Automated Transaction Bot',
        description: 'Bot for automating TRON transactions',
        url: window.location.host,
        icons: ['https://your-icon-url.png']
      }
    });

    debugLog('SignClient initialized successfully');

    // Initialize Web3Modal
    web3Modal = new Web3Modal({
      projectId: 'YOUR_PROJECT_ID', // Same project ID as above
      chains: ['tron'],
      themeMode: 'dark',
      themeVariables: {
        '--w3m-z-index': '9999'
      }
    });

    debugLog('Web3Modal initialized successfully');

    // Set up event listeners
    signClient.on('session_event', ({ event }) => {
      debugLog('Session event:', event);
    });

    signClient.on('session_update', ({ topic, params }) => {
      debugLog('Session updated:', { topic, params });
    });

    signClient.on('session_delete', () => {
      debugLog('Session deleted');
      updateUI('disconnected');
    });

    return true;
  } catch (error) {
    debugLog('Error initializing WalletConnect:', error);
    return false;
  }
}

async function connectWallet() {
  try {
    debugLog('Attempting to connect wallet...');
    
    if (!signClient) {
      const initialized = await initWalletConnect();
      if (!initialized) {
        throw new Error('Failed to initialize WalletConnect');
      }
    }

    // Open Web3Modal
    const { uri, approval } = await signClient.connect({
      requiredNamespaces: {
        tron: {
          methods: ['tron_signTransaction', 'tron_signMessage'],
          chains: ['tron:mainnet'],
          events: ['chainChanged', 'accountsChanged']
        }
      }
    });

    if (uri) {
      web3Modal.openModal({ uri });
    }

    const session = await approval();
    debugLog('Wallet connected successfully:', session);

    // Update UI and send data back to Telegram bot
    updateUI('connected');
    const accounts = session.namespaces.tron.accounts;
    const address = accounts[0].split(':')[2];
    
    window.Telegram.WebApp.sendData(JSON.stringify({
      type: 'wallet_connected',
      address: address
    }));

    return session;
  } catch (error) {
    debugLog('Error connecting wallet:', error);
    updateUI('error', error.message);
    throw error;
  }
}

function updateUI(status, error = null) {
  switch (status) {
    case 'connected':
      statusElement.textContent = 'Connected';
      statusElement.className = 'status connected';
      errorElement.style.display = 'none';
      break;
    case 'disconnected':
      statusElement.textContent = 'Disconnected';
      statusElement.className = 'status disconnected';
      errorElement.style.display = 'none';
      break;
    case 'error':
      statusElement.textContent = 'Error';
      statusElement.className = 'status error';
      errorElement.textContent = error;
      errorElement.style.display = 'block';
      break;
  }
}

function debugLog(...args) {
  const debugElement = document.getElementById('debug');
  const timestamp = new Date().toISOString();
  const message = args.map(arg => 
    typeof arg === 'object' ? JSON.stringify(arg, null, 2) : arg
  ).join(' ');
  
  debugElement.innerHTML += `<div>[${timestamp}] ${message}</div>`;
  console.log('[WalletConnect Debug]', ...args);
}

// Connect button click handler
connectButton.addEventListener('click', async () => {
  try {
    await connectWallet();
  } catch (error) {
    debugLog('Connection error:', error);
    updateUI('error', error.message);
  }
});

// Initialize on page load
window.addEventListener('load', async () => {
  debugLog('Page loaded, initializing WalletConnect...');
  await initWalletConnect();
});

// Clean up on page unload
window.addEventListener('beforeunload', async () => {
  if (signClient) {
    debugLog('Cleaning up WalletConnect session...');
    await signClient.disconnect();
  }
}); 