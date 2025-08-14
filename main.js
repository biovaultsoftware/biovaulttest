// main.js 
/******************************
 * Base Setup / Global Constants
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 2; // Updated for additional stores if needed
const VAULT_STORE = 'vault';
const PROOFS_STORE = 'proofs';

// Vault & Bonus Limits
const INITIAL_BALANCE_SHE = 1200;
const EXCHANGE_RATE = 12; // 1 TVM = 12 SHE
const INITIAL_BIO_CONSTANT = 1736565605;
const LOCKOUT_DURATION_SECONDS = 3600;
const MAX_AUTH_ATTEMPTS = 3;
const CONTRACT_ADDRESS = '0xCc79b1BC9eAbc3d30a3800f4d41a4A0599e1F3c6';
const USDT_ADDRESS = '0xdac17f958d2ee523a2206206994597c13d831ec7';
const ABI = [ /* Same ABI as before, omitted for brevity */ ];
const GENESIS_BIO_CONSTANT = 1736565605;
const BIO_TOLERANCE = 720;
const BIO_STEP = 1;
const SEGMENTS_PER_LAYER = 1200;
const LAYERS = 10;
const DECIMALS_FACTOR = 1000000;
const SEGMENTS_PER_TVM = 12;
const DAILY_CAP_TVM = 30;
const MONTHLY_CAP_TVM = 300;
const YEARLY_CAP_TVM = 900;
const EXTRA_BONUS_TVM = 100;
const MAX_PROOFS_LENGTH = 200;
const SEGMENT_PROOF_TYPEHASH = ethers.keccak256(ethers.toUtf8Bytes("SegmentProof(uint256 segmentIndex,uint256 currentBioConst,bytes32 ownershipProof,bytes32 unlockIntegrityProof,bytes32 spentProof,uint256 ownershipChangeCount,bytes32 biometricZKP)"));
const CLAIM_TYPEHASH = ethers.keccak256(ethers.toUtf8Bytes("Claim(address user,bytes32 proofsHash,bytes32 deviceKeyHash,uint256 userBioConstant,uint256 nonce)"));
const HISTORY_MAX = 20;
const KEY_HASH_SALT = "Balance-Chain-v3-PRD";
const PBKDF2_ITERS = 310000;
const AES_KEY_LENGTH = 256;
const MAX_IDLE = 15 * 60 * 1000;
const HMAC_KEY = new TextEncoder().encode("BalanceChainHMACSecret");
const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;
const vaultSyncChannel = new BroadcastChannel('vault-sync');
const WALLET_CONNECT_PROJECT_ID = 'your_project_id_here'; // Replace with actual ID

// State
let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;
let provider = null;
let signer = null;
let tvmContract = null;
let usdtContract = null;
let account = null;
let chainId = null;

let vaultData = {
  bioIBAN: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  bonusConstant: 0,
  initialBalanceSHE: INITIAL_BALANCE_SHE,
  balanceSHE: 0,
  balanceUSD: 0,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  joinTimestamp: 0,
  credentialId: null,
  userWallet: "",
  deviceKeyHash: "",
  layerBalances: Array.from({length: LAYERS}, () => 0)
};

vaultData.layerBalances[0] = INITIAL_BALANCE_SHE;

// Utils Module
const Utils = {
  enc: new TextEncoder(),
  dec: new TextDecoder(),
  toB64: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  fromB64: (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer,
  rand: (len) => crypto.getRandomValues(new Uint8Array(len)),
  ctEq: (a = "", b = "") => {
    if (a.length !== b.length) return false;
    let res = 0;
    for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return res === 0;
  },
  canonical: (obj) => JSON.stringify(obj, Object.keys(obj).sort()),
  sha256: async (data) => {
    const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? Utils.enc.encode(data) : data);
    return Utils.toB64(buf);
  },
  sha256Hex: async (str) => {
    const buf = await crypto.subtle.digest("SHA-256", Utils.enc.encode(str));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  },
  hmacSha256: async (message) => {
    const key = await crypto.subtle.importKey("raw", HMAC_KEY, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, Utils.enc.encode(message));
    return Utils.toB64(signature);
  },
  sanitizeInput: (input) => DOMPurify.sanitize(input)
};

// Encryption Module
const Encryption = {
  encryptData: async (key, dataObj) => {
    const iv = Utils.rand(12);
    const plaintext = Utils.enc.encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv, ciphertext };
  },
  decryptData: async (key, iv, ciphertext) => {
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(Utils.dec.decode(plainBuf));
  },
  bufferToBase64: (buf) => Utils.toB64(buf),
  base64ToBuffer: (b64) => Utils.fromB64(b64)
};

// DB Module
const DB = {
  openVaultDB: async () => {
    return new Promise((resolve, reject) => {
      let req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (evt) => {
        let db = evt.target.result;
        if (!db.objectStoreNames.contains(VAULT_STORE)) {
          db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(PROOFS_STORE)) {
          db.createObjectStore(PROOFS_STORE, { keyPath: 'id' });
        }
      };
      req.onsuccess = (evt) => resolve(evt.target.result);
      req.onerror = (evt) => reject(evt.target.error);
    });
  },
  saveVaultDataToDB: async (iv, ciphertext, saltBase64) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      const store = tx.objectStore(VAULT_STORE);
      store.put({
        id: 'vaultData',
        iv: Encryption.bufferToBase64(iv),
        ciphertext: Encryption.bufferToBase64(ciphertext),
        salt: saltBase64,
        lockoutTimestamp: vaultData.lockoutTimestamp || null,
        authAttempts: vaultData.authAttempts || 0
      });
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  },
  loadVaultDataFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readonly');
      const store = tx.objectStore(VAULT_STORE);
      const getReq = store.get('vaultData');
      getReq.onsuccess = () => {
        if (getReq.result) {
          try {
            let iv = Encryption.base64ToBuffer(getReq.result.iv);
            let ciph = Encryption.base64ToBuffer(getReq.result.ciphertext);
            let s = getReq.result.salt ? Encryption.base64ToBuffer(getReq.result.salt) : null;
            resolve({
              iv, ciphertext: ciph, salt: s,
              lockoutTimestamp: getReq.result.lockoutTimestamp || null,
              authAttempts: getReq.result.authAttempts || 0
            });
          } catch (err) {
            console.error("Error decoding stored data =>", err);
            resolve(null);
          }
        } else {
          resolve(null);
        }
      };
      getReq.onerror = (err) => reject(err);
    });
  },
  saveProofToDB: async (proofId, proofData) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readwrite');
      const store = tx.objectStore(PROOFS_STORE);
      store.put({ id: proofId, data: proofData });
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  },
  loadProofFromDB: async (proofId) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readonly');
      const store = tx.objectStore(PROOFS_STORE);
      const getReq = store.get(proofId);
      getReq.onsuccess = () => resolve(getReq.result ? getReq.result.data : null);
      getReq.onerror = (err) => reject(err);
    });
  }
};

// Vault Module
const Vault = {
  deriveKeyFromPIN: async (pin, salt) => {
    const pinBytes = Utils.enc.encode(pin);
    const keyMaterial = await crypto.subtle.importKey('raw', pinBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey({
      name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256'
    }, keyMaterial, { name: 'AES-GCM', length: AES_KEY_LENGTH }, false, ['encrypt', 'decrypt']);
  },
  promptAndSaveVault: async (salt = null) => {
    try {
      if (!derivedKey) throw new Error("No derivedKey");
      let { iv, ciphertext } = await Encryption.encryptData(derivedKey, vaultData);
      let saltBase64;
      if (salt) {
        saltBase64 = Encryption.bufferToBase64(salt);
      } else {
        let stored = await DB.loadVaultDataFromDB();
        if (stored && stored.salt) {
          saltBase64 = Encryption.bufferToBase64(stored.salt);
        } else {
          throw new Error("Salt not found => cannot persist");
        }
      }
      await DB.saveVaultDataToDB(iv, ciphertext, saltBase64);

      const backupPayload = {
        iv: Encryption.bufferToBase64(iv),
        data: Encryption.bufferToBase64(ciphertext),
        salt: saltBase64,
        timestamp: Date.now()
      };
      localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));
      vaultSyncChannel.postMessage({ type: 'vaultUpdate', payload: backupPayload });
      console.log("Vault data stored");
    } catch (err) {
      console.error("Vault persist failed:", err);
      UI.showAlert("CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!");
    }
  },
  lockVault: () => {
    if (!vaultUnlocked) return;
    vaultUnlocked = false;
    document.getElementById('vaultUI').classList.add('hidden');
    document.getElementById('lockVaultBtn').classList.add('hidden');
    document.getElementById('lockedScreen').classList.remove('hidden');
    localStorage.setItem('vaultUnlocked', 'false');
    console.log("🔒 Vault locked");
  },
  updateVaultUI: () => {
    document.getElementById('bioIban').textContent = vaultData.bioIBAN;
    document.getElementById('bonusConstant').textContent = vaultData.bonusConstant;
    document.getElementById('utcTime').textContent = new Date(vaultData.lastUTCTimestamp * 1000).toUTCString();
    document.getElementById('walletAddress').textContent = vaultData.userWallet;
    document.getElementById('balanceTVM').textContent = (vaultData.balanceSHE / EXCHANGE_RATE).toFixed(2);
    document.getElementById('sheMetrics').textContent = vaultData.balanceSHE;
    document.getElementById('balanceUSD').textContent = ((vaultData.balanceSHE / EXCHANGE_RATE) / EXCHANGE_RATE).toFixed(2); // Adjust based on price
    const tbody = document.getElementById('txTable').querySelector('tbody');
    tbody.innerHTML = '';
    vaultData.transactions.slice(-HISTORY_MAX).forEach(tx => {
      const row = document.createElement('tr');
      row.innerHTML = `<td>${tx.bioIBAN}</td><td>${tx.bioCatch}</td><td>${tx.amount}</td><td>${tx.date}</td><td>${tx.status}</td>`;
      tbody.appendChild(row);
    });
  }
};

// Biometric Module
const Biometric = {
  performBiometricAuthenticationForCreation: async () => {
    try {
      const publicKey = {
        challenge: Utils.rand(32),
        rp: { name: "Bio-Vault" },
        user: {
          id: Utils.rand(16),
          name: "bio-user",
          displayName: "Bio User"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required"
        },
        timeout: 60000,
        attestation: "none"
      };
      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) return null;
      return credential;
    } catch (err) {
      console.error("Biometric creation error:", err);
      return null;
    }
  },
  performBiometricAssertion: async (credentialId) => {
    try {
      const publicKey = {
        challenge: Utils.rand(32),
        allowCredentials: [{ id: Encryption.base64ToBuffer(credentialId), type: 'public-key' }],
        userVerification: "required",
        timeout: 60000
      };
      const assertion = await navigator.credentials.get({ publicKey });
      return !!assertion;
    } catch (err) {
      console.error("Biometric assertion error:", err);
      return false;
    }
  }
};

// Proofs Module
const Proofs = {
  calculateProofsHash: (proofs) => {
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
      ['tuple(uint256 segmentIndex,uint256 currentBioConst,bytes32 ownershipProof,bytes32 unlockIntegrityProof,bytes32 spentProof,uint256 ownershipChangeCount,bytes32 biometricZKP)[]'],
      [proofs]
    );
    return ethers.keccak256(encoded);
  },
  generateProofChain: async (layer, segmentIndex, userBioConstant, biometricZKP) => {
    const chain = [];
    let prevOwnershipProof = ethers.ZeroHash;
    let currentBio = userBioConstant - (layer - 1) * BIO_STEP;
    for (let j = layer - 1; j >= 0; j--) {
      const ownershipProof = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'bytes32', 'uint256'], [segmentIndex, prevOwnershipProof, currentBio]));
      const unlockIntegrityProof = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'uint256'], [ownershipProof, currentBio]));
      const spentProof = ethers.ZeroHash;
      const ownershipChangeCount = 1;
      const proof = {
        segmentIndex,
        currentBioConst: currentBio,
        ownershipProof,
        unlockIntegrityProof,
        spentProof,
        ownershipChangeCount,
        biometricZKP
      };
      chain.unshift(proof);
      prevOwnershipProof = ownershipProof;
      currentBio += BIO_STEP;
    }
    return chain;
  },
  generateBioCatch: async (amount, layer) => {
    const proofs = [];
    const userBioConstant = Math.floor(Date.now() / 1000);
    const biometricZKP = await Utils.sha256Hex('biometric-' + userBioConstant + Utils.rand(16)); // Simulate ZKP
    const baseIndex = BigInt(ethers.keccak256(vaultData.deviceKeyHash));
    for (let c = 0; c < amount; c++) {
      const segmentIndex = (baseIndex + BigInt(c)).toString();
      const chain = await Proofs.generateProofChain(layer, segmentIndex, userBioConstant, biometricZKP);
      proofs.push(...chain);
    }
    const payload = {
      proofs,
      layer,
      amount,
      deviceKeyHash: vaultData.deviceKeyHash,
      userBioConstant
    };
    // Encrypt payload
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const exportedKey = await crypto.subtle.exportKey('raw', key);
    const iv = Utils.rand(12);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, Utils.enc.encode(JSON.stringify(payload)));
    const encryptedPayload = {
      key: Utils.toB64(exportedKey),
      iv: Utils.toB64(iv),
      data: Utils.toB64(encrypted)
    };
    return JSON.stringify(encryptedPayload);
  },
  decryptBioCatch: async (encryptedStr) => {
    const encryptedPayload = JSON.parse(encryptedStr);
    const key = await crypto.subtle.importKey('raw', Utils.fromB64(encryptedPayload.key), 'AES-GCM', false, ['decrypt']);
    const iv = Utils.fromB64(encryptedPayload.iv);
    const data = Utils.fromB64(encryptedPayload.data);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return JSON.parse(Utils.dec.decode(decrypted));
  },
  validateProofs: async (proofs, layer, userBioConstant) => {
    if (proofs.length % layer !== 0) return false;
    const segmentCount = proofs.length / layer;
    for (let c = 0; c < segmentCount; c++) {
      const chain = proofs.slice(c * layer, (c + 1) * layer);
      let prevBio = chain[chain.length - 1].currentBioConst;
      let prevOwnershipProof = ethers.ZeroHash;
      for (let i = chain.length - 1; i >= 0; i--) {
        const currentProof = chain[i];
        if (currentProof.currentBioConst <= prevBio) return false;
        if (currentProof.currentBioConst > Math.floor(Date.now() / 1000) + BIO_TOLERANCE) return false;
        if (currentProof.currentBioConst < userBioConstant - i * BIO_STEP) return false;
        const calculatedOwnershipProof = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'bytes32', 'uint256'], [currentProof.segmentIndex, prevOwnershipProof, currentProof.currentBioConst]));
        if (currentProof.ownershipProof !== calculatedOwnershipProof) return false;
        const calculatedUnlockIntegrityProof = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'uint256'], [currentProof.ownershipProof, currentProof.currentBioConst]));
        if (currentProof.unlockIntegrityProof !== calculatedUnlockIntegrityProof) return false;
        if (currentProof.spentProof !== ethers.ZeroHash) return false;
        if (currentProof.ownershipChangeCount !== 1) return false;
        if (currentProof.biometricZKP === ethers.ZeroHash) return false;
        prevBio = currentProof.currentBioConst;
        prevOwnershipProof = currentProof.ownershipProof;
      }
    }
    return true;
  },
  signClaim: async (proofs, deviceKeyHash, userBioConstant, nonce) => {
    const proofsHash = Proofs.calculateProofsHash(proofs);
    const message = {
      user: account,
      proofsHash,
      deviceKeyHash,
      userBioConstant,
      nonce
    };
    const domain = {
      name: 'TVM',
      version: '1',
      chainId,
      verifyingContract: CONTRACT_ADDRESS
    };
    const types = {
      Claim: [
        { name: 'user', type: 'address' },
        { name: 'proofsHash', type: 'bytes32' },
        { name: 'deviceKeyHash', type: 'bytes32' },
        { name: 'userBioConstant', type: 'uint256' },
        { name: 'nonce', type: 'uint256' }
      ]
    };
    return await signer.signTypedData(domain, types, message);
  }
};

// Wallet Module
const Wallet = {
  connectMetaMask: async () => {
    if (!window.ethereum) {
      UI.showAlert('MetaMask is not installed!');
      return;
    }
    provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send("eth_requestAccounts", []);
    signer = await provider.getSigner();
    account = await signer.getAddress();
    chainId = Number(await provider.getNetwork().then(net => net.chainId));
    Wallet.initContracts();
    UI.updateConnectedAccount();
    await Wallet.updateBalances();
    Wallet.subscribeToEvents();
  },
  connectWalletConnect: async () => {
    try {
      const wcProvider = await EthereumProvider.init({
        projectId: WALLET_CONNECT_PROJECT_ID,
        metadata: {
          name: "Bio-Vault",
          description: "P2P Bio-Vault App",
          url: window.location.origin,
          icons: ["https://avatars.githubusercontent.com/u/37784886"]
        },
        showQrModal: true,
        chains: [1] // Assume mainnet, adjust
      });
      await wcProvider.enable();
      provider = new ethers.BrowserProvider(wcProvider);
      signer = await provider.getSigner();
      account = await signer.getAddress();
      chainId = Number(await provider.getNetwork().then(net => net.chainId));
      Wallet.initContracts();
      UI.updateConnectedAccount();
      await Wallet.updateBalances();
      Wallet.subscribeToEvents();
      wcProvider.on("chainChanged", Wallet.handleChainChanged);
      wcProvider.on("accountsChanged", Wallet.handleAccountsChanged);
      wcProvider.on("disconnect", Wallet.handleDisconnect);
    } catch (err) {
      console.error("WalletConnect error:", err);
      UI.showAlert('WalletConnect connection failed: ' + err.message);
    }
  },
  initContracts: () => {
    tvmContract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);
    usdtContract = new ethers.Contract(USDT_ADDRESS, [
      'function balanceOf(address) view returns (uint256)',
      'function approve(address, uint256) returns (bool)',
      'function allowance(address, address) view returns (uint256)'
    ], signer);
  },
  updateBalances: async () => {
    if (!account) return;
    try {
      const tvmBal = await tvmContract.balanceOf(account);
      document.getElementById('tvmBalance').textContent = ethers.formatUnits(tvmBal, 6);
      const usdtBal = await usdtContract.balanceOf(account);
      document.getElementById('usdtBalance').textContent = ethers.formatUnits(usdtBal, 6);
      const price = await tvmContract.tvmPrice();
      document.getElementById('tvmPrice').textContent = price.toString();
      document.getElementById('balanceTVM').textContent = ethers.formatUnits(tvmBal, 6);
      document.getElementById('balanceUSD').textContent = (Number(ethers.formatUnits(tvmBal, 6)) * Number(price) / DECIMALS_FACTOR).toFixed(2);
    } catch (err) {
      console.error("Balance update error:", err);
    }
  },
  subscribeToEvents: () => {
    tvmContract.on("TVMClaimed", (user, amount, segmentCount, chainHash) => {
      if (user.toLowerCase() === account.toLowerCase()) {
        UI.showAlert(`TVM Claimed: ${amount} TVM`);
        Wallet.updateBalances();
        Notifications.sendPush('TVM Claimed', `You claimed ${amount} TVM`);
      }
    });
    tvmContract.on("SwapExecuted", (user, amount, direction, postRatio) => {
      if (user.toLowerCase() === account.toLowerCase()) {
        UI.showAlert(`Swap Executed: ${amount} ${direction}`);
        Wallet.updateBalances();
        Notifications.sendPush('Swap Executed', `${direction} swap of ${amount} completed`);
      }
    });
    // Add other events
  },
  handleChainChanged: (newChainId) => {
    chainId = Number(newChainId);
    Wallet.initContracts();
    Wallet.updateBalances();
  },
  handleAccountsChanged: (accounts) => {
    account = accounts[0];
    UI.updateConnectedAccount();
    Wallet.updateBalances();
  },
  handleDisconnect: () => {
    provider = null;
    signer = null;
    account = null;
    UI.updateConnectedAccount();
  }
};

// P2P Module
const P2P = {
  handleCatchOut: async () => {
    const amount = Utils.sanitizeInput(prompt("Enter amount of SHE to transfer:"));
    const layer = Utils.sanitizeInput(prompt("Enter layer (1-10):"));
    if (!amount || !layer || isNaN(amount) || isNaN(layer) || layer < 1 || layer > 10) return;
    UI.showLoading('catchOut');
    try {
      const payload = await Proofs.generateBioCatch(parseInt(amount), parseInt(layer));
      document.getElementById('bioCatchText').textContent = payload;
      document.getElementById('bioCatchModal').classList.remove('hidden');
      QRCode.toCanvas(document.getElementById('qrCode'), payload, err => err && console.error(err));
      // NFC share if supported
      if ('nfc' in navigator) {
        try {
          const nfc = new NDEFWriter();
          await nfc.write({ records: [{ recordType: "text", data: payload }] });
          UI.showAlert("Shared via NFC");
        } catch (err) {
          console.error("NFC write error:", err);
        }
      }
      vaultData.balanceSHE -= parseInt(amount);
      vaultData.layerBalances[parseInt(layer) - 1] -= parseInt(amount);
      await Vault.promptAndSaveVault();
    } catch (err) {
      UI.showAlert("Catch Out failed: " + err.message);
    } finally {
      UI.hideLoading('catchOut');
    }
  },
  handleCatchIn: async () => {
    const payloadStr = Utils.sanitizeInput(prompt("Paste Bio-Catch payload:"));
    if (!payloadStr) return;
    UI.showLoading('catchIn');
    try {
      const payload = await Proofs.decryptBioCatch(payloadStr);
      const valid = await Proofs.validateProofs(payload.proofs, payload.layer, payload.userBioConstant);
      if (valid) {
        vaultData.balanceSHE += payload.amount;
        vaultData.layerBalances[payload.layer - 1] += payload.amount;
        await Vault.promptAndSaveVault();
        UI.showAlert("Catch In successful.");
      } else {
        UI.showAlert("Invalid payload.");
      }
    } catch (err) {
      UI.showAlert("Invalid payload: " + err.message);
    } finally {
      UI.hideLoading('catchIn');
    }
  },
  handleNfcRead: async () => {
    if ('nfc' in navigator) {
      try {
        const nfc = new NDEFReader();
        await nfc.scan();
        nfc.onreading = (event) => {
          const message = event.message;
          for (const record of message.records) {
            if (record.recordType === "text") {
              P2P.handleCatchInPayload(record.data);
            }
          }
        };
      } catch (err) {
        console.error("NFC read error:", err);
      }
    }
  },
  handleCatchInPayload: async (payloadStr) => {
    // Similar to handleCatchIn but from NFC
    // ...
  }
};

// Notifications Module
const Notifications = {
  requestPermission: async () => {
    if (Notification.permission !== 'granted') {
      await Notification.requestPermission();
    }
  },
  sendPush: (title, body) => {
    if (Notification.permission === 'granted') {
      navigator.serviceWorker.ready.then(reg => {
        reg.showNotification(title, { body });
      });
    }
  }
};

// UI Module
const UI = {
  showAlert: (msg) => alert(msg),
  showLoading: (id) => {
    const loadingEl = document.getElementById(`${id}-loading`);
    if (loadingEl) loadingEl.style.display = 'block';
  },
  hideLoading: (id) => {
    const loadingEl = document.getElementById(`${id}-loading`);
    if (loadingEl) loadingEl.style.display = 'none';
  },
  updateConnectedAccount: () => {
    document.getElementById('connectedAccount').textContent = account || 'Not connected';
  }
};

// Contract Interaction Module
const ContractInteractions = {
  claimTVM: async () => {
    UI.showLoading('claim');
    try {
      const proofsStr = Utils.sanitizeInput(document.getElementById('claim-proofs').value);
      const deviceKeyHash = Utils.sanitizeInput(document.getElementById('claim-device-key-hash').value);
      const userBioConstant = Utils.sanitizeInput(document.getElementById('claim-user-bio-constant').value);
      const nonce = Utils.sanitizeInput(document.getElementById('claim-nonce').value);
      const signature = Utils.sanitizeInput(document.getElementById('claim-signature').value);
      const proofs = JSON.parse(proofsStr);
      const gasEstimate = await tvmContract.claimTVM.estimateGas(proofs, signature, deviceKeyHash, userBioConstant, nonce);
      const tx = await tvmContract.claimTVM(proofs, signature, deviceKeyHash, userBioConstant, nonce, { gasLimit: gasEstimate * 120n / 100n });
      await tx.wait();
      UI.showAlert('Claim successful.');
      Wallet.updateBalances();
    } catch (err) {
      console.error(err);
      UI.showAlert('Error claiming TVM: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('claim');
    }
  },
  generateClaimSignature: async () => {
    try {
      const proofsStr = Utils.sanitizeInput(document.getElementById('claim-proofs').value);
      const deviceKeyHash = Utils.sanitizeInput(document.getElementById('claim-device-key-hash').value);
      const userBioConstant = Number(Utils.sanitizeInput(document.getElementById('claim-user-bio-constant').value));
      const nonce = Number(Utils.sanitizeInput(document.getElementById('claim-nonce').value));
      const proofs = JSON.parse(proofsStr);
      const signature = await Proofs.signClaim(proofs, deviceKeyHash, userBioConstant, nonce);
      document.getElementById('claim-signature').value = signature;
    } catch (err) {
      UI.showAlert('Signature generation failed: ' + err.message);
    }
  },
  // Similar for exchange, swap, transfer with gas estimate, error parse
  exchangeTVMForSegments: async () => {
    // Implement similar to claim
  },
  // ...
};

// Init Function
async function init() {
  Notifications.requestPermission();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').then(reg => {
      console.log('SW registered');
    }).catch(err => console.error('SW registration failed', err));
  }
  P2P.handleNfcRead(); // Start NFC listening if supported

  const stored = await DB.loadVaultDataFromDB();
  if (stored) {
    vaultData.authAttempts = stored.authAttempts;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
  } else {
    const credential = await Biometric.performBiometricAuthenticationForCreation();
    if (credential) {
      vaultData.credentialId = Encryption.bufferToBase64(credential.rawId);
      vaultData.bioIBAN = await Utils.sha256Hex(Math.random().toString());
      vaultData.joinTimestamp = Date.now();
      vaultData.deviceKeyHash = await Utils.sha256Hex(KEY_HASH_SALT + Utils.toB64(Utils.rand(32)));
      vaultData.balanceSHE = INITIAL_BALANCE_SHE;
      const salt = Utils.rand(16);
      const pin = Utils.sanitizeInput(prompt("Set passphrase:"));
      derivedKey = await Vault.deriveKeyFromPIN(pin, salt);
      await Vault.promptAndSaveVault(salt);
    }
  }

  // Event listeners
  document.getElementById('connectMetaMaskBtn').addEventListener('click', Wallet.connectMetaMask);
  document.getElementById('connectWalletConnectBtn').addEventListener('click', Wallet.connectWalletConnect);
  document.getElementById('enterVaultBtn').addEventListener('click', async () => {
    if (vaultData.lockoutTimestamp && Date.now() < vaultData.lockoutTimestamp + LOCKOUT_DURATION_SECONDS * 1000) {
      UI.showAlert("Vault locked out.");
      return;
    }
    const pin = Utils.sanitizeInput(prompt("Enter passphrase:"));
    const stored = await DB.loadVaultDataFromDB();
    if (stored) {
      derivedKey = await Vault.deriveKeyFromPIN(pin, stored.salt);
      try {
        vaultData = await Encryption.decryptData(derivedKey, stored.iv, stored.ciphertext);
        if (await Biometric.performBiometricAssertion(vaultData.credentialId)) {
          vaultUnlocked = true;
          document.getElementById('lockedScreen').classList.add('hidden');
          document.getElementById('vaultUI').classList.remove('hidden');
          Vault.updateVaultUI();
        } else {
          vaultData.authAttempts++;
          if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
            vaultData.lockoutTimestamp = Date.now();
          }
          await Vault.promptAndSaveVault();
          UI.showAlert("Biometric failed.");
        }
      } catch (err) {
        UI.showAlert("Invalid passphrase.");
      }
    }
  });

  document.getElementById('lockVaultBtn').addEventListener('click', Vault.lockVault);
  document.getElementById('catchOutBtn').addEventListener('click', P2P.handleCatchOut);
  document.getElementById('catchInBtn').addEventListener('click', P2P.handleCatchIn);
  document.getElementById('generate-claim-signature-btn').addEventListener('click', ContractInteractions.generateClaimSignature);
  document.getElementById('claim-tvm-btn').addEventListener('click', ContractInteractions.claimTVM);
  // Add other listeners similarly

  setTimeout(Vault.lockVault, MAX_IDLE);
  setInterval(() => {
    document.getElementById('utcTime').textContent = new Date().toUTCString();
  }, 1000);
}

init();
