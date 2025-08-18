/******************************
 * main.js - ES2018 compatible (no optional chaining / numeric separators)
 ******************************/

// ---------- Base Setup / Global Constants ----------
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 3;
const VAULT_STORE = 'vault';
const PROOFS_STORE = 'proofs';
const SEGMENTS_STORE = 'segments';
const INITIAL_BALANCE_SHE = 1200;
const EXCHANGE_RATE = 12; // 1 TVM = 12 SHE
const INITIAL_BIO_CONSTANT = 1736565605;
const LOCKOUT_DURATION_SECONDS = 3600;
const MAX_AUTH_ATTEMPTS = 3;

// IMPORTANT: lowercase to bypass strict checksum validation in ethers v6
const CONTRACT_ADDRESS = '0xcc79b1bc9eabc3d30a3800f4d41a4a0599e1f3c6';
const USDT_ADDRESS     = '0xdac17f958d2ee523a2206206994597c13d831ec7';

const ABI = [
  { "inputs":[{ "components":[
      {"internalType":"uint256","name":"segmentIndex","type":"uint256"},
      {"internalType":"uint256","name":"currentBioConst","type":"uint256"},
      {"internalType":"bytes32","name":"ownershipProof","type":"bytes32"},
      {"internalType":"bytes32","name":"unlockIntegrityProof","type":"bytes32"},
      {"internalType":"bytes32","name":"spentProof","type":"bytes32"},
      {"internalType":"uint256","name":"ownershipChangeCount","type":"uint256"},
      {"internalType":"bytes32","name":"biometricZKP","type":"bytes32"}],
      "internalType":"struct TVM.SegmentProof[]","name":"proofs","type":"tuple[]"},
      {"internalType":"bytes","name":"signature","type":"bytes"},
      {"internalType":"bytes32","name":"deviceKeyHash","type":"bytes32"},
      {"internalType":"uint256","name":"userBioConstant","type":"uint256"},
      {"internalType":"uint256","name":"nonce","type":"uint256"}],
    "name":"claimTVM","outputs":[],"stateMutability":"nonpayable","type":"function"
  },
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"exchangeTVMForSegments","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"swapTVMForUSDT","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"swapUSDTForTVM","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
];

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
const SEGMENT_HISTORY_MAX = 10;
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
const WALLET_CONNECT_PROJECT_ID = 'c4f79cc9f2f73b737d4d06795a48b4a5';

// ---------- State ----------
let vaultUnlocked = false;
let derivedKey = null;
let provider = null;
let signer = null;
let tvmContract = null;
let usdtContract = null;
let account = null;
let chainId = null;

let autoProofs = null;
let autoDeviceKeyHash = '';
let autoUserBioConstant = 0;
let autoNonce = 0;
let autoSignature = '';
let transactionLock = false;

const SESSION_URL_KEY = 'last_session_url';
const VAULT_UNLOCKED_KEY = 'vaultUnlocked';
const VAULT_LOCK_KEY = 'vaultLock';

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
  layerBalances: Array.from({length: LAYERS}, function(){ return 0; })
};
vaultData.layerBalances[0] = INITIAL_BALANCE_SHE;

// ---------- Utils ----------
const Utils = {
  enc: new TextEncoder(),
  dec: new TextDecoder(),
  toB64: (buf) => btoa(String.fromCharCode.apply(null, new Uint8Array(buf))),
  fromB64: (b64) => Uint8Array.from(atob(b64), function(c){ return c.charCodeAt(0); }).buffer,
  rand:  (len) => crypto.getRandomValues(new Uint8Array(len)),
  ctEq:  (a, b) => {
    a = a || ""; b = b || "";
    if (a.length !== b.length) return false;
    var res = 0; for (var i=0;i<a.length;i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return res===0;
  },
  canonical: (obj) => JSON.stringify(obj, Object.keys(obj).sort()),
  sha256: async (data) => {
    const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? Utils.enc.encode(data) : data);
    return Utils.toB64(buf);
  },
  sha256Hex: async (str) => {
    const buf = await crypto.subtle.digest("SHA-256", Utils.enc.encode(str));
    return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
  },
  hmacSha256: async (message) => {
    const key = await crypto.subtle.importKey("raw", HMAC_KEY, { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, Utils.enc.encode(message));
    return Utils.toB64(signature);
  },
  sanitizeInput: (input) => (typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(input) : String(input)),
  to0x: (hex) => hex && hex.slice(0,2)==='0x' ? hex : ('0x' + hex)
};

// ---------- Encryption ----------
const Encryption = {
  encryptData: async (key, dataObj) => {
    const iv = Utils.rand(12);
    const plaintext = Utils.enc.encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt({ name:'AES-GCM', iv: iv }, key, plaintext);
    return { iv: iv, ciphertext: ciphertext };
  },
  decryptData: async (key, iv, ciphertext) => {
    const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: iv }, key, ciphertext);
    return JSON.parse(Utils.dec.decode(plainBuf));
  },
  bufferToBase64: (buf) => {
    const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer || buf);
    return btoa(String.fromCharCode.apply(null, u8));
  },
  base64ToBuffer: (b64) => {
    if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) throw new Error('Invalid Base64 string');
    const bin = atob(b64); const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
    return out.buffer;
  }
};

// ---------- DB (IndexedDB) ----------
const DB = {
  openVaultDB: () => new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE))   db.createObjectStore(VAULT_STORE, { keyPath:'id' });
      if (!db.objectStoreNames.contains(PROOFS_STORE))  db.createObjectStore(PROOFS_STORE,{ keyPath:'id' });
      if (!db.objectStoreNames.contains(SEGMENTS_STORE))db.createObjectStore(SEGMENTS_STORE,{ keyPath:'segmentIndex' });
      if (!db.objectStoreNames.contains('replays'))     db.createObjectStore('replays',{ keyPath:'nonce' });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  }),

  saveVaultDataToDB: async (iv, ciphertext, saltB64) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).put({
        id:'vaultData',
        iv: Encryption.bufferToBase64(iv),
        ciphertext: Encryption.bufferToBase64(ciphertext),
        salt: saltB64,
        lockoutTimestamp: vaultData.lockoutTimestamp || null,
        authAttempts: vaultData.authAttempts || 0
      });
      tx.oncomplete = resolve; tx.onerror = (e)=>reject(e.target.error);
    });
  },

  loadVaultDataFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readonly');
      const get = tx.objectStore(VAULT_STORE).get('vaultData');
      get.onsuccess = () => {
        const r = get.result;
        if (!r) return resolve(null);
        try {
          resolve({
            iv: Encryption.base64ToBuffer(r.iv),
            ciphertext: Encryption.base64ToBuffer(r.ciphertext),
            salt: r.salt ? Encryption.base64ToBuffer(r.salt) : null,
            lockoutTimestamp: r.lockoutTimestamp || null,
            authAttempts: r.authAttempts || 0
          });
        } catch (e) { console.error('[BioVault] Corrupted vault record', e); resolve(null); }
      };
      get.onerror = (e)=>reject(e.target.error);
    });
  },

  clearVaultDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).clear();
      tx.oncomplete = resolve; tx.onerror = (e)=>reject(e.target.error);
    });
  },

  saveProofsToDB: async (bundle) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readwrite');
      tx.objectStore(PROOFS_STORE).put({ id:'autoProofs', data: bundle });
      tx.oncomplete = resolve; tx.onerror = (e)=>reject(e.target.error);
    });
  },
  loadProofsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readonly');
      const get = tx.objectStore(PROOFS_STORE).get('autoProofs');
      get.onsuccess = ()=>resolve(get.result ? get.result.data : null);
      get.onerror = (e)=>reject(e.target.error);
    });
  },

  saveSegmentToDB: async (segment) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      tx.objectStore(SEGMENTS_STORE).put(segment);
      tx.oncomplete = resolve; tx.onerror = (e)=>reject(e.target.error);
    });
  },
  loadSegmentsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readonly');
      const getAll = tx.objectStore(SEGMENTS_STORE).getAll();
      getAll.onsuccess = ()=>resolve(getAll.result || []);
      getAll.onerror = (e)=>reject(e.target.error);
    });
  },
  deleteSegmentFromDB: async (segmentIndex) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      tx.objectStore(SEGMENTS_STORE).delete(segmentIndex);
      tx.oncomplete = resolve; tx.onerror = (e)=>reject(e.target.error);
    });
  },
  getSegment: async (segmentIndex) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readonly');
      const req = tx.objectStore(SEGMENTS_STORE).get(segmentIndex);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = (e) => reject(e.target.error);
    });
  },
  hasReplayNonce: async (nonce) => {
    const db = await DB.openVaultDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['replays'],'readonly');
      const g = tx.objectStore('replays').get(nonce);
      g.onsuccess = () => res(!!g.result);
      g.onerror = (e) => rej(e.target.error);
    });
  },
  putReplayNonce: async (nonce) => {
    const db = await DB.openVaultDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['replays'],'readwrite');
      tx.objectStore('replays').put({ nonce: nonce, ts: Date.now() });
      tx.oncomplete = res; tx.onerror = (e)=>rej(e.target.error);
    });
  }
};

// ---------- Biometric ----------
const Biometric = {
  _bioBusy: false,

  performBiometricAuthenticationForCreation: async () => {
    if (Biometric._bioBusy) return null;
    Biometric._bioBusy = true;
    try {
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: Utils.rand(32),
          rp: { name: "BioVault", id: location.hostname },
          user: { id: Utils.rand(16), name: "user@biovault", displayName: "User" },
          pubKeyCredParams: [
            { type: "public-key", alg: -7   }, // ES256
            { type: "public-key", alg: -257 }  // RS256
          ],
          authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
          timeout: 60000
        }
      });
      return credential;
    } catch (err) {
      console.error('[BioVault] Biometric creation failed', err);
      return null;
    } finally {
      Biometric._bioBusy = false;
    }
  },

  performBiometricAssertion: async (credentialId) => {
    if (Biometric._bioBusy) return false;
    Biometric._bioBusy = true;
    try {
      const idBuf = Encryption.base64ToBuffer(credentialId);
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: Utils.rand(32),
          allowCredentials: [{ type: "public-key", id: new Uint8Array(idBuf) }],
          userVerification: "required",
          timeout: 60000
        }
      });
      return !!assertion;
    } catch (err) {
      console.error('[BioVault] Biometric assertion failed', err);
      return false;
    } finally {
      Biometric._bioBusy = false;
    }
  },

  generateBiometricZKP: async () => {
    if (!vaultData || !vaultData.credentialId) return null;
    if (Biometric._bioBusy) return null;
    Biometric._bioBusy = true;
    try {
      const challenge = Utils.rand(32);
      const idBuf = Encryption.base64ToBuffer(vaultData.credentialId);
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          allowCredentials: [{ type: "public-key", id: new Uint8Array(idBuf) }],
          userVerification: "required",
          timeout: 60000
        }
      });
      if (!assertion) return null;
      const hex = await Utils.sha256Hex(String.fromCharCode.apply(null, new Uint8Array(assertion.signature)));
      return Utils.to0x(hex);
    } catch (err) {
      console.error('[BioVault] Biometric ZKP failed', err);
      return null;
    } finally {
      Biometric._bioBusy = false;
    }
  }
};

async function reEnrollBiometricIfNeeded() {
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: Utils.rand(32),
        rp: { name: "BioVault", id: location.hostname },
        user: { id: Utils.rand(16), name: "user@biovault", displayName: "User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000
      }
    });
    if (!cred) return false;
    vaultData.credentialId = Encryption.bufferToBase64(cred.rawId);
    await persistVaultData(); // save with current derivedKey
    return true;
  } catch (e) {
    console.warn('[BioVault] Re-enroll failed:', e);
    return false;
  }
}

// ---------- Vault helpers for UI show/hide ----------
function revealVaultUI() {
  var wp = document.querySelector('#biovault .whitepaper');
  if (wp) wp.classList.add('hidden');
  var locked = document.getElementById('lockedScreen');
  var vault  = document.getElementById('vaultUI');
  if (locked) locked.classList.add('hidden');
  if (vault) { vault.classList.remove('hidden'); vault.style.display = 'block'; }
  try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'true'); } catch(e){}
}
function restoreLockedUI() {
  var wp = document.querySelector('#biovault .whitepaper');
  if (wp) wp.classList.remove('hidden');
  var locked = document.getElementById('lockedScreen');
  var vault  = document.getElementById('vaultUI');
  if (vault) { vault.classList.add('hidden'); vault.style.display = 'none'; }
  if (locked) locked.classList.remove('hidden');
  try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'false'); } catch(e){}
}

// ---------- Vault ----------
const Vault = {
  deriveKeyFromPIN: async (pin, salt) => {
    const baseKey = await crypto.subtle.importKey("raw", Utils.enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name:"PBKDF2", salt: salt, iterations: PBKDF2_ITERS, hash:"SHA-256" },
      baseKey, { name:"AES-GCM", length:AES_KEY_LENGTH }, false, ["encrypt","decrypt"]
    );
  },
  promptAndSaveVault: async (salt) => persistVaultData(salt || null),
  updateVaultUI: () => {
    var e;
    e = document.getElementById('bioIBAN');       if (e) e.textContent = vaultData.bioIBAN;
    e = document.getElementById('balanceSHE');    if (e) e.textContent = vaultData.balanceSHE;
    var tvmFloat = vaultData.balanceSHE / EXCHANGE_RATE;
    e = document.getElementById('balanceTVM');    if (e) e.textContent = tvmFloat.toFixed(4);
    e = document.getElementById('balanceUSD');    if (e) e.textContent = tvmFloat.toFixed(2);
    e = document.getElementById('bonusConstant'); if (e) e.textContent = vaultData.bonusConstant;
    e = document.getElementById('connectedAccount'); if (e) e.textContent = vaultData.userWallet || 'Not connected';

    const historyBody = document.getElementById('transactionHistory');
    if (historyBody) {
      historyBody.innerHTML = '';
      vaultData.transactions.slice(0, HISTORY_MAX).forEach(function(tx){
        const row = document.createElement('tr');
        const cols = [tx.bioIBAN, tx.bioCatch, String(tx.amount), new Date(tx.timestamp).toUTCString(), tx.status];
        cols.forEach(function(v){
          const td = document.createElement('td'); td.textContent = String(v); row.appendChild(td);
        });
        historyBody.appendChild(row);
      });
    }
  },
  lockVault: async () => {
    vaultUnlocked = false;
    try { await Vault.promptAndSaveVault(); } catch (e) { console.warn("[BioVault] save-on-lock failed", e); }
    derivedKey = null;
    restoreLockedUI();
  },
  updateBalanceFromSegments: async () => {
    const segs = await DB.loadSegmentsFromDB();
    vaultData.balanceSHE = segs.filter(function(s){ return s.currentOwner===vaultData.bioIBAN; }).length;
    Vault.updateVaultUI();
  }
};

// ---------- Wallet ----------
const Wallet = {
  connectMetaMask: async () => {
    if (!window.ethereum) { alert('Install MetaMask.'); return; }
    provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send('eth_requestAccounts', []);
    signer = await provider.getSigner();
    account = await signer.getAddress();
    chainId = await provider.getNetwork().then(function(net){ return net.chainId; });
    vaultData.userWallet = account;
    UI.updateConnectedAccount();
    Wallet.initContracts();
    await Wallet.updateBalances();
    enableDashboardButtons();
    const btn = document.getElementById('connect-wallet');
    if (btn) { btn.textContent = 'Wallet Connected'; btn.disabled = true; }
  },

  connectWalletConnect: async () => {
    let WCProvider;
    try {
      WCProvider = await import('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.14.0/dist/esm/index.js');
    } catch (e) {
      UI.showAlert('Could not load WalletConnect (offline or blocked). Try MetaMask.');
      return;
    }
    const wcProvider = await WCProvider.EthereumProvider.init({ projectId: WALLET_CONNECT_PROJECT_ID, chains:[1], showQrModal:true });
    await wcProvider.enable();
    provider = new ethers.BrowserProvider(wcProvider);
    signer = await provider.getSigner();
    account = await signer.getAddress();
    chainId = await provider.getNetwork().then(function(net){ return net.chainId; });
    vaultData.userWallet = account;
    UI.updateConnectedAccount();
    Wallet.initContracts();
    await Wallet.updateBalances();
    enableDashboardButtons();
    const btn = document.getElementById('connect-wallet');
    if (btn) { btn.textContent = 'Wallet Connected'; btn.disabled = true; }
  },

  initContracts: () => {
    try {
      tvmContract  = new ethers.Contract(CONTRACT_ADDRESS.toLowerCase(), ABI, signer);
      usdtContract = new ethers.Contract(USDT_ADDRESS.toLowerCase(), [
        {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
      ], signer);
      console.log('[BioVault] Contracts initialized');
    } catch (e) {
      console.error('[BioVault] initContracts failed', e);
    }
  },

  updateBalances: async () => {
    if (!tvmContract || !account) return;
    try {
      const tvmBal = await tvmContract.balanceOf(account);
      var e1 = document.getElementById('user-balance');
      if (e1) e1.textContent = ethers.formatUnits(tvmBal, 18) + ' TVM';
      const usdtBal = await usdtContract.balanceOf(account);
      var e2 = document.getElementById('usdt-balance');
      if (e2) e2.textContent = ethers.formatUnits(usdtBal, 6) + ' USDT';
      var e3 = document.getElementById('tvm-price');      if (e3) e3.textContent  = '1.00 USDT';
      var e4 = document.getElementById('pool-ratio');     if (e4) e4.textContent = '51% HI / 49% AI';
      var e5 = document.getElementById('avg-reserves');   if (e5) e5.textContent = '100M TVM';
    } catch (e) {
      console.warn('Balance refresh failed:', e);
      var ub = document.getElementById('user-balance');
      var uu = document.getElementById('usdt-balance');
      if (ub) ub.textContent = '— TVM';
      if (uu) uu.textContent = '— USDT';
    }
  },

  ensureAllowance: async (token, owner, spender, amount) => {
    if (!token || !token.allowance) return;
    const a = await token.allowance(owner, spender);
    if (a < amount) {
      const tx = await token.approve(spender, amount);
      await tx.wait();
    }
  },

  getOnchainBalances: async () => {
    if (!tvmContract || !usdtContract || !account) throw new Error('Connect wallet first.');
    const tvm  = await tvmContract.balanceOf(account);
    const usdt = await usdtContract.balanceOf(account);
    return { tvm: tvm, usdt: usdt };
  }
};

// ---------- Proofs ----------
const Proofs = {
  generateAutoProof: async () => {
    if (!vaultUnlocked) throw new Error('Vault locked.');
    const segmentIndex = Math.floor(Math.random() * 1200) + 1;
    const currentBioConst = vaultData.initialBioConstant + segmentIndex;
    const ownershipProof = Utils.to0x(await Utils.sha256Hex('ownership' + segmentIndex));
    const unlockIntegrityProof = Utils.to0x(await Utils.sha256Hex('integrity' + currentBioConst));
    const spentProof = Utils.to0x(await Utils.sha256Hex('spent' + segmentIndex));
    const ownershipChangeCount = 0;

    const biometricZKP = await Biometric.generateBiometricZKP();
    if (!biometricZKP) throw new Error('Biometric ZKP generation failed or was denied.');

    autoProofs = [{ segmentIndex: segmentIndex, currentBioConst: currentBioConst, ownershipProof: ownershipProof, unlockIntegrityProof: unlockIntegrityProof, spentProof: spentProof, ownershipChangeCount: ownershipChangeCount, biometricZKP: biometricZKP }];
    autoDeviceKeyHash = vaultData.deviceKeyHash;
    autoUserBioConstant = currentBioConst;
    autoNonce = Math.floor(Math.random() * 1000000);
    autoSignature = await Proofs.signClaim(autoProofs, autoDeviceKeyHash, autoUserBioConstant, autoNonce);

    await DB.saveProofsToDB({
      proofs: autoProofs,
      deviceKeyHash: autoDeviceKeyHash,
      userBioConstant: autoUserBioConstant,
      nonce: autoNonce,
      signature: autoSignature
    });
    return true;
  },

  loadAutoProof: async () => {
    const stored = await DB.loadProofsFromDB();
    if (stored) {
      autoProofs = stored.proofs;
      autoDeviceKeyHash = stored.deviceKeyHash;
      autoUserBioConstant = stored.userBioConstant;
      autoNonce = stored.nonce;
      autoSignature = stored.signature;
    } else {
      autoProofs = null; // generate lazily on button click
    }
  },

  signClaim: async (proofs, deviceKeyHash, userBioConstant, nonce) => {
    const coder = ethers.AbiCoder.defaultAbiCoder();
    const inner = proofs.map(function(p){
      return ethers.keccak256(coder.encode(
        ['uint256','uint256','bytes32','bytes32','bytes32','uint256','bytes32'],
        [p.segmentIndex, p.currentBioConst, p.ownershipProof, p.unlockIntegrityProof, p.spentProof, p.ownershipChangeCount, p.biometricZKP]
      ));
    });
    const proofsHash = ethers.keccak256(coder.encode(['bytes32[]'], [inner]));
    const domain = { name: 'TVM', version: '1', chainId: Number(chainId), verifyingContract: CONTRACT_ADDRESS.toLowerCase() };
    const types = { Claim: [
      { name: 'user', type: 'address' },
      { name: 'proofsHash', type: 'bytes32' },
      { name: 'deviceKeyHash', type: 'bytes32' },
      { name: 'userBioConstant', type: 'uint256' },
      { name: 'nonce', type: 'uint256' }
    ]};
    const value = { user: account, proofsHash: proofsHash, deviceKeyHash: deviceKeyHash, userBioConstant: userBioConstant, nonce: nonce };
    return signer.signTypedData(domain, types, value);
  }
};

// ---------- UI ----------
const UI = {
  showAlert: (msg) => alert(msg),
  showLoading: (id) => {
    var el = document.getElementById(id + '-loading');
    if (el) el.classList.remove('hidden');
  },
  hideLoading: (id) => {
    var el = document.getElementById(id + '-loading');
    if (el) el.classList.add('hidden');
  },
  updateConnectedAccount: () => {
    var ca = document.getElementById('connectedAccount');
    if (ca) ca.textContent = account ? (account.slice(0,6)+'...'+account.slice(-4)) : 'Not connected';
    var wa = document.getElementById('wallet-address');
    if (wa) wa.textContent  = account ? ('Connected: '+account.slice(0,6)+'...'+account.slice(-4)) : '';
  }
};

// ---------- Contract Interactions ----------
const withBuffer = (g) => (g * 120n) / 100n;
const ensureReady = () => {
  if (!account || !tvmContract) { UI.showAlert('Connect your wallet first.'); return false; }
  return true;
};

const ContractInteractions = {
  claimTVM: async () => {
    if (!ensureReady()) return;
    UI.showLoading('claim');
    try {
      await Proofs.loadAutoProof();
      if (!autoProofs) await Proofs.generateAutoProof();
      const gasEstimate = await tvmContract.estimateGas.claimTVM(
        autoProofs, autoSignature, autoDeviceKeyHash, autoUserBioConstant, autoNonce
      );
      const tx = await tvmContract.claimTVM(
        autoProofs, autoSignature, autoDeviceKeyHash, autoUserBioConstant, autoNonce,
        { gasLimit: withBuffer(gasEstimate) }
      );
      await tx.wait();
      UI.showAlert('Claim successful.');
      Wallet.updateBalances();
      autoProofs = null;
    } catch (err) {
      console.error(err);
      UI.showAlert('Error claiming TVM: ' + (err.reason || err.message || err));
    } finally {
      UI.hideLoading('claim');
    }
  },

  exchangeTVMForSegments: async () => {
    if (!ensureReady()) return;
    UI.showLoading('exchange');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.tvm;
      if (amount === 0n) { UI.showAlert('No TVM to exchange.'); return; }
      const gasEstimate = await tvmContract.estimateGas.exchangeTVMForSegments(amount);
      const tx = await tvmContract.exchangeTVMForSegments(amount, { gasLimit: withBuffer(gasEstimate) });
      await tx.wait();
      UI.showAlert('Exchange successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error exchanging: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('exchange');
    }
  },

  swapTVMForUSDT: async () => {
    if (!ensureReady()) return;
    UI.showLoading('swap');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.tvm;
      if (amount === 0n) { UI.showAlert('No TVM to swap.'); return; }
      const gasEstimate = await tvmContract.estimateGas.swapTVMForUSDT(amount);
      const tx = await tvmContract.swapTVMForUSDT(amount, { gasLimit: withBuffer(gasEstimate) });
      await tx.wait();
      UI.showAlert('Swap successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error swapping: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('swap');
    }
  },

  swapUSDTForTVM: async () => {
    if (!ensureReady()) return;
    UI.showLoading('swap-usdt');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.usdt;
      if (amount === 0n) { UI.showAlert('No USDT to swap.'); return; }
      await Wallet.ensureAllowance(usdtContract, account, CONTRACT_ADDRESS.toLowerCase(), amount);
      const gasEstimate = await tvmContract.estimateGas.swapUSDTForTVM(amount);
      const tx = await tvmContract.swapUSDTForTVM(amount, { gasLimit: withBuffer(gasEstimate) });
      await tx.wait();
      UI.showAlert('Swap USDT→TVM successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error swapping USDT to TVM: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('swap-usdt');
    }
  }
};

// ---------- Segment (Micro-ledger) ----------
const Segment = {
  initializeSegments: async () => {
    for (let i = 1; i <= INITIAL_BALANCE_SHE; i++) {
      const segment = {
        segmentIndex: i,
        currentOwner: vaultData.bioIBAN,
        history: [{
          event:'Initialization',
          timestamp: Date.now(),
          from:'Genesis',
          to: vaultData.bioIBAN,
          bioConst: GENESIS_BIO_CONSTANT + i,
          integrityHash: await Utils.sha256Hex('init' + i + vaultData.bioIBAN)
        }]
      };
      await DB.saveSegmentToDB(segment);
    }
    vaultData.balanceSHE = INITIAL_BALANCE_SHE;
  },
  validateSegment: async (segment) => {
    const init = segment.history[0];
    const expectedInit = await Utils.sha256Hex('init' + segment.segmentIndex + init.to);
    if (init.integrityHash !== expectedInit) return false;
    let hash = init.integrityHash;
    for (let j=1;j<segment.history.length;j++) {
      const h = segment.history[j];
      hash = await Utils.sha256Hex(hash + h.event + h.timestamp + h.from + h.to + h.bioConst);
      if (h.integrityHash !== hash) return false;
    }
    const last = segment.history[segment.history.length - 1];
    if (last.biometricZKP && !/^0x[0-9a-fA-F]{64}$/.test(last.biometricZKP)) return false;
    return true;
  }
};

// ---------- P2P ----------
const P2P = {
  handleCatchOut: async () => {
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
      if (!vaultUnlocked) return UI.showAlert('Vault locked.');
      const amount = parseInt(prompt('Amount in SHE to send:'), 10);
      if (isNaN(amount) || amount <= 0 || amount > vaultData.balanceSHE) return UI.showAlert('Invalid amount.');
      if (amount > 300) return UI.showAlert('Amount exceeds per-transfer segment limit.');

      const _raw = prompt('Recipient Bio-IBAN:');
      const recipientIBAN = _raw ? Utils.sanitizeInput(_raw) : '';
      if (!recipientIBAN) return;

      const segments = await DB.loadSegmentsFromDB();
      const transferable = segments.filter(function(s){ return s.currentOwner === vaultData.bioIBAN; }).slice(0, amount);
      if (transferable.length < amount) return UI.showAlert('Insufficient segments.');

      const zkp = await Biometric.generateBiometricZKP();
      if (!zkp) return UI.showAlert('Biometric ZKP generation failed.');

      const payload = { bioCatch: [], nonce: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + '-' + Math.random()) };
      for (let k=0;k<transferable.length;k++) {
        const s = transferable[k];
        const last = s.history[s.history.length - 1];
        const timestamp = Date.now();
        const bioConst = last.bioConst + BIO_STEP;
        const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Transfer' + timestamp + vaultData.bioIBAN + recipientIBAN + bioConst);
        const newHistory = { event:'Transfer', timestamp: timestamp, from:vaultData.bioIBAN, to:recipientIBAN, bioConst: bioConst, integrityHash: integrityHash, biometricZKP: zkp };
        s.history.push(newHistory);
        s.currentOwner = recipientIBAN;
        await DB.saveSegmentToDB(s);
        payload.bioCatch.push(JSON.parse(JSON.stringify(s)));
      }
      console.log('Payload for transfer:', JSON.stringify(payload));
      alert('Catch Out: Transfer payload generated. Share via NFC or QR.');
      vaultData.transactions.push({ bioIBAN: vaultData.bioIBAN, bioCatch: 'Outgoing to ' + recipientIBAN, amount: amount / EXCHANGE_RATE, timestamp: Date.now(), status: 'Sent' });
      await Vault.updateBalanceFromSegments();
      await persistVaultData();
    } finally {
      transactionLock = false;
    }
  },

  handleCatchIn: async () => {
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
      if (!vaultUnlocked) return UI.showAlert('Vault locked.');
      const payloadStr = prompt('Enter Bio-Catch payload (JSON):');
      if (!payloadStr) return;
      if (payloadStr.length > 750000) return UI.showAlert('Payload too large.');

      let payload;
      try { payload = JSON.parse(payloadStr); } catch (e) { return UI.showAlert('Invalid payload JSON.'); }
      if (!payload || !Array.isArray(payload.bioCatch)) return UI.showAlert('Malformed payload: missing bioCatch array.');
      if (!payload.nonce) return UI.showAlert('Malformed payload: missing nonce.');
      if (payload.bioCatch.length > 300) return UI.showAlert('Too many segments in a single payload.');

      if (await DB.hasReplayNonce(payload.nonce)) return UI.showAlert('Duplicate transfer detected (replay).');
      await DB.putReplayNonce(payload.nonce);

      let validSegments = 0;
      for (let i=0;i<payload.bioCatch.length;i++) {
        let seg = payload.bioCatch[i];
        if (!(await Segment.validateSegment(seg))) continue;
        const last = seg.history[seg.history.length - 1];
        const timestamp = Date.now();
        const bioConst = last.bioConst + BIO_STEP;
        const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Received' + timestamp + last.from + vaultData.bioIBAN + bioConst);
        const zkpIn = await Biometric.generateBiometricZKP();
        seg.history.push({ event:'Received', timestamp: timestamp, from:last.from, to:vaultData.bioIBAN, bioConst: bioConst, integrityHash: integrityHash, biometricZKP: zkpIn });
        seg.currentOwner = vaultData.bioIBAN;
        await DB.saveSegmentToDB(seg);
        validSegments++;
      }
      if (validSegments > 0) {
        vaultData.transactions.push({ bioIBAN: vaultData.bioIBAN, bioCatch:'Incoming', amount: validSegments / EXCHANGE_RATE, timestamp: Date.now(), status:'Received' });
        await Vault.updateBalanceFromSegments();
        UI.showAlert('Received ' + validSegments + ' valid segments.');
        await persistVaultData();
      } else {
        UI.showAlert('No valid segments received.');
      }
    } finally {
      transactionLock = false;
    }
  },

  handleNfcRead: async () => {
    if ('NDEFReader' in window) {
      try {
        const reader = new NDEFReader();
        await reader.scan();
        reader.onreading = function(){ UI.showAlert('Incoming P2P transfer detected.'); };
      } catch (e) {
        console.warn('NFC scan failed:', e);
      }
    }
  }
};

// ---------- Notifications ----------
const Notifications = {
  requestPermission: () => {
    if ('Notification' in window && Notification.permission !== 'granted') Notification.requestPermission();
  },
  showNotification: (title, body) => {
    if ('Notification' in window && Notification.permission === 'granted') new Notification(title, { body: body });
  }
};

// ---------- Backups ----------
async function exportFullBackup() {
  const segments = await DB.loadSegmentsFromDB();
  const proofsBundle = await DB.loadProofsFromDB();
  const payload = { vaultData: vaultData, segments: segments, proofsBundle: proofsBundle, exportedAt: Date.now() };
  const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'biovault.fullbackup.json'; a.click();
}
async function importFullBackup(file) {
  const txt = await file.text();
  const obj = JSON.parse(txt);
  if (!obj || !obj.vaultData || !Array.isArray(obj.segments)) return UI.showAlert('Invalid full backup');
  const stored = await DB.loadVaultDataFromDB();
  if (!derivedKey) {
    if (!stored || !stored.salt) return UI.showAlert("Unlock once before importing (no salt).");
    const pin = prompt("Enter passphrase to re-encrypt imported vault:");
    if (!pin) return UI.showAlert("Import canceled.");
    derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin), stored.salt);
  }
  vaultData = obj.vaultData;
  const segs = obj.segments;
  const db = await DB.openVaultDB();
  await new Promise((res, rej) => {
    const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
    tx.objectStore(SEGMENTS_STORE).clear();
    segs.forEach(function(s){ tx.objectStore(SEGMENTS_STORE).put(s); });
    tx.oncomplete = res; tx.onerror = (e)=>rej(e.target.error);
  });
  if (obj.proofsBundle) await DB.saveProofsToDB(obj.proofsBundle);
  await persistVaultData();
  await Vault.updateBalanceFromSegments();
  Vault.updateVaultUI();
  UI.showAlert('Full backup imported.');
}
function exportTransactions() {
  const blob = new Blob([JSON.stringify(vaultData.transactions)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'transactions.json'; a.click();
}
function backupVault() {
  const backup = JSON.stringify(vaultData);
  const blob = new Blob([backup], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'vault.backup'; a.click();
}
function exportFriendlyBackup() { alert('Exporting friendly backup...'); }
function importVault() {
  const file = document.getElementById('importVaultInput').files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const imported = JSON.parse(e.target.result);
      const stored = await DB.loadVaultDataFromDB();
      if (!derivedKey) {
        if (!stored || !stored.salt) return UI.showAlert("Unlock once before importing (no salt found).");
        const pin = prompt("Enter passphrase to re-encrypt imported vault:");
        if (!pin) return UI.showAlert("Import canceled.");
        derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin), stored.salt);
      }
      vaultData = imported;
      await Vault.promptAndSaveVault();
      Vault.updateVaultUI();
      UI.showAlert("Vault imported and saved.");
    } catch (err) {
      console.error("Import failed", err);
      UI.showAlert("Failed to import backup.");
    }
  };
  reader.readAsText(file);
}
function copyToClipboard(id) {
  const textEl = document.getElementById(id);
  if (!textEl) return;
  navigator.clipboard.writeText(textEl.textContent).then(function(){ UI.showAlert('Copied!'); });
}

// ---------- Export to Blockchain helper ----------
async function exportProofToBlockchain() {
  showSection('dashboard');
  UI.showAlert('Open the Dashboard and click an action (e.g., Claim) to authorize with biometrics.');
}

// ---------- Section Switching ----------
function showSection(id) {
  var secs = document.querySelectorAll('.section');
  for (var i=0;i<secs.length;i++) secs[i].classList.remove('active-section');
  var tgt = document.getElementById(id);
  if (tgt) tgt.classList.add('active-section');
  if (id === 'dashboard') loadDashboardData();
  if (id === 'biovault' && vaultUnlocked) {
    var wp = document.querySelector('#biovault .whitepaper'); if (wp) wp.classList.add('hidden');
    var vu = document.getElementById('vaultUI'); if (vu) vu.classList.remove('hidden');
    var ls = document.getElementById('lockedScreen'); if (ls) ls.classList.add('hidden');
  }
}
window.showSection = showSection; // expose for nav links that call it

// ---------- Theme Toggle ----------
(function(){
  var t = document.getElementById('theme-toggle');
  if (t) t.addEventListener('click', function(){ document.body.classList.toggle('dark-mode'); });
})();

// ---------- Enable Dashboard Buttons ----------
function enableDashboardButtons() {
  var b1 = document.getElementById('claim-tvm-btn');        if (b1) b1.disabled = false;
  var b2 = document.getElementById('exchange-tvm-btn');     if (b2) b2.disabled = false;
  var b3 = document.getElementById('swap-tvm-usdt-btn');    if (b3) b3.disabled = false;
  var b4 = document.getElementById('swap-usdt-tvm-btn');    if (b4) b4.disabled = false;
}

// ---------- Service Worker ----------
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(function(){ console.log('[BioVault] SW registered'); }).catch(function(err){ console.warn('SW registration failed', err); });
}

// ---------- Persistence + session restore ----------
async function requestPersistentStorage() {
  try {
    if (navigator.storage && navigator.storage.persist) {
      const granted = await navigator.storage.persist();
      console.log(granted ? "🔒 Persistent storage granted" : "⚠️ Storage may be cleared under pressure");
    }
  } catch (e) { console.warn("persist() not available", e); }
}
function setupSessionRestore() {
  try {
    const lastURL = localStorage.getItem(SESSION_URL_KEY);
    if (lastURL && location.href !== lastURL) history.replaceState(null, "", lastURL);
  } catch(e){}
  window.addEventListener("beforeunload", function() {
    try { localStorage.setItem(SESSION_URL_KEY, location.href); } catch(e){}
  });
}
function enforceSingleVault() {
  const v = localStorage.getItem(VAULT_LOCK_KEY);
  if (!v) localStorage.setItem(VAULT_LOCK_KEY, 'locked');
}
function preventMultipleVaults() {
  window.addEventListener('storage', function(e) {
    if (e.key === VAULT_UNLOCKED_KEY) {
      const unlocked = e.newValue === 'true';
      if (unlocked && !vaultUnlocked) { vaultUnlocked = true; revealVaultUI(); }
      if (!unlocked && vaultUnlocked) { vaultUnlocked = false; if (Vault.lockVault) Vault.lockVault(); }
    }
  });
}
function isVaultLockedOut() {
  if (!vaultData.lockoutTimestamp) return false;
  const now = Math.floor(Date.now()/1000);
  if (now < vaultData.lockoutTimestamp) return true;
  vaultData.lockoutTimestamp = null;
  vaultData.authAttempts = 0;
  return false;
}
async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now()/1000) + LOCKOUT_DURATION_SECONDS;
  }
  await Vault.promptAndSaveVault();
}
async function persistVaultData(saltBuf) {
  if (!derivedKey) throw new Error('Derived key missing; cannot save vault.');
  const enc = await Encryption.encryptData(derivedKey, vaultData);
  const iv = enc.iv; const ciphertext = enc.ciphertext;
  let saltBase64;
  if (saltBuf) { saltBase64 = Encryption.bufferToBase64(saltBuf); }
  else {
    const existing = await DB.loadVaultDataFromDB();
    if (existing && existing.salt) saltBase64 = Encryption.bufferToBase64(existing.salt);
    else throw new Error('Salt missing; persist aborted.');
  }
  await DB.saveVaultDataToDB(iv, ciphertext, saltBase64);
}

// ---------- Init ----------
async function init() {
  console.log('[BioVault] init() starting…');
  await requestPersistentStorage();
  setupSessionRestore();
  enforceSingleVault();
  preventMultipleVaults();
  Notifications.requestPermission();
  P2P.handleNfcRead();

  const stored = await DB.loadVaultDataFromDB();
  if (stored) {
    console.log('[BioVault] Vault record found. Attempts:', stored.authAttempts);
    vaultData.authAttempts = stored.authAttempts;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
  } else {
    const credential = await Biometric.performBiometricAuthenticationForCreation();
    if (credential) {
      vaultData.credentialId = Encryption.bufferToBase64(credential.rawId);
      vaultData.bioIBAN = await Utils.sha256Hex(Math.random().toString());
      vaultData.joinTimestamp = Date.now();
      vaultData.deviceKeyHash = Utils.to0x(await Utils.sha256Hex(KEY_HASH_SALT + Utils.toB64(Utils.rand(32))));
      vaultData.balanceSHE = INITIAL_BALANCE_SHE;

      const salt = Utils.rand(16);
      const pin = prompt("Set passphrase:");
      derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin || ''), salt);
      await persistVaultData(salt);

      for (let i=1;i<=INITIAL_BALANCE_SHE;i++){
        await DB.saveSegmentToDB({
          segmentIndex: i,
          currentOwner: vaultData.bioIBAN,
          history: [{
            event:'Initialization',
            timestamp: Date.now(),
            from:'Genesis',
            to: vaultData.bioIBAN,
            bioConst: GENESIS_BIO_CONSTANT + i,
            integrityHash: await Utils.sha256Hex('init'+i+vaultData.bioIBAN)
          }]
        });
      }

      vaultUnlocked = true;
      revealVaultUI();
      await Vault.updateBalanceFromSegments();
      Vault.updateVaultUI();
    }
  }

  // Event Listeners
  const byId = function(id){ return document.getElementById(id); };
  var el;

  el = byId('connectMetaMaskBtn');     if (el) el.addEventListener('click', Wallet.connectMetaMask);
  el = byId('connectWalletConnectBtn');if (el) el.addEventListener('click', Wallet.connectWalletConnect);

  el = byId('enterVaultBtn'); if (el) el.addEventListener('click', async function(){
    console.log('[BioVault] Enter Vault clicked');
    if (isVaultLockedOut()) { UI.showAlert("Vault locked out."); return; }

    const pin = prompt("Enter passphrase:");
    const stored = await DB.loadVaultDataFromDB();
    if (!stored) return;

    derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin || ''), stored.salt);
    try {
      vaultData = await Encryption.decryptData(derivedKey, stored.iv, stored.ciphertext);

      let ok = await Biometric.performBiometricAssertion(vaultData.credentialId);
      if (!ok) {
        const wantReEnroll = confirm("Biometric failed. Re-enroll on this device and proceed?");
        if (wantReEnroll) ok = await reEnrollBiometricIfNeeded();
      }
      if (!ok) { await handleFailedAuthAttempt(); return UI.showAlert("Biometric failed."); }

      vaultUnlocked = true;
      revealVaultUI();
      await Vault.updateBalanceFromSegments();
      Vault.updateVaultUI();
      try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'true'); } catch(e){}
    } catch (e) {
      console.error('[BioVault] Unlock error', e);
      await handleFailedAuthAttempt();
      UI.showAlert("Invalid passphrase or corrupted vault.");
    }
  });

  el = byId('lockVaultBtn');           if (el) el.addEventListener('click', Vault.lockVault);
  el = byId('catchOutBtn');            if (el) el.addEventListener('click', P2P.handleCatchOut);
  el = byId('catchInBtn');             if (el) el.addEventListener('click', P2P.handleCatchIn);
  el = byId('claim-tvm-btn');          if (el) el.addEventListener('click', ContractInteractions.claimTVM);
  el = byId('exchange-tvm-btn');       if (el) el.addEventListener('click', ContractInteractions.exchangeTVMForSegments);
  el = byId('swap-tvm-usdt-btn');      if (el) el.addEventListener('click', ContractInteractions.swapTVMForUSDT);
  el = byId('swap-usdt-tvm-btn');      if (el) el.addEventListener('click', ContractInteractions.swapUSDTForTVM);
  el = byId('connect-wallet');         if (el) el.addEventListener('click', Wallet.connectMetaMask);

  // Idle Timeout
  let idleTimer;
  const resetIdle = function(){ clearTimeout(idleTimer); idleTimer = setTimeout(Vault.lockVault, MAX_IDLE); };
  ['click','keydown','mousemove','touchstart','visibilitychange'].forEach(function(evt){
    window.addEventListener(evt, resetIdle);
  });
  resetIdle();

  // UTC Time Update
  setInterval(function(){
    const tz = document.getElementById('utcTime');
    if (tz) tz.textContent = new Date().toUTCString();
  }, 1000);

  // Load Dashboard on Init if Needed (no-op if wallet not connected)
  loadDashboardData();
  console.log('[BioVault] init() complete.');
}

// ---------- Dashboard ----------
async function loadDashboardData() {
  if (!tvmContract) return;
  await Wallet.updateBalances();

  let table = '';
  let totalReserves = 0;
  for (let i = 1; i <= LAYERS; i++) {
    const reserve = 100000000; // mock
    totalReserves += reserve;
    const capProgress = (SEGMENTS_PER_LAYER / reserve * 100).toFixed(2) + '%';
    table += '<tr><td>'+i+'</td><td>'+reserve.toLocaleString()+' TVM</td><td>'+capProgress+'</td></tr>';
  }
  const lt = document.getElementById('layer-table');
  if (lt) lt.innerHTML = table;
  const ar = document.getElementById('avg-reserves');
  if (ar) ar.textContent = (totalReserves / LAYERS).toLocaleString() + ' TVM';

  const c1 = document.getElementById('pool-chart');
  const c2 = document.getElementById('layer-chart');
  if (window.Chart && c1 && c2) {
    if (c1._chart) c1._chart.destroy();
    c1._chart = new Chart(c1, {
      type: 'doughnut',
      data: { labels: ['Human Investment (51%)','AI Cap (49%)'], datasets: [{ data: [51,49], backgroundColor: ['#007bff','#dc3545'], borderRadius: 5 }] },
      options: { responsive:true, plugins:{ legend:{ position:'bottom' } }, cutout:'60%' }
    });
    if (c2._chart) c2._chart.destroy();
    c2._chart = new Chart(c2, {
      type: 'bar',
      data: { labels: Array.from({ length: LAYERS }, function(_, i){ return 'Layer ' + (i + 1); }), datasets: [{ label: 'Reserve (M TVM)', data: Array(LAYERS).fill(100), backgroundColor: '#007bff' }] },
      options: { responsive:true, scales:{ y:{ beginAtZero:true } } }
    });
  }
}

init();
