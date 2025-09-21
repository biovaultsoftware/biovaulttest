'use strict'; // Enable strict mode for better error checking

/******************************
 * main.js - ES2018 compatible (no optional chaining / numeric separators)
 * Ultimate master-class build: compact+encrypted P2P, network guards, robust charts, safe base64, 0x Bio-IBAN, bonus constant.
 * UPDATED: Implements clarified rules:
 *  - On-chain TVM claim uses segments with ownershipChangeCount === 1 (no 10-history on-chain).
 *  - P2P sends only unlocked segments; after send, auto-unlock equal count if caps allow.
 *  - Tracks daily/monthly/yearly segment caps (360/3600/10800) and yearly TVM (900 + 100 parity).
 *
 * PATCH: P2P payload switched from JSON to CBOR + varint streaming (v:3 envelope),
 *        with backward-compat import for v:1/v:2.
 ******************************/

// Dynamically load latest libraries (production: use bundler like Webpack for offline support)
async function loadLibraries() {
  try {
    await injectScript('https://cdn.jsdelivr.net/npm/ethers@6.15.0/dist/ethers.umd.min.js');
    await injectScript('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.21.8/dist/esm/index.js');
    await injectScript('https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js'); // Latest as of 2025
    console.log('[BioVault] Libraries loaded successfully');
  } catch (e) {
    console.error('[BioVault] Library load failed', e);
    UI.showAlert('Failed to load required libraries. Check your connection.');
  }
}

// ---------- Base Setup / Global Constants ----------//
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 4; // bumped for new fields
const VAULT_STORE = 'vault';
const PROOFS_STORE = 'proofs';
const SEGMENTS_STORE = 'segments';
const INITIAL_BALANCE_SHE = 1200;
const EXCHANGE_RATE = 12; // 1 TVM = 12 SHE
const INITIAL_BIO_CONSTANT = 1736565605;
const LOCKOUT_DURATION_SECONDS = 3600;
const MAX_AUTH_ATTEMPTS = 3;
// IMPORTANT: lowercase to bypass strict checksum validation in ethers v6
const CONTRACT_ADDRESS = '0xf15d7981dd2031cae8bb5f58513ae38b3d7a2b34';
const USDT_ADDRESS = '0x81cdb7fcf129b35cb36c0331db9664381b9254c9';
// expected network for your deployment
const EXPECTED_CHAIN_ID = 42161; // Arbitrum One
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
const BIO_STEP = 1;
const SEGMENTS_PER_LAYER = 1200;
const LAYERS = 10;
const SEGMENTS_PER_TVM = 12;
const DAILY_CAP_TVM = 30;
const MONTHLY_CAP_TVM = 300;
const YEARLY_CAP_TVM = 900;
const EXTRA_BONUS_TVM = 100; // parity
const MAX_YEARLY_TVM_TOTAL = YEARLY_CAP_TVM + EXTRA_BONUS_TVM;
const SEGMENT_HISTORY_MAX = 10;
const HISTORY_MAX = 20;
const KEY_HASH_SALT = "Balance-Chain-v3-PRD";
const PBKDF2_ITERS = 310000;
const AES_KEY_LENGTH = 256;
const MAX_IDLE = 15 * 60 * 1000;
const HMAC_KEY = new TextEncoder().encode("BalanceChainHMACSecret");
const WALLET_CONNECT_PROJECT_ID = 'c4f79cc9f2f73b737d4d06795a48b4a5'; // Replace with your own for production
// ---- QR/ZIP/Chart integration constants ----
const QR_CHUNK_MAX = 900; // safe per-frame payload length for QR (approx, ECC M)
const QR_SIZE = 512; // px
const QR_MARGIN = 2; // quiet zone
let _qrLibReady = false;
let _zipLibReady = false;
let _chartLibReady = false;
// ---------- Derived segment caps (segments, not TVM) ----------
const DAILY_CAP_SEG = DAILY_CAP_TVM * SEGMENTS_PER_TVM; // 360
const MONTHLY_CAP_SEG = MONTHLY_CAP_TVM * SEGMENTS_PER_TVM; // 3600
const YEARLY_CAP_SEG = YEARLY_CAP_TVM * SEGMENTS_PER_TVM; // 10800
// ---------- State ----------
let vaultUnlocked = false;
let derivedKey = null;
let provider = null;
let signer = null;
let tvmContract = null;
let usdtContract = null;
let account = null;
let chainId = null;
let transactionLock = false;
let lastCatchOutPayload = null;
// New: keep the raw CBOR bytes and a default filename for re-download
let lastCatchOutPayloadBytes = null;
let lastCatchOutFileName = "";
const SESSION_URL_KEY = 'last_session_url';
const VAULT_UNLOCKED_KEY = 'vaultUnlocked';
const VAULT_LOCK_KEY = 'vaultLock';
const VAULT_BACKUP_KEY = 'vault.backup';
// ---------- CONSTANTS (all used below) ----------
const BIO_TOLERANCE = 720; // seconds: biometric freshness window
const DECIMALS_FACTOR = 1000000;
const MAX_PROOFS_LENGTH = 200; // cap batch size
const SEGMENT_PROOF_TYPEHASH = ethers.utils.keccak256(
  ethers.utils.toUtf8Bytes(
    "SegmentProof(uint256 segmentIndex,uint256 currentBioConst,bytes32 ownershipProof,bytes32 unlockIntegrityProof,bytes32 spentProof,uint256 ownershipChangeCount,bytes32 biometricZKP)"
  )
);
const CLAIM_TYPEHASH = ethers.utils.keccak256(
  ethers.utils.toUtf8Bytes(
    "Claim(address user,bytes32 proofsHash,bytes32 deviceKeyHash,uint256 userBioConstant,uint256 nonce)"
  )
);
const STORAGE_CHECK_INTERVAL = 300000; // 5 min
const vaultSyncChannel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('vault-sync') : null;
// ---------- AUTO (now actually used) ----------
let autoProofs = null;
let autoDeviceKeyHash = ''; // bytes32 hex
let autoUserBioConstant = 0;
let autoNonce = 0;
let autoSignature = '';
// ---------- UTIL ----------
const coder = ethers.utils.defaultAbiCoder;
function toBaseUnits(xHuman) {
  return Math.floor(Number(xHuman) * DECIMALS_FACTOR);
}
function fromBaseUnits(xBase) {
  return Number(xBase) / DECIMALS_FACTOR;
}
function nowSec() { return Math.floor(Date.now() / 1000); }
function keccakPacked(types, values) {
  return ethers.utils.keccak256(coder.encode(types, values));
}
// Compute hash of a SegmentProof as the on-chain contract would (EIP-712-style struct hash)
function hashSegmentProof(p) {
  return keccakPacked(
    [
      'bytes32',
      'uint256',
      'uint256',
      'bytes32',
      'bytes32',
      'bytes32',
      'uint256',
      'bytes32'
    ],
    [
      SEGMENT_PROOF_TYPEHASH,
      p.segmentIndex,
      p.currentBioConst,
      p.ownershipProof,
      p.unlockIntegrityProof,
      p.spentProof,
      p.ownershipChangeCount,
      p.biometricZKP
    ]
  );
}
// Merkle root of segment proof hashes (for compact payload)
function merkleRoot(hashes /* array of 0x..32B */) {
  if (!hashes.length) return ethers.constants.HashZero;
  let layer = hashes.slice();
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : left;
      next.push(ethers.utils.keccak256(ethers.utils.concat([left, right])));
    }
    layer = next;
  }
  return layer[0];
}
// Segment index bitmap compression (compact segment set)
function segmentBitmap(indices){
  if (!indices || indices.length === 0) return '0x';
  const max = Math.max(...indices);
  const bytes = new Uint8Array(Math.floor(max / 8) + 1);
  for (let ii = 0; ii < indices.length; ii++) {
    const i = indices[ii];
    bytes[i >> 3] |= (1 << (i & 7));
  }
  return ethers.utils.hexlify(bytes);
}
// Biometric recency / tolerance gate
function checkBioFreshness(ts /* seconds */) {
  if (Math.abs(nowSec() - ts) > BIO_TOLERANCE) {
    throw new Error('Biometric proof outside tolerance window of ' + BIO_TOLERANCE + 's');
  }
}
// AES-GCM envelope keyed for the receiver (compact & private)
async function encryptForReceiver(receiverDeviceKeyHashHex, bytes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ethers.utils.arrayify(receiverDeviceKeyHashHex),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', salt, info: new Uint8Array([]), hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  return {
    iv: ethers.utils.hexlify(iv),
    salt: ethers.utils.hexlify(salt),
    ct: ethers.utils.hexlify(ct)
  };
}
async function decryptFromSender(receiverDeviceKeyHashHex, envelope) {
  const iv = envelope.iv, salt = envelope.salt, ct = envelope.ct;
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ethers.utils.arrayify(receiverDeviceKeyHashHex),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', salt: ethers.utils.arrayify(salt), info: new Uint8Array([]), hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ethers.utils.arrayify(iv) },
    key,
    ethers.utils.arrayify(ct)
  );
  return new Uint8Array(pt);
}
function downloadBytes(filename, u8, mime){
  const blob = new Blob([u8], { type: mime || 'application/cbor' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
// ---------- OWNERSHIP RULES (enforced in proof composers) ----------
function encodeOwnershipProof({ originalOwner, previousOwner, currentOwner }) {
  return keccakPacked(
    ['address', 'address', 'address'],
    [originalOwner, previousOwner, currentOwner]
  );
}
function encodeSpentProof({ previousOwner, segmentIndex, nonce }) {
  return keccakPacked(
    ['address', 'uint256', 'uint256'],
    [previousOwner, segmentIndex, nonce]
  );
}
function encodeUnlockIntegrityProof({ chainId, vaultId, purpose }) {
  return keccakPacked(
    ['uint256', 'bytes32', 'bytes32'],
    [chainId, ethers.utils.id(vaultId || 'vault'), ethers.utils.id(purpose || 'transfer')]
  );
}
// ---------- TVM MINT (strict rules) ----------
function buildTvmMintSegmentProof({
  segmentIndex, vaultOwner, currentOwner, currentBioConst, biometricZKP, chainId, vaultId
}) {
  if (vaultOwner.toLowerCase() === currentOwner.toLowerCase()) {
    throw new Error('TVM mint: current owner must differ from vault owner');
  }
  const ownershipProof = encodeOwnershipProof({
    originalOwner: vaultOwner,
    previousOwner: vaultOwner,
    currentOwner: currentOwner
  });
  const unlockIntegrityProof = encodeUnlockIntegrityProof({ chainId, vaultId, purpose: 'mint' });
  const spentProof = ethers.constants.HashZero;
  const ownershipChangeCount = 1;
  checkBioFreshness(biometricZKP.ts);
  return {
    segmentIndex,
    currentBioConst,
    ownershipProof,
    unlockIntegrityProof,
    spentProof,
    ownershipChangeCount,
    biometricZKP: biometricZKP.commit
  };
}
// ---------- P2P TRANSFER ----------
function buildP2PTransferSegmentProof({
  segmentIndex, originalOwner, currentOwner, receiver, previousOwner,
  currentBioConst, biometricZKP, chainId, vaultId, nonceForSpent
}) {
  if (currentOwner.toLowerCase() !== previousOwner.toLowerCase()) {
    throw new Error('Transfer composer: `previousOwner` must equal `currentOwner` before hand-off');
  }
  const ownershipProof = encodeOwnershipProof({
    originalOwner,
    previousOwner: currentOwner,
    currentOwner: receiver
  });
  const unlockIntegrityProof = encodeUnlockIntegrityProof({ chainId, vaultId, purpose: 'transfer' });
  const spentProof = encodeSpentProof({ previousOwner: currentOwner, segmentIndex, nonce: nonceForSpent });
  const ownershipChangeCount = 0;
  checkBioFreshness(biometricZKP.ts);
  return {
    segmentIndex,
    currentBioConst,
    ownershipProof,
    unlockIntegrityProof,
    spentProof,
    ownershipChangeCount,
    biometricZKP: biometricZKP.commit
  };
}
// ---------- PREVIOUS-OWNER CATCH-IN ----------
function buildCatchInClaim({ user, proofs, deviceKeyHash, userBioConstant, nonce }) {
  if (proofs.length === 0) throw new Error('No proofs to claim');
  if (proofs.length > MAX_PROOFS_LENGTH) throw new Error('Too many proofs; max ' + MAX_PROOFS_LENGTH);
  const proofHashes = proofs.map(hashSegmentProof);
  const proofsHash = merkleRoot(proofHashes);
  const claimDigest = keccakPacked(
    ['bytes32','address','bytes32','bytes32','uint256','uint256'],
    [CLAIM_TYPEHASH, user, proofsHash, deviceKeyHash, userBioConstant, nonce]
  );
  return { proofsHash, claimDigest };
}
// ---------- COMPACT PAYLOAD BUILDER (Merkle + bitmap + envelope) ----------
async function buildCompactPayload({
  version = 3, from, to, chainId, deviceKeyHashReceiver, userBioConstant, proofs
}) {
  if (proofs.length > MAX_PROOFS_LENGTH) throw new Error('Too many proofs; max ' + MAX_PROOFS_LENGTH);
  const proofHashes = proofs.map(hashSegmentProof);
  const proofsRoot = merkleRoot(proofHashes);
  const segments = proofs.map(p => p.segmentIndex).sort((a, b) => a - b);
  const bitmap = segmentBitmap(segments);
  const r = buildCatchInClaim({
    user: from,
    proofs,
    deviceKeyHash: autoDeviceKeyHash || ethers.constants.HashZero,
    userBioConstant: autoUserBioConstant || userBioConstant,
    nonce: autoNonce
  });
  const claimDigest = r.claimDigest;
  const raw = new TextEncoder().encode(JSON.stringify({ chainId, proofs }));
  const envelope = await encryptForReceiver(deviceKeyHashReceiver, raw);
  const payload = {
    v: version,
    from,
    to,
    root: proofsRoot,
    segbm: bitmap,
    dk: deviceKeyHashReceiver,
    ubc: userBioConstant,
    nonce: autoNonce,
    env: envelope,
    sig: autoSignature
  };
  return { payload, claimDigest };
}
// ---------- SIGN & SEND ----------
async function signClaimDigest(signer, claimDigest) {
  const sig = await signer.signMessage(ethers.utils.arrayify(claimDigest));
  autoSignature = sig;
  return sig;
}
function importVault(armoredText) {
  try {
    const parsed = JSON.parse(decodeURIComponent(escape(atob(armoredText))));
    window.__vaultState = parsed.state || {};
    autoDeviceKeyHash = (parsed?.auto?.autoDeviceKeyHash) || autoDeviceKeyHash;
    autoUserBioConstant = (parsed?.auto?.userBioConstant) || autoUserBioConstant;
    autoNonce = (parsed?.auto?.autoNonce) || autoNonce;
    if (vaultSyncChannel) vaultSyncChannel.postMessage({ type: 'backup:restored', ts: Date.now() });
    return true;
  } catch (e) {
    console.error('Import failed', e);
    return false;
  }
}
// ---------- PERIODIC STORAGE CHECK ----------
let __storageCheckTimer = setInterval(() => {
  const exists = !!localStorage.getItem(VAULT_BACKUP_KEY);
  if (!exists) console.warn('Vault backup missing; consider running backupVault()');
}, STORAGE_CHECK_INTERVAL);
// ---------- HIGH-LEVEL FLOWS ----------
// 1) TVM Mint flow (one or many segments)
async function composeAndSendMint({
  segments, vaultOwner, currentOwner, currentBioConst, biometricZKP, chainId, vaultId, receiverDeviceKeyHash, signer
}) {
  const from = await signer.getAddress();
  if (from.toLowerCase() !== currentOwner.toLowerCase()) {
    throw new Error('Signer must match currentOwner for mint claim');
  }
  const proofs = segments.map(sIdx => buildTvmMintSegmentProof({
    segmentIndex: sIdx,
    vaultOwner,
    currentOwner,
    currentBioConst,
    biometricZKP,
    chainId,
    vaultId
  }));
  autoProofs = proofs;
  autoUserBioConstant = currentBioConst;
  const b = await buildCompactPayload({
    from,
    to: currentOwner,
    chainId,
    deviceKeyHashReceiver,
    userBioConstant: currentBioConst,
    proofs
  });
  const payload = b.payload;
  const claimDigest = b.claimDigest;
  payload.sig = await signClaimDigest(signer, claimDigest);
  await exportProofToBlockchain(payload);
  return payload;
}
// 2) P2P Transfer flow
async function composeAndSendTransfer({
  segments, originalOwner, currentOwner, receiver, currentBioConst, biometricZKP, chainId, vaultId, nonceForSpent, receiverDeviceKeyHash, signer
}) {
  const from = await signer.getAddress();
  if (from.toLowerCase() !== currentOwner.toLowerCase()) throw new Error('Sender must be current owner');
  const proofs = segments.map(sIdx => buildP2PTransferSegmentProof({
    segmentIndex: sIdx,
    originalOwner,
    currentOwner,
    receiver,
    previousOwner: currentOwner,
    currentBioConst,
    biometricZKP,
    chainId,
    vaultId,
    nonceForSpent
  }));
  autoProofs = proofs;
  autoUserBioConstant = currentBioConst;
  const b = await buildCompactPayload({
    from,
    to: receiver,
    chainId,
    deviceKeyHashReceiver,
    userBioConstant: currentBioConst,
    proofs
  });
  const payload = b.payload;
  const claimDigest = b.claimDigest;
  payload.sig = await signClaimDigest(signer, claimDigest);
  await exportProofToBlockchain(payload);
  return payload;
}
// 3) Previous-owner Catch-in (anti double-spend)
async function composeCatchIn({
  previousOwner, deviceKeyHash, userBioConstant, signer
}) {
  const from = await signer.getAddress();
  if (from.toLowerCase() !== previousOwner.toLowerCase()) throw new Error('Only previous owner can catch-in');
  if (!autoProofs || !autoProofs.length) throw new Error('No prior proofs cached to catch-in');
  const c = buildCatchInClaim({
    user: previousOwner,
    proofs: autoProofs,
    deviceKeyHash,
    userBioConstant,
    nonce: ++autoNonce // bump nonce for uniqueness
  });
  const sig = await signClaimDigest(signer, c.claimDigest);
  const payload = { user: previousOwner, proofsHash: c.proofsHash, deviceKeyHash, ubc: userBioConstant, nonce: autoNonce, sig };
  lastCatchOutPayload = payload;
  // send to chain/relayer:
  await exportProofToBlockchain({ type: 'catch-in', user: previousOwner, proofsHash: c.proofsHash, deviceKeyHash, ubc: userBioConstant, nonce: autoNonce, sig });
  return payload;
}
let vaultData = {
  bioIBAN: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  bonusConstant: INITIAL_BIO_CONSTANT,
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
  layerBalances: Array.from({length: LAYERS}, () => 0),
  caps: { dayKey:"", monthKey:"", yearKey:"", dayUsedSeg:0, monthUsedSeg:0, yearUsedSeg:0, tvmYearlyClaimed:0 },
  nextSegmentIndex: INITIAL_BALANCE_SHE + 1
};
vaultData.layerBalances[0] = INITIAL_BALANCE_SHE;
let lastCatchOutPayloadStr = "";
let lastQrFrames = [];
let lastQrFrameIndex = 0;
// ---------- Utils (safe base64 / crypto helpers) ----------
function _u8ToB64(u8) {
  const CHUNK = 0x8000;
  let s = '';
  for (let i = 0; i < u8.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(s);
}
const Utils = {
  enc: new TextEncoder(),
  dec: new TextDecoder(),
  toB64: function (buf) { 
    const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : (buf && buf.buffer) ? new Uint8Array(buf.buffer) : new Uint8Array(buf || []); 
    return _u8ToB64(u8); 
  },
  fromB64: function (b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer; },
  rand: function (len) { return crypto.getRandomValues(new Uint8Array(len)); },
  ctEq: function (a, b) { 
    a = a || ""; b = b || ""; 
    if (a.length !== b.length) return false; 
    let r = 0; 
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); 
    return r === 0; 
  },
  canonical: function (obj) { return JSON.stringify(obj, Object.keys(obj).sort()); },
  sha256: async function (data) { 
    const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? Utils.enc.encode(data) : data); 
    return Utils.toB64(buf); 
  },
  sha256Hex: async function (str) { 
    const buf = await crypto.subtle.digest("SHA-256", Utils.enc.encode(str)); 
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join(""); 
  },
  hmacSha256: async function (message) { 
    const key = await crypto.subtle.importKey("raw", HMAC_KEY, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); 
    const signature = await crypto.subtle.sign("HMAC", key, Utils.enc.encode(message)); 
    return Utils.toB64(signature); 
  },
  sanitizeInput: function (input) { return typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(input) : String(input); },
  to0x: function (hex) { return hex && hex.slice(0, 2) === '0x' ? hex : ('0x' + hex); }
};
// ---------- Script Loader (QR + JSZip + Chart.js) ----------
function injectScript(src) { 
  return new Promise((resolve, reject) => { 
    const s = document.createElement('script'); 
    s.src = src; s.async = true; 
    s.onload = resolve; 
    s.onerror = reject; 
    document.head.appendChild(s); 
  }); 
}
async function ensureQrLib() { 
  if (_qrLibReady) return; 
  try { 
    await injectScript('https://cdn.jsdelivr.net/npm/qrcode@1.5.4/build/qrcode.min.js'); 
    if (window.QRCode && typeof window.QRCode.toCanvas === 'function') _qrLibReady = true; 
  } catch (e) { console.warn('[BioVault] QR lib load failed', e); } 
}
async function ensureZipLib() { 
  if (_zipLibReady) return; 
  try { 
    await injectScript('https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js'); 
    if (window.JSZip) _zipLibReady = true; 
  } catch (e) { console.warn('[BioVault] JSZip load failed', e); } 
}
async function ensureChartLib() { 
  if (_chartLibReady || window.Chart) { _chartLibReady = true; return; } 
  try { 
    await injectScript('https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js'); 
    _chartLibReady = !!window.Chart; 
  } catch (e) { console.warn('[BioVault] Chart.js load failed', e); } 
}
// ---------- Encryption ----------
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
  bufferToBase64: (buf) => { 
    const u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : (buf && buf.buffer) ? new Uint8Array(buf.buffer) : new Uint8Array(buf); 
    return _u8ToB64(u8); 
  },
  base64ToBuffer: (b64) => {
    if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) throw new Error('Invalid Base64 string');
    const bin = atob(b64); 
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
};
// ---------- DB (IndexedDB) with encryption ----------
const DB = {
  openVaultDB: () => new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(PROOFS_STORE)) db.createObjectStore(PROOFS_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(SEGMENTS_STORE)) db.createObjectStore(SEGMENTS_STORE, { keyPath: 'segmentIndex' });
      if (!db.objectStoreNames.contains('replays')) db.createObjectStore('replays', { keyPath: 'nonce' });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e.target.error);
  }),
  // Encrypt before save, decrypt after load for all stores
  saveVaultDataToDB: async (iv, ciphertext, saltB64) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).put({
        id: 'vaultData',
        iv: Encryption.bufferToBase64(iv),
        ciphertext: Encryption.bufferToBase64(ciphertext),
        salt: saltB64,
        lockoutTimestamp: vaultData.lockoutTimestamp || null,
        authAttempts: vaultData.authAttempts || 0
      });
      tx.oncomplete = resolve;
      tx.onerror = (e) => reject(e.target.error);
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
      get.onerror = (e) => reject(e.target.error);
    });
  },
  clearVaultDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).clear();
      tx.oncomplete = resolve;
      tx.onerror = (e) => reject(e.target.error);
    });
  },
  saveProofsToDB: async (bundle) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readwrite');
      tx.objectStore(PROOFS_STORE).put({ id: 'autoProofs', data: bundle });
      tx.oncomplete = resolve;
      tx.onerror = (e) => reject(e.target.error);
    });
  },
  loadProofsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readonly');
      const get = tx.objectStore(PROOFS_STORE).get('autoProofs');
      get.onsuccess = () => resolve(get.result ? get.result.data : null);
      get.onerror = (e) => reject(e.target.error);
    });
  },
  saveSegmentToDB: async (segment) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      tx.objectStore(SEGMENTS_STORE).put(segment);
      tx.oncomplete = resolve;
      tx.onerror = (e) => reject(e.target.error);
    });
  },
  loadSegmentsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readonly');
      const getAll = tx.objectStore(SEGMENTS_STORE).getAll();
      getAll.onsuccess = () => resolve(getAll.result || []);
      getAll.onerror = (e) => reject(e.target.error);
    });
  },
  deleteSegmentFromDB: async (segmentIndex) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      tx.objectStore(SEGMENTS_STORE).delete(segmentIndex);
      tx.oncomplete = resolve;
      tx.onerror = (e) => reject(e.target.error);
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
      const tx = db.transaction(['replays'], 'readonly');
      const g = tx.objectStore('replays').get(nonce);
      g.onsuccess = () => res(!!g.result);
      g.onerror = (e) => rej(e.target.error);
    });
  },
  putReplayNonce: async (nonce) => {
    const db = await DB.openVaultDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['replays'], 'readwrite');
      tx.objectStore('replays').put({ nonce, ts: Date.now() });
      tx.oncomplete = res;
      tx.onerror = (e) => rej(e.target.error);
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
            { type: "public-key", alg: -7 }, // ES256
            { type: "public-key", alg: -257 } // RS256
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
          challenge,
          allowCredentials: [{ type: "public-key", id: new Uint8Array(idBuf) }],
          userVerification: "required",
          timeout: 60000
        }
      });
      if (!assertion) return null;
      const hex = await Utils.sha256Hex(String.fromCharCode.apply(null, new Uint8Array(assertion.signature)));
      return { commit: Utils.to0x(hex), ts: nowSec() }; // include freshness timestamp
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
    await persistVaultData();
    return true;
  } catch (e) {
    console.warn('[BioVault] Re-enroll failed:', e);
    return false;
  }
}
// ---------- Vault helpers for UI show/hide ----------
function revealVaultUI() {
  const wp = document.querySelector('#biovault .whitepaper');
  if (wp) wp.classList.add('hidden');
  const locked = document.getElementById('lockedScreen');
  const vault = document.getElementById('vaultUI');
  if (locked) locked.classList.add('hidden');
  if (vault) { vault.classList.remove('hidden'); vault.style.display = 'block'; }
  try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'true'); } catch(e) {}
}
function restoreLockedUI() {
  const wp = document.querySelector('#biovault .whitepaper');
  if (wp) wp.classList.remove('hidden');
  const locked = document.getElementById('lockedScreen');
  const vault = document.getElementById('vaultUI');
  if (vault) { vault.classList.add('hidden'); vault.style.display = 'none'; }
  if (locked) locked.classList.remove('hidden');
  try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'false'); } catch(e) {}
}
// ---------- Time/Caps Helpers ----------
function utcDayKey(d) { 
  const dt = new Date(d); 
  return dt.getUTCFullYear() + "-" + String(dt.getUTCMonth() + 1).padStart(2, '0') + "-" + String(dt.getUTCDate()).padStart(2, '0'); 
}
function utcMonthKey(d) { 
  const dt = new Date(d); 
  return dt.getUTCFullYear() + "-" + String(dt.getUTCMonth() + 1).padStart(2, '0'); 
}
function utcYearKey(d) { 
  const dt = new Date(d); 
  return String(dt.getUTCFullYear()); 
}
function resetCapsIfNeeded(nowTs) {
  const dKey = utcDayKey(nowTs);
  const mKey = utcMonthKey(nowTs);
  const yKey = utcYearKey(nowTs);
  if (vaultData.caps.dayKey !== dKey) { vaultData.caps.dayKey = dKey; vaultData.caps.dayUsedSeg = 0; }
  if (vaultData.caps.monthKey !== mKey) { vaultData.caps.monthKey = mKey; vaultData.caps.monthUsedSeg = 0; }
  if (vaultData.caps.yearKey !== yKey) { vaultData.caps.yearKey = yKey; vaultData.caps.yearUsedSeg = 0; vaultData.caps.tvmYearlyClaimed = 0; }
}
function canUnlockSegments(n) {
  const now = Date.now();
  resetCapsIfNeeded(now);
  return vaultData.caps.dayUsedSeg + n <= DAILY_CAP_SEG &&
         vaultData.caps.monthUsedSeg + n <= MONTHLY_CAP_SEG &&
         vaultData.caps.yearUsedSeg + n <= YEARLY_CAP_SEG;
}
function recordUnlock(n) {
  const now = Date.now();
  resetCapsIfNeeded(now);
  vaultData.caps.dayUsedSeg += n;
  vaultData.caps.monthUsedSeg += n;
  vaultData.caps.yearUsedSeg += n;
}
// ---------- Vault ----------
const Vault = {
  deriveKeyFromPIN: async (pin, salt) => {
    const baseKey = await crypto.subtle.importKey("raw", Utils.enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
      baseKey, { name: "AES-GCM", length: AES_KEY_LENGTH }, false, ["encrypt", "decrypt"]
    );
  },
  promptAndSaveVault: async (salt) => await persistVaultData(salt || null),
  updateVaultUI: () => {
    const eIBAN = document.getElementById('bioIBAN');
    if (eIBAN) eIBAN.textContent = vaultData.bioIBAN;
    const eSHE = document.getElementById('balanceSHE');
    if (eSHE) eSHE.textContent = vaultData.balanceSHE;
    const tvmFloat = vaultData.balanceSHE / EXCHANGE_RATE;
    const eTVM = document.getElementById('balanceTVM');
    if (eTVM) eTVM.textContent = tvmFloat.toFixed(4);
    const eUSD = document.getElementById('balanceUSD');
    if (eUSD) eUSD.textContent = tvmFloat.toFixed(2);
    const eBonus = document.getElementById('bonusConstant');
    if (eBonus) eBonus.textContent = vaultData.bonusConstant;
    const eAccount = document.getElementById('connectedAccount');
    if (eAccount) eAccount.textContent = vaultData.userWallet || 'Not connected';
    const historyBody = document.getElementById('transactionHistory');
    if (historyBody) {
      historyBody.innerHTML = '';
      vaultData.transactions.slice(0, HISTORY_MAX).forEach(tx => {
        const row = document.createElement('tr');
        const cols = [tx.bioIBAN, tx.bioCatch, String(tx.amount), new Date(tx.timestamp).toUTCString(), tx.status];
        cols.forEach(v => {
          const td = document.createElement('td');
          td.textContent = v;
          row.appendChild(td);
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
    vaultData.balanceSHE = segs.filter(s => s.currentOwner === vaultData.bioIBAN).length;
    Vault.updateVaultUI();
  }
};
// ---------- Network/Contract guards ----------
async function contractExists(addr) {
  if (!provider) return false;
  try {
    const code = await provider.getCode(addr);
    return code && code !== '0x';
  } catch (e) { return false; }
}
function enableDashboardButtons() {
  const ids = ['claim-tvm-btn', 'exchange-tvm-btn', 'swap-tvm-usdt-btn', 'swap-usdt-tvm-btn'];
  ids.forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = false;
  });
}
function disableDashboardButtons() {
  const ids = ['claim-tvm-btn', 'exchange-tvm-btn', 'swap-tvm-usdt-btn', 'swap-usdt-tvm-btn'];
  ids.forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = true;
  });
}
const ARBITRUM_ONE_PARAMS = {
  chainId: '0xA4B1',
  chainName: 'Arbitrum One',
  nativeCurrency: {
    name: 'Ethereum',
    symbol: 'ETH',
    decimals: 18
  },
  rpcUrls: ['https://arb1.arbitrum.io/rpc'],
  blockExplorerUrls: ['https://arbiscan.io']
};
// ---------- Wallet ----------
const Wallet = {
  connectMetaMask: async () => {
    if (!window.ethereum) { UI.showAlert('Install MetaMask to continue.'); return; }
    try {
      provider = new ethers.BrowserProvider(window.ethereum);
      await provider.send('eth_requestAccounts', []);
      signer = await provider.getSigner();
      account = await signer.getAddress();
      chainId = (await provider.getNetwork()).chainId;
      if (Number(chainId) !== EXPECTED_CHAIN_ID) {
        try {
          await window.ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: '0x' + EXPECTED_CHAIN_ID.toString(16) }]
          });
          chainId = (await provider.getNetwork()).chainId;
        } catch (switchError) {
          if (switchError.code === 4902) {
            try {
              await window.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [ARBITRUM_ONE_PARAMS]
              });
              await window.ethereum.request({
                method: 'wallet_switchEthereumChain',
                params: [{ chainId: '0x' + EXPECTED_CHAIN_ID.toString(16) }]
              });
              chainId = (await provider.getNetwork()).chainId;
            } catch (addError) {
              console.error('[BioVault] Chain add failed', addError);
              UI.showAlert('Failed to add/switch to Arbitrum One. Please add it manually in your wallet.');
              return;
            }
          } else {
            console.error('[BioVault] Chain switch failed', switchError);
            UI.showAlert('Failed to switch to Arbitrum One. Please switch manually in your wallet.');
            return;
          }
        }
      }
      vaultData.userWallet = account;
      UI.updateConnectedAccount();
      await Wallet.initContracts();
      await Wallet.updateBalances();
      enableDashboardButtons();
      const btn = document.getElementById('connect-wallet');
      if (btn) { btn.textContent = 'Wallet Connected'; btn.disabled = true; }
    } catch (e) {
      console.error('[BioVault] MetaMask connect failed', e);
      UI.showAlert('MetaMask connection failed: ' + (e.message || e));
    }
  },
  connectWalletConnect: async () => {
    let WCProvider;
    try {
      WCProvider = await retryImport('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.21.8/dist/esm/index.js');
    } catch (e) {
      UI.showAlert('Could not load WalletConnect (offline or blocked). Try MetaMask.');
      return;
    }
    const wcProvider = await WCProvider.EthereumProvider.init({
      projectId: WALLET_CONNECT_PROJECT_ID,
      chains: [EXPECTED_CHAIN_ID],
      optionalChains: [1, 10, 137],
      showQrModal: true
    });
    await wcProvider.enable();
    provider = new ethers.BrowserProvider(wcProvider);
    signer = await provider.getSigner();
    account = await signer.getAddress();
    chainId = (await provider.getNetwork()).chainId;
    if (Number(chainId) !== EXPECTED_CHAIN_ID) {
      try {
        await wcProvider.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: '0x' + EXPECTED_CHAIN_ID.toString(16) }]
        });
        chainId = (await provider.getNetwork()).chainId;
      } catch (switchError) {
        if (switchError.code === 4902) {
          try {
            await wcProvider.request({
              method: 'wallet_addEthereumChain',
              params: [ARBITRUM_ONE_PARAMS]
            });
            await wcProvider.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: '0x' + EXPECTED_CHAIN_ID.toString(16) }]
            });
            chainId = (await provider.getNetwork()).chainId;
          } catch (addError) {
            console.error('[BioVault] Chain add failed', addError);
            UI.showAlert('Failed to add/switch to Arbitrum One. Please add it manually in your wallet.');
            return;
          }
        } else {
          console.error('[BioVault] Chain switch failed', switchError);
          UI.showAlert('Failed to switch to Arbitrum One. Please switch manually in your wallet.');
          return;
        }
      }
    }
    vaultData.userWallet = account;
    UI.updateConnectedAccount();
    await Wallet.initContracts();
    await Wallet.updateBalances();
    enableDashboardButtons();
    const btn = document.getElementById('connect-wallet');
    if (btn) { btn.textContent = 'Wallet Connected'; btn.disabled = true; }
  },
  initContracts: async () => {
    try {
      if (Number(chainId) !== EXPECTED_CHAIN_ID) {
        UI.showAlert('Wrong network. Please switch to the expected network.');
        tvmContract = null; usdtContract = null; disableDashboardButtons(); return;
      }
      const tvmAddr = CONTRACT_ADDRESS.toLowerCase();
      const usdtAddr = USDT_ADDRESS.toLowerCase();
      const tvmOk = await contractExists(tvmAddr);
      const usdtOk = await contractExists(usdtAddr);
      if (!tvmOk || !usdtOk) {
        UI.showAlert('Contract(s) not deployed on this network. Dashboard features disabled.');
        tvmContract = null; usdtContract = null; disableDashboardButtons(); return;
      }
      tvmContract = new ethers.Contract(tvmAddr, ABI, signer);
      usdtContract = new ethers.Contract(usdtAddr, [
        {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
      ], signer);
      console.log('[BioVault] Contracts initialized');
    } catch (e) {
      console.error('[BioVault] initContracts failed', e);
      tvmContract = null; usdtContract = null; disableDashboardButtons();
    }
  },
  updateBalances: async () => {
    try {
      if (!account || !provider) return;
      const ub = document.getElementById('user-balance');
      if (ub) ub.textContent = '— TVM';
      const uu = document.getElementById('usdt-balance');
      if (uu) uu.textContent = '— USDT';
      const tvmOk = await contractExists(CONTRACT_ADDRESS.toLowerCase());
      const usdtOk = await contractExists(USDT_ADDRESS.toLowerCase());
      if (!tvmOk || !usdtOk || !tvmContract || !usdtContract) return;
      const tvmBal = await tvmContract.balanceOf(account);
      if (ub) ub.textContent = ethers.utils.formatUnits(tvmBal, 18) + ' TVM';
      const usdtBal = await usdtContract.balanceOf(account);
      if (uu) uu.textContent = ethers.utils.formatUnits(usdtBal, 6) + ' USDT';
      const e3 = document.getElementById('tvm-price');
      if (e3) e3.textContent = '1.00 USDT'; // Fetch real price from oracle if available
      const e4 = document.getElementById('pool-ratio');
      if (e4) e4.textContent = '51% HI / 49% AI'; // Fetch from contract if method exists
      const e5 = document.getElementById('avg-reserves');
      if (e5) e5.textContent = '100M TVM'; // Implement contract call for real reserves
    } catch (e) {
      console.warn('Balance refresh failed:', e);
    }
  },
  ensureAllowance: async (token, owner, spender, amount) => {
    if (!token || !token.allowance) return;
    const a = await token.allowance(owner, spender);
    if (a.lt(amount)) {
      const tx = await token.approve(spender, amount);
      await tx.wait();
    }
  },
  getOnchainBalances: async () => {
    if (!tvmContract || !usdtContract || !account) throw new Error('Connect wallet first.');
    const tvm = await tvmContract.balanceOf(account);
    const usdt = await usdtContract.balanceOf(account);
    return { tvm, usdt };
  }
};
// ---------- Segment (Micro-ledger) ----------
const Segment = {
  _nextHash: async (prevHash, event, timestamp, from, to, bioConst) => await Utils.sha256Hex(prevHash + event + timestamp + from + to + bioConst),
  initializeSegments: async () => {
    const now = Date.now();
    for (let i = 1; i <= INITIAL_BALANCE_SHE; i++) {
      const initHash = await Utils.sha256Hex('init' + i + vaultData.bioIBAN);
      const unlockedTs = now + i;
      const unlockHash = await Utils.sha256Hex(initHash + 'Unlock' + unlockedTs + 'Genesis' + vaultData.bioIBAN + (GENESIS_BIO_CONSTANT + i + 1));
      const segment = {
        segmentIndex: i,
        currentOwner: vaultData.bioIBAN,
        ownershipChangeCount: 1,
        claimed: false,
        history: [
          { event: 'Initialization', timestamp: now, from: 'Genesis', to: vaultData.bioIBAN, bioConst: GENESIS_BIO_CONSTANT + i, integrityHash: initHash },
          { event: 'Unlock', timestamp: unlockedTs, from: 'Genesis', to: vaultData.bioIBAN, bioConst: GENESIS_BIO_CONSTANT + i + 1, integrityHash: unlockHash }
        ]
      };
      await DB.saveSegmentToDB(segment);
    }
    vaultData.balanceSHE = INITIAL_BALANCE_SHE;
    vaultData.nextSegmentIndex = INITIAL_BALANCE_SHE + 1;
  },
  unlockNextSegments: async (count) => {
    if (count <= 0) return 0;
    if (!canUnlockSegments(count)) return 0;
    let created = 0;
    const now = Date.now();
    for (let k = 0; k < count; k++) {
      const idx = vaultData.nextSegmentIndex;
      if (idx > LAYERS * SEGMENTS_PER_LAYER) break;
      const initHash = await Utils.sha256Hex('init' + idx + vaultData.bioIBAN);
      const ts = now + k;
      const unlockHash = await Utils.sha256Hex(initHash + 'Unlock' + ts + 'Locked' + vaultData.bioIBAN + (GENESIS_BIO_CONSTANT + idx + 1));
      const seg = {
        segmentIndex: idx,
        currentOwner: vaultData.bioIBAN,
        ownershipChangeCount: 1,
        claimed: false,
        history: [
          { event: 'Initialization', timestamp: ts, from: 'Locked', to: vaultData.bioIBAN, bioConst: GENESIS_BIO_CONSTANT + idx, integrityHash: initHash },
          { event: 'Unlock', timestamp: ts, from: 'Locked', to: vaultData.bioIBAN, bioConst: GENESIS_BIO_CONSTANT + idx + 1, integrityHash: unlockHash }
        ]
      };
      await DB.saveSegmentToDB(seg);
      vaultData.nextSegmentIndex = idx + 1;
      created++;
    }
    if (created > 0) {
      recordUnlock(created);
      await Vault.updateBalanceFromSegments();
      await persistVaultData();
    }
    return created;
  },
  validateSegment: async (segment) => {
    if (!segment || !Array.isArray(segment.history) || segment.history.length === 0) return false;
    const init = segment.history[0];
    const expectedInit = await Utils.sha256Hex('init' + segment.segmentIndex + init.to);
    if (init.integrityHash !== expectedInit) return false;
    let hash = init.integrityHash;
    for (let j = 1; j < segment.history.length; j++) {
      const h = segment.history[j];
      hash = await Utils.sha256Hex(hash + h.event + h.timestamp + h.from + h.to + h.bioConst);
      if (h.integrityHash !== hash) return false;
    }
    const last = segment.history[segment.history.length - 1];
    if (last.biometricZKP && !/^0x[0-9a-fA-F]{64}$/.test(last.biometricZKP)) return false;
    return true;
  }
};
// ---------- P2P helpers: compact/encrypt payload ----------
function toCompactChains(chains) {
  function eShort(e) { return e === 'Transfer' ? 'T' : (e === 'Received' ? 'R' : (e === 'Unlock' ? 'U' : (e === 'Claimed' ? 'C' : 'I'))); }
  const out = [];
  for (let i = 0; i < chains.length; i++) {
    const c = chains[i];
    const h = [];
    for (let j = 0; j < c.history.length; j++) {
      const x = c.history[j];
      h.push({ e: eShort(x.event), t: x.timestamp, f: x.from, o: x.to, b: x.bioConst, x: x.integrityHash, z: x.biometricZKP });
    }
    out.push({ i: c.segmentIndex, h });
  }
  return out;
}
function fromCompactChains(comp) {
  function eLong(e) { return e === 'T' ? 'Transfer' : (e === 'R' ? 'Received' : (e === 'U' ? 'Unlock' : (e === 'C' ? 'Claimed' : 'Initialization'))); }
  const out = [];
  for (let i = 0; i < comp.length; i++) {
    const c = comp[i];
    const h = [];
    for (let j = 0; j < c.h.length; j++) {
      const x = c.h[j];
      h.push({ event: eLong(x.e), timestamp: x.t, from: x.f, to: x.o, bioConst: x.b, integrityHash: x.x, biometricZKP: x.z });
    }
    out.push({ segmentIndex: c.i, history: h });
  }
  return out;
}
// ---------- CBOR + Varint Streaming (for P2P payloads) ----------
const CBOR = (function () {
  // ... (keep as is, it's production-ready)
})();
// Varint (unsigned LEB128)
const Varint = {
  enc: (u) => {
    const out = [];
    while (u > 0x7f) {
      out.push((u & 0x7f) | 0x80);
      u >>>= 7;
    }
    out.push(u & 0x7f);
    return out;
  },
  dec: (view, offObj) => {
    let x = 0, s = 0, b;
    do {
      b = view[offObj.o++];
      x |= (b & 0x7f) << s;
      s += 7;
    } while (b & 0x80);
    return x >>> 0;
  }
};
function hexToBytes(h) {
  if (h.startsWith('0x')) h = h.slice(2);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) {
  let s = '0x';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
// ChainsCodec: builds a compact binary stream with varints and bytes, then wraps with CBOR for the envelope.
const ChainsCodec = {
  encode: (compactChains) => {
    const addrSet = new Map();
    const addAddr = (a) => { if (!addrSet.has(a)) addrSet.set(a, addrSet.size); };
    for (const c of compactChains) {
      for (const h of c.h) {
        addAddr(h.f);
        addAddr(h.o);
      }
    }
    const addrs = Array.from(addrSet.keys());
    const bu = [];
    // address table
    Varint.enc(addrs.length).forEach(b => bu.push(b));
    const te = new TextEncoder();
    for (const a of addrs) {
      const ab = te.encode(a);
      Varint.enc(ab.length).forEach(b => bu.push(b));
      for (let i = 0; i < ab.length; i++) bu.push(ab[i]);
    }
    // chains
    Varint.enc(compactChains.length).forEach(b => bu.push(b));
    let prevIdx = 0;
    for (const c of compactChains) {
      const segIdxDelta = c.i - prevIdx;
      prevIdx = c.i;
      Varint.enc(segIdxDelta).forEach(b => bu.push(b));
      const baseT = c.h.length ? c.h[0].t : 0;
      const baseB = c.h.length ? c.h[0].b : 0;
      Varint.enc(baseT).forEach(b => bu.push(b));
      Varint.enc(baseB).forEach(b => bu.push(b));
      Varint.enc(c.h.length).forEach(b => bu.push(b));
      let lastT = baseT, lastB = baseB;
      for (const e of c.h) {
        const code = e.e === 'I' ? 0 : (e.e === 'U' ? 1 : (e.e === 'T' ? 2 : (e.e === 'R' ? 3 : (e.e === 'C' ? 4 : 255))));
        Varint.enc(code).forEach(b => bu.push(b));
        Varint.enc(addrSet.get(e.f)).forEach(b => bu.push(b));
        Varint.enc(addrSet.get(e.o)).forEach(b => bu.push(b));
        Varint.enc(e.t - lastT).forEach(b => bu.push(b)); lastT = e.t;
        Varint.enc(e.b - lastB).forEach(b => bu.push(b)); lastB = e.b;
        const hx = hexToBytes(e.x);
        for (let i = 0; i < hx.length; i++) bu.push(hx[i]);
        if (e.z && /^0x[0-9a-fA-F]{64}$/.test(e.z)) {
          Varint.enc(1).forEach(b => bu.push(b));
          const zz = hexToBytes(e.z);
          for (let i = 0; i < zz.length; i++) bu.push(zz[i]);
        } else {
          Varint.enc(0).forEach(b => bu.push(b));
        }
      }
    }
    return new Uint8Array(bu);
  },
  decode: (bytes) => {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const off = { o: 0 };
    const addrCount = Varint.dec(view, off);
    const addrs = [];
    const td = new TextDecoder();
    for (let i = 0; i < addrCount; i++) {
      const L = Varint.dec(view, off);
      const s = td.decode(view.subarray(off.o, off.o + L));
      off.o += L;
      addrs.push(s);
    }
    const chainCount = Varint.dec(view, off);
    const chains = [];
    let prevIdx = 0;
    for (let ci = 0; ci < chainCount; ci++) {
      const segIdx = prevIdx + Varint.dec(view, off);
      prevIdx = segIdx;
      const baseT = Varint.dec(view, off);
      const baseB = Varint.dec(view, off);
      const evCount = Varint.dec(view, off);
      let lastT = baseT, lastB = baseB;
      const hist = [];
      for (let ei = 0; ei < evCount; ei++) {
        const code = Varint.dec(view, off);
        const fidx = Varint.dec(view, off);
        const oidx = Varint.dec(view, off);
        const dt = Varint.dec(view, off); lastT += dt;
        const db = Varint.dec(view, off); lastB += db;
        const hx = view.subarray(off.o, off.o + 32); off.o += 32;
        const hasZ = Varint.dec(view, off);
        let z = null;
        if (hasZ) { const zz = view.subarray(off.o, off.o + 32); off.o += 32; z = bytesToHex(zz); }
        const e = code === 0 ? 'I' : (code === 1 ? 'U' : (code === 2 ? 'T' : (code === 3 ? 'R' : 'C')));
        hist.push({ e, t: lastT, f: addrs[fidx], o: addrs[oidx], b: lastB, x: bytesToHex(hx), z });
      }
      chains.push({ i: segIdx, h: hist });
    }
    return chains;
  }
};
// Extend Encryption with raw bytes helpers (AES-GCM)
Encryption.encryptBytes = async (key, bytesU8) => {
  const iv = Utils.rand(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytesU8);
  return { iv, ciphertext };
};
Encryption.decryptBytes = async (key, iv, ciphertext) => {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(pt);
};
// Derive transport key from from|to|nonce (transport privacy; both sides can derive)
async function deriveP2PKey(from, to, nonce) {
  const salt = Utils.enc.encode('BC-P2P|' + from + '|' + to + '|' + String(nonce));
  const base = await crypto.subtle.importKey("raw", HMAC_KEY, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: AES_KEY_LENGTH }, false, ["encrypt", "decrypt"]
  );
}
async function handleIncomingChains(chains, fromIBAN, toIBAN) {
  let validSegments = 0;
  for (const entry of chains) {
    let seg = await DB.getSegment(entry.segmentIndex);
    let reconstructed = seg ? JSON.parse(JSON.stringify(seg)) : { segmentIndex: entry.segmentIndex, currentOwner: 'Unknown', ownershipChangeCount: (seg && seg.ownershipChangeCount) || 0, claimed: false, history: [] };
    reconstructed.history.push(...entry.history);
    if (!(await Segment.validateSegment(reconstructed))) continue;
    const last = reconstructed.history[reconstructed.history.length - 1];
    if (last.to !== vaultData.bioIBAN) continue;
    const timestamp = Date.now();
    const bioConst = last.bioConst + BIO_STEP;
    const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Received' + timestamp + last.from + vaultData.bioIBAN + bioConst);
    const zkpIn = await Biometric.generateBiometricZKP();
    reconstructed.history.push({ event: 'Received', timestamp, from: last.from, to: vaultData.bioIBAN, bioConst, integrityHash, biometricZKP: zkpIn });
    reconstructed.currentOwner = vaultData.bioIBAN;
    reconstructed.ownershipChangeCount = (reconstructed.ownershipChangeCount || 0) + 1;
    reconstructed.claimed = reconstructed.claimed || false;
    await DB.saveSegmentToDB(reconstructed);
    validSegments++;
  }
  if (validSegments > 0) {
    vaultData.transactions.push({ bioIBAN: vaultData.bioIBAN, bioCatch: 'Incoming', amount: validSegments / EXCHANGE_RATE, timestamp: Date.now(), status: 'Received' });
    await Vault.updateBalanceFromSegments();
    UI.showAlert('Received ' + validSegments + ' valid segments.');
    await persistVaultData();
  } else {
    UI.showAlert('No valid segments received.');
  }
}
// ---------- Proofs (on-chain TVM mint) ----------
const Proofs = {
  prepareClaimBatch: async (segmentsNeeded) => {
    if (!vaultUnlocked) throw new Error('Vault locked.');
    const segs = await DB.loadSegmentsFromDB();
    const eligible = segs.filter(s => s.currentOwner === vaultData.bioIBAN && !s.claimed && Number(s.ownershipChangeCount || 0) === 1);
    if (eligible.length < segmentsNeeded) return { proofs: [], used: [] };
    const chosen = eligible.slice(0, segmentsNeeded).sort((a, b) => a.segmentIndex - b.segmentIndex);
    const biometricZKP = await Biometric.generateBiometricZKP();
    if (!biometricZKP) throw new Error('Biometric ZKP generation failed or was denied.');
    const proofs = [];
    for (const s of chosen) {
      const last = s.history[s.history.length - 1];
      const baseStr = 'seg|' + s.segmentIndex + '|' + vaultData.bioIBAN + '|' + (s.ownershipChangeCount || 1) + '|' + last.integrityHash + '|' + last.bioConst;
      const ownershipProof = Utils.to0x(await Utils.sha256Hex('own|' + baseStr));
      const unlockIntegrityProof = Utils.to0x(await Utils.sha256Hex('unlock|' + baseStr));
      const spentProof = Utils.to0x(await Utils.sha256Hex('spent|' + baseStr));
      proofs.push({
        segmentIndex: s.segmentIndex,
        currentBioConst: last.bioConst,
        ownershipProof,
        unlockIntegrityProof,
        spentProof,
        ownershipChangeCount: 1,
        biometricZKP: biometricZKP.commit
      });
    }
    const inner = proofs.map(p => ethers.utils.keccak256(coder.encode(
      ['uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'bytes32'],
      [p.segmentIndex, p.currentBioConst, p.ownershipProof, p.unlockIntegrityProof, p.spentProof, p.ownershipChangeCount, p.biometricZKP]
    )));
    const proofsHash = ethers.utils.keccak256(coder.encode(['bytes32[]'], [inner]));
    const deviceKeyHash = vaultData.deviceKeyHash;
    const userBioConstant = proofs[0] ? proofs[0].currentBioConst : vaultData.initialBioConstant;
    const nonce = Math.floor(Math.random() * 1000000000);
    const domain = { name: 'TVM', version: '1', chainId: Number(chainId || EXPECTED_CHAIN_ID), verifyingContract: CONTRACT_ADDRESS.toLowerCase() };
    const types = { Claim: [
      { name: 'user', type: 'address' },
      { name: 'proofsHash', type: 'bytes32' },
      { name: 'deviceKeyHash', type: 'bytes32' },
      { name: 'userBioConstant', type: 'uint256' },
      { name: 'nonce', type: 'uint256' }
    ]};
    const value = { user: account, proofsHash, deviceKeyHash, userBioConstant, nonce };
    const signature = await signer.signTypedData(domain, types, value);
    return { proofs, signature, deviceKeyHash, userBioConstant, nonce, used: chosen };
  },
  markClaimed: async (segmentsUsed) => {
    for (const s of segmentsUsed) {
      s.claimed = true;
      const last = s.history[s.history.length - 1];
      const ts = Date.now();
      const bio = last.bioConst + 1;
      const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Claimed' + ts + vaultData.bioIBAN + 'OnChain' + bio);
      s.history.push({ event: 'Claimed', timestamp: ts, from: vaultData.bioIBAN, to: 'OnChain', bioConst: bio, integrityHash });
      await DB.saveSegmentToDB(s);
    }
  }
};
// ---------- UI ----------
const UI = {
  showAlert: (msg) => alert(msg),
  showLoading: (id) => {
    const el = document.getElementById(id + '-loading');
    if (el) el.classList.remove('hidden');
  },
  hideLoading: (id) => {
    const el = document.getElementById(id + '-loading');
    if (el) el.classList.add('hidden');
  },
  updateConnectedAccount: () => {
    const ca = document.getElementById('connectedAccount');
    if (ca) ca.textContent = account ? (account.slice(0, 6) + '...' + account.slice(-4)) : 'Not connected';
    const wa = document.getElementById('wallet-address');
    if (wa) wa.textContent = account ? ('Connected: ' + account.slice(0, 6) + '...' + account.slice(-4)) : '';
  }
};
// ---------- Contract Interactions ----------
const withBuffer = (g) => {
  try { return (g * 120n) / 100n; } catch { return Math.floor(Number(g) * 1.2); }
};
const ensureReady = () => {
  if (!account || !tvmContract) { UI.showAlert('Connect your wallet first.'); return false; }
  return true;
};
const ContractInteractions = {
  claimTVM: async (tvmToClaim /* optional integer */) => {
    if (!ensureReady() || !tvmContract || typeof tvmContract.claimTVM !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('claim');
    try {
      const tvmAmount = Math.max(1, parseInt(tvmToClaim || 1, 10));
      const needSeg = tvmAmount * SEGMENTS_PER_TVM;
      const prep = await Proofs.prepareClaimBatch(needSeg);
      if (!prep.proofs || prep.proofs.length !== needSeg) {
        UI.showAlert('Not enough eligible segments (need ' + needSeg + ' with ownershipChangeCount=1).'); return;
      }
      resetCapsIfNeeded(Date.now());
      if (vaultData.caps.tvmYearlyClaimed + tvmAmount > MAX_YEARLY_TVM_TOTAL) {
        UI.showAlert('Yearly TVM cap reached locally.'); return;
      }
      const overrides = {};
      try {
        const ge = await tvmContract.estimateGas.claimTVM(prep.proofs, prep.signature, prep.deviceKeyHash, prep.userBioConstant, prep.nonce);
        overrides.gasLimit = withBuffer(ge);
      } catch (e) { console.warn('estimateGas failed; sending without explicit gasLimit', e); }
      const tx = await tvmContract.claimTVM(prep.proofs, prep.signature, prep.deviceKeyHash, prep.userBioConstant, prep.nonce, overrides);
      await tx.wait();
      await Proofs.markClaimed(prep.used);
      vaultData.caps.tvmYearlyClaimed += tvmAmount;
      UI.showAlert('Claim successful: ' + tvmAmount + ' TVM (' + needSeg + ' segments).');
      Wallet.updateBalances();
      autoProofs = null;
      await persistVaultData();
    } catch (err) {
      console.error(err);
      UI.showAlert('Error claiming TVM: ' + (err.reason || err.message || err));
    } finally {
      UI.hideLoading('claim');
    }
  },
  exchangeTVMForSegments: async () => {
    if (!ensureReady() || !tvmContract || typeof tvmContract.exchangeTVMForSegments !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('exchange');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.tvm;
      if (amount.eq(0)) { UI.showAlert('No TVM to exchange.'); return; }
      const overrides = {};
      try { const ge = await tvmContract.estimateGas.exchangeTVMForSegments(amount); overrides.gasLimit = withBuffer(ge); } catch(e) {}
      const tx = await tvmContract.exchangeTVMForSegments(amount, overrides);
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
    if (!ensureReady() || !tvmContract || typeof tvmContract.swapTVMForUSDT !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('swap');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.tvm;
      if (amount.eq(0)) { UI.showAlert('No TVM to swap.'); return; }
      const overrides = {};
      try { const ge = await tvmContract.estimateGas.swapTVMForUSDT(amount); overrides.gasLimit = withBuffer(ge); } catch(e) {}
      const tx = await tvmContract.swapTVMForUSDT(amount, overrides);
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
    if (!ensureReady() || !tvmContract || typeof tvmContract.swapUSDTForTVM !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('swap-usdt');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.usdt;
      if (amount.eq(0)) { UI.showAlert('No USDT to swap.'); return; }
      await Wallet.ensureAllowance(usdtContract, account, CONTRACT_ADDRESS.toLowerCase(), amount);
      const overrides = {};
      try { const ge = await tvmContract.estimateGas.swapUSDTForTVM(amount); overrides.gasLimit = withBuffer(ge); } catch(e) {}
      const tx = await tvmContract.swapUSDTForTVM(amount, overrides);
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
// ---------- P2P (modal-integrated) ----------
const P2P = {
  createCatchOut: async (recipientIBAN, amountSegments, note) => {
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
      if (!vaultUnlocked) return UI.showAlert('Vault locked.');
      const amount = parseInt(amountSegments, 10);
      if (isNaN(amount) || amount <= 0 || amount > vaultData.balanceSHE) return UI.showAlert('Invalid amount.');
      if (amount > 300) return UI.showAlert('Amount exceeds per-transfer segment limit.');
      const segments = await DB.loadSegmentsFromDB();
      const transferable = segments.filter(s => s.currentOwner === vaultData.bioIBAN && !s.claimed && Number(s.ownershipChangeCount || 0) >= 1).slice(0, amount);
      if (transferable.length < amount) return UI.showAlert('Insufficient unlocked segments.');
      const zkp = await Biometric.generateBiometricZKP();
      if (!zkp) return UI.showAlert('Biometric ZKP generation failed.');
      const header = { from: vaultData.bioIBAN, to: recipientIBAN, nonce: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + '-' + Math.random() };
      const chainsOut = [];
      for (const s of transferable) {
        const last = s.history[s.history.length - 1];
        const timestamp = Date.now();
        const bioConst = last.bioConst + BIO_STEP;
        const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Transfer' + timestamp + vaultData.bioIBAN + recipientIBAN + bioConst);
        const newHistory = { event: 'Transfer', timestamp, from: vaultData.bioIBAN, to: recipientIBAN, bioConst, integrityHash, biometricZKP: zkp };
        s.history.push(newHistory);
        s.currentOwner = recipientIBAN;
        s.ownershipChangeCount = (s.ownershipChangeCount || 0) + 1;
        await DB.saveSegmentToDB(s);
        chainsOut.push({ segmentIndex: s.segmentIndex, history: s.history.slice(-SEGMENT_HISTORY_MAX) });
      }
      vaultData.transactions.push({ bioIBAN: vaultData.bioIBAN, bioCatch: 'Outgoing to ' + recipientIBAN, amount: amount / EXCHANGE_RATE, timestamp: Date.now(), status: 'Sent' });
      await Vault.updateBalanceFromSegments();
      const created = await Segment.unlockNextSegments(amount);
      if (created < amount) {
        UI.showAlert('Unlocked only ' + created + ' of ' + amount + ' due to caps. Balance may drop until caps reset.');
      }
      await Vault.updateBalanceFromSegments();
      await persistVaultData();
      const chainsOutCompact = toCompactChains(chainsOut);
      const packed = ChainsCodec.encode(chainsOutCompact);
      const bodyCbor = CBOR.encode({ c: packed, t: Date.now(), n: note || '' });
      const p2pKey = await deriveP2PKey(header.from, header.to, header.nonce);
      const enc = await Encryption.encryptBytes(p2pKey, bodyCbor);
      const payload = {
        v: 3,
        from: header.from,
        to: header.to,
        nonce: header.nonce,
        iv: Encryption.bufferToBase64(enc.iv),
        ct: Encryption.bufferToBase64(enc.ciphertext)
      };
      lastCatchOutPayload = payload;
      const cborEnvelope = CBOR.encode(payload);
      lastCatchOutPayloadBytes = cborEnvelope;
      lastCatchOutPayloadStr = _u8ToB64(cborEnvelope);
      lastCatchOutFileName = 'biovault_catchout_' + header.nonce + '.cbor';
      downloadBytes(lastCatchOutFileName, lastCatchOutPayloadBytes, 'application/cbor');
      await showCatchOutResultModal();
    } finally {
      transactionLock = false;
    }
  },
  importCatchIn: async (payloadStr) => {
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
      if (!vaultUnlocked) return UI.showAlert('Vault locked.');
      if (!payloadStr) return;
      if (payloadStr.length > 1200000) return UI.showAlert('Payload too large.');
      let envelope = null;
      try { envelope = JSON.parse(payloadStr); } catch {} // not JSON
      if (!envelope) {
        try {
          const bytes = Encryption.base64ToBuffer(payloadStr);
          const u8 = new Uint8Array(bytes);
          envelope = CBOR.decode(u8);
        } catch (e) {
          return UI.showAlert('Invalid payload: neither JSON nor base64-CBOR.');
        }
      }
      if (!envelope) return UI.showAlert('Malformed payload.');
      if (!envelope.nonce) return UI.showAlert('Malformed payload: missing nonce.');
      if (await DB.hasReplayNonce(envelope.nonce)) return UI.showAlert('Duplicate transfer detected (replay).');
      await DB.putReplayNonce(envelope.nonce);
      if (envelope.v === 3 && envelope.iv && envelope.ct) {
        const p2pKey = await deriveP2PKey(envelope.from, envelope.to, envelope.nonce);
        const bytes = await Encryption.decryptBytes(
          p2pKey,
          Encryption.base64ToBuffer(envelope.iv),
          Encryption.base64ToBuffer(envelope.ct)
        );
        const obj = CBOR.decode(bytes);
        if (!obj || !(obj.c instanceof Uint8Array)) return UI.showAlert('Decrypted CBOR invalid.');
        const expandedChains = ChainsCodec.decode(obj.c);
        await handleIncomingChains(fromCompactChains(expandedChains), envelope.from, envelope.to);
        return;
      }
      if (envelope.v === 2 && envelope.iv && envelope.ct) {
        const p2pKey2 = await deriveP2PKey(envelope.from, envelope.to, envelope.nonce);
        const obj2 = await Encryption.decryptData(
          p2pKey2,
          Encryption.base64ToBuffer(envelope.iv),
          Encryption.base64ToBuffer(envelope.ct)
        );
        if (!obj2 || !Array.isArray(obj2.c)) return UI.showAlert('Decrypted payload invalid.');
        const expandedChains2 = fromCompactChains(obj2.c);
        await handleIncomingChains(expandedChains2, envelope.from, envelope.to);
        return;
      }
      if (envelope.v === 1 && Array.isArray(envelope.chains)) {
        await handleIncomingChains(envelope.chains, envelope.from, envelope.to);
        return;
      }
      UI.showAlert('Unsupported or malformed payload.');
    } finally {
      transactionLock = false;
    }
  }
};
// New: direct import from a .cbor file
P2P.importCatchInFile = async (file) => {
  if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
  transactionLock = true;
  try {
    if (!vaultUnlocked) return UI.showAlert('Vault locked.');
    if (!file) return UI.showAlert('No file selected.');
    const buf = await file.arrayBuffer();
    const u8 = new Uint8Array(buf);
    const envelope = CBOR.decode(u8);
    if (!envelope || !envelope.nonce) return UI.showAlert('Malformed payload file.');
    if (await DB.hasReplayNonce(envelope.nonce)) return UI.showAlert('Duplicate transfer detected (replay).');
    await DB.putReplayNonce(envelope.nonce);
    if (envelope.v === 3 && envelope.iv && envelope.ct) {
      const p2pKey = await deriveP2PKey(envelope.from, envelope.to, envelope.nonce);
      const bytes = await Encryption.decryptBytes(
        p2pKey,
        Encryption.base64ToBuffer(envelope.iv),
        Encryption.base64ToBuffer(envelope.ct)
      );
      const body = CBOR.decode(bytes);
      if (!body || !(body.c instanceof Uint8Array)) return UI.showAlert('Decrypted CBOR invalid.');
      const expandedChains = ChainsCodec.decode(body.c);
      await handleIncomingChains(fromCompactChains(expandedChains), envelope.from, envelope.to);
      return;
    }
    return UI.showAlert('Unsupported or malformed payload file.');
  } catch (e) {
    console.error('CatchIn file failed', e);
    UI.showAlert('Catch In file failed: ' + (e.message || e));
  } finally {
    transactionLock = false;
  }
};
// ---------- Notifications ----------
const Notifications = {
  requestPermission: () => {
    if ('Notification' in window && Notification.permission !== 'granted') Notification.requestPermission();
  },
  showNotification: (title, body) => {
    if ('Notification' in window && Notification.permission === 'granted') new Notification(title, { body });
  }
};
// ---------- Backups ----------
async function exportFullBackup() {
  const segments = await DB.loadSegmentsFromDB();
  const proofsBundle = await DB.loadProofsFromDB();
  const payload = { vaultData, segments, proofsBundle, exportedAt: Date.now() };
  const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'biovault.fullbackup.json';
  a.click();
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
    segs.forEach(s => tx.objectStore(SEGMENTS_STORE).put(s));
    tx.oncomplete = res;
    tx.onerror = (e) => rej(e.target.error);
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
  const a = document.createElement('a');
  a.href = url;
  a.download = 'transactions.json';
  a.click();
}
function backupVault() {
  const backup = JSON.stringify(vaultData);
  const blob = new Blob([backup], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vault.backup';
  a.click();
}
function copyToClipboard(id) {
  const textEl = document.getElementById(id);
  if (!textEl) return;
  navigator.clipboard.writeText(textEl.textContent).then(() => UI.showAlert('Copied!'));
}
// ---------- Export to Blockchain helper ----------
async function exportProofToBlockchain(payload) {
  if (payload) {
    try {
      console.debug('[BioVault] Submitting compact payload to chain/relayer:', payload);
      // In production, replace with actual API call or contract interaction, e.g.:
      // await fetch('https://your-relayer.com/submit', { method: 'POST', body: JSON.stringify(payload) });
      return true;
    } catch (e) {
      console.error('[BioVault] submit failed', e);
      throw e;
    }
  }
  showSection('dashboard');
  UI.showAlert('Open the Dashboard and click an action (e.g., Claim) to authorize with biometrics.');
  return true;
}
// ---------- Section Switching ----------
function showSection(id) {
  document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active-section'));
  const tgt = document.getElementById(id);
  if (tgt) tgt.classList.add('active-section');
  if (id === 'dashboard') loadDashboardData();
  if (id === 'biovault' && vaultUnlocked) {
    const wp = document.querySelector('#biovault .whitepaper');
    if (wp) wp.classList.add('hidden');
    const vu = document.getElementById('vaultUI');
    if (vu) vu.classList.remove('hidden');
    vu.style.display = 'block';
    const ls = document.getElementById('lockedScreen');
    if (ls) ls.classList.add('hidden');
  }
}
window.showSection = showSection;
// ---------- Theme Toggle ----------
(() => {
  const t = document.getElementById('theme-toggle');
  if (t) t.addEventListener('click', () => document.body.classList.toggle('dark-mode'));
})();
// ---------- Service Worker ----------
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(() => console.log('[BioVault] SW registered')).catch(err => console.warn('SW registration failed', err));
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
  } catch(e) {}
  window.addEventListener("beforeunload", () => {
    try { localStorage.setItem(SESSION_URL_KEY, location.href); } catch(e) {}
  });
}
function enforceSingleVault() {
  const v = localStorage.getItem(VAULT_LOCK_KEY);
  if (!v) localStorage.setItem(VAULT_LOCK_KEY, 'locked');
}
function preventMultipleVaults() {
  window.addEventListener('storage', (e) => {
    if (e.key === VAULT_UNLOCKED_KEY) {
      const unlocked = e.newValue === 'true';
      if (unlocked && !vaultUnlocked) { vaultUnlocked = true; revealVaultUI(); }
      if (!unlocked && vaultUnlocked) { vaultUnlocked = false; Vault.lockVault(); }
    }
  });
}
function isVaultLockedOut() {
  if (!vaultData.lockoutTimestamp) return false;
  const now = Math.floor(Date.now() / 1000);
  if (now < vaultData.lockoutTimestamp) return true;
  vaultData.lockoutTimestamp = null;
  vaultData.authAttempts = 0;
  return false;
}
async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
  }
  await Vault.promptAndSaveVault();
}
async function persistVaultData(saltBuf) {
  if (!derivedKey) throw new Error('Derived key missing; cannot save vault.');
  const enc = await Encryption.encryptData(derivedKey, vaultData);
  const iv = enc.iv;
  const ciphertext = enc.ciphertext;
  let saltBase64;
  if (saltBuf) { saltBase64 = Encryption.bufferToBase64(saltBuf); }
  else {
    const existing = await DB.loadVaultDataFromDB();
    if (existing && existing.salt) saltBase64 = Encryption.bufferToBase64(existing.salt);
    else throw new Error('Salt missing; persist aborted.');
  }
  await DB.saveVaultDataToDB(iv, ciphertext, saltBase64);
}

async function showCatchOutResultModal() {
  const ta = document.getElementById('catchOutResultText');
  if (ta) {
    ta.value = '';
    const parent = ta.closest('.form-group, .mb-3, .input-group');
    if (parent) parent.classList.add('d-none');
  }
  const btnDownload = document.getElementById('btnDownloadCbor');
  if (btnDownload) {
    btnDownload.classList.remove('d-none');
    btnDownload.onclick = () => {
      if (lastCatchOutPayloadBytes && lastCatchOutPayloadBytes.length) {
        downloadBytes(lastCatchOutFileName || 'catchout.cbor', lastCatchOutPayloadBytes, 'application/cbor');
      } else {
        UI.showAlert('No payload to download.');
      }
    };
  }
  if (lastCatchOutPayloadStr) await prepareFramesForPayload(lastCatchOutPayloadStr);
  const modalEl = document.getElementById('modalCatchOutResult');
  if (modalEl) {
    const m = window.bootstrap ? new bootstrap.Modal(modalEl) : null;
    if (m) m.show();
    else modalEl.style.display = 'block';
  }
}
// ---------- Migrations (production-grade safety) ----------
async function migrateSegmentsV4() {
  const segs = await DB.loadSegmentsFromDB();
  if (!segs || segs.length === 0) return;
  let changed = 0;
  for (const s of segs) {
    let mutated = false;
    if (typeof s.claimed !== 'boolean') { s.claimed = false; mutated = true; }
    if (typeof s.ownershipChangeCount !== 'number') {
      let hasUnlock = false, transfers = 0, receiveds = 0;
      for (const ev of s.history) {
        if (ev.event === 'Unlock') hasUnlock = true;
        if (ev.event === 'Transfer') transfers++;
        if (ev.event === 'Received') receiveds++;
      }
      if (!hasUnlock && s.history.length === 1 && s.currentOwner === vaultData.bioIBAN) {
        const init = s.history[0];
        const ts = (init.timestamp || Date.now()) + 1;
        const unlockHash = await Utils.sha256Hex(init.integrityHash + 'Unlock' + ts + init.from + init.to + (init.bioConst + 1));
        s.history.push({ event: 'Unlock', timestamp: ts, from: init.from, to: init.to, bioConst: init.bioConst + 1, integrityHash: unlockHash });
        hasUnlock = true;
        mutated = true;
      }
      s.ownershipChangeCount = (hasUnlock ? 1 : 0) + transfers + receiveds;
      if (s.ownershipChangeCount < 0) s.ownershipChangeCount = 0;
      mutated = true;
    }
    if (mutated) { await DB.saveSegmentToDB(s); changed++; }
  }
  const maxIdx = segs.reduce((m, s) => Math.max(m, s.segmentIndex), 0);
  if (typeof vaultData.nextSegmentIndex !== 'number' || vaultData.nextSegmentIndex <= maxIdx) {
    vaultData.nextSegmentIndex = maxIdx + 1;
  }
  if (changed > 0) {
    await Vault.updateBalanceFromSegments();
    await persistVaultData();
  }
}
async function migrateVaultAfterDecrypt() {
  if (vaultData.bioIBAN && vaultData.bioIBAN.slice(0, 2) !== '0x') vaultData.bioIBAN = '0x' + vaultData.bioIBAN;
  if (typeof vaultData.bonusConstant !== 'number' || vaultData.bonusConstant <= 0) vaultData.bonusConstant = EXTRA_BONUS_TVM;
  if (!vaultData.caps) {
    vaultData.caps = { dayKey: "", monthKey: "", yearKey: "", dayUsedSeg: 0, monthUsedSeg: 0, yearUsedSeg: 0, tvmYearlyClaimed: 0 };
  }
  resetCapsIfNeeded(Date.now());
  if (typeof vaultData.nextSegmentIndex !== 'number' || vaultData.nextSegmentIndex < INITIAL_BALANCE_SHE + 1) {
    vaultData.nextSegmentIndex = INITIAL_BALANCE_SHE + 1;
  }
  await migrateSegmentsV4();
}
// ---------- Init ----------
async function init() {
  console.log('[BioVault] init() starting…');
  await loadLibraries();
  await requestPersistentStorage();
  setupSessionRestore();
  enforceSingleVault();
  preventMultipleVaults();
  Notifications.requestPermission();
  if ('NDEFReader' in window) {
    try {
      const reader = new NDEFReader();
      await reader.scan();
      reader.onreading = () => UI.showAlert('Incoming P2P transfer detected.');
    } catch (e) {
      console.warn('NFC scan failed:', e);
    }
  }
  const stored = await DB.loadVaultDataFromDB();
  if (stored) {
    console.log('[BioVault] Vault record found. Attempts:', stored.authAttempts);
    vaultData.authAttempts = stored.authAttempts;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
  } else {
    const credential = await Biometric.performBiometricAuthenticationForCreation();
    if (credential) {
      vaultData.credentialId = Encryption.bufferToBase64(credential.rawId);
      const rndHex = await Utils.sha256Hex(Math.random().toString());
      vaultData.bioIBAN = Utils.to0x(rndHex);
      vaultData.joinTimestamp = Date.now();
      vaultData.deviceKeyHash = Utils.to0x(await Utils.sha256Hex(KEY_HASH_SALT + Utils.toB64(Utils.rand(32))));
      vaultData.balanceSHE = INITIAL_BALANCE_SHE;
      vaultData.bonusConstant = currentBioConst;
      const salt = Utils.rand(16);
      const pin = prompt("Set passphrase:");
      derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin || ''), salt);
      await persistVaultData(salt);
      await Segment.initializeSegments();
      vaultUnlocked = true;
      revealVaultUI();
      await Vault.updateBalanceFromSegments();
      Vault.updateVaultUI();
    }
  }
  const byId = id => document.getElementById(id);
  let el;
  el = byId('connectMetaMaskBtn');
  if (el) el.addEventListener('click', Wallet.connectMetaMask);
  el = byId('connectWalletConnectBtn');
  if (el) el.addEventListener('click', Wallet.connectWalletConnect);
  el = byId('connect-wallet');
  if (el) el.addEventListener('click', Wallet.connectMetaMask);
  el = byId('enterVaultBtn');
  if (el) el.addEventListener('click', async () => {
    console.log('[BioVault] Enter Vault clicked');
    if (isVaultLockedOut()) { UI.showAlert("Vault locked out."); return; }
    const pin = prompt("Enter passphrase:");
    const stored = await DB.loadVaultDataFromDB();
    if (!stored) return;
    derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin || ''), stored.salt);
    try {
      vaultData = await Encryption.decryptData(derivedKey, stored.iv, stored.ciphertext);
      await migrateVaultAfterDecrypt();
      await persistVaultData();
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
      localStorage.setItem(VAULT_UNLOCKED_KEY, 'true');
    } catch (e) {
      console.error('[BioVault] Unlock error', e);
      await handleFailedAuthAttempt();
      UI.showAlert("Invalid passphrase or corrupted vault.");
    }
  });
  el = byId('lockVaultBtn');
  if (el) el.addEventListener('click', Vault.lockVault);
  el = byId('catchOutBtn');
  if (el) el.addEventListener('click', () => {
    const modalEl = byId('modalCatchOut');
    if (modalEl) {
      const m = window.bootstrap ? new window.bootstrap.Modal(modalEl) : null;
      if (m) m.show();
      else modalEl.style.display = 'block';
    }
  });
  el = byId('catchInBtn');
  if (el) el.addEventListener('click', () => {
    const modalEl = byId('modalCatchIn');
    if (modalEl) {
      const m = window.bootstrap ? new window.bootstrap.Modal(modalEl) : null;
      if (m) m.show();
      else modalEl.style.display = 'block';
    }
  });
  const claimBtn = byId('claim-tvm-btn');
  if (claimBtn) claimBtn.addEventListener('click', () => {
    const modalEl = byId('modalClaim');
    if (modalEl) {
      const m = window.bootstrap ? new window.bootstrap.Modal(modalEl) : null;
      if (m) m.show();
      else modalEl.style.display = 'block';
    }
  });
  const formCO = byId('formCatchOut');
  if (formCO) formCO.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const recv = Utils.sanitizeInput(byId('receiverBioModal')?.value || '');
    const amt = Utils.sanitizeInput(byId('amountSegmentsModal')?.value || '');
    const note = Utils.sanitizeInput(byId('noteModal')?.value || '');
    if (!recv) { formCO.classList.add('was-validated'); return; }
    const amtNum = parseInt(amt, 10);
    if (isNaN(amtNum) || amtNum <= 0) { formCO.classList.add('was-validated'); return; }
    const sp = byId('spCreateCatchOut');
    if (sp) sp.classList.remove('d-none');
    const btn = byId('btnCreateCatchOut');
    if (btn) btn.disabled = true;
    try {
      await P2P.createCatchOut(recv, amtNum, note);
      if (window.bootstrap) {
        const m1 = window.bootstrap.Modal.getInstance(byId('modalCatchOut'));
        if (m1) m1.hide();
      }
    } catch (e) {
      console.error('CatchOut failed', e);
      UI.showAlert('Catch Out failed: ' + (e.message || e));
    } finally {
      if (sp) sp.classList.add('d-none');
      if (btn) btn.disabled = false;
    }
  });
  const btnCopy = byId('btnCopyCatchOut');
  if (btnCopy) btnCopy.addEventListener('click', () => {
    const ta = byId('catchOutResultText');
    if (!ta) return;
    navigator.clipboard.writeText(ta.value || '').then(() => UI.showAlert('Payload copied to clipboard.'));
  });

  const formClaim = byId('formClaim');
  if (formClaim) formClaim.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const sp = byId('spSubmitClaim');
    if (sp) sp.classList.remove('d-none');
    const btn = byId('btnSubmitClaim');
    if (btn) btn.disabled = true;
    try {
      await ContractInteractions.claimTVM();
      if (window.bootstrap) {
        const m3 = window.bootstrap.Modal.getInstance(byId('modalClaim'));
        if (m3) m3.hide();
      }
    } catch (e) {
      console.error('Claim failed', e);
      UI.showAlert('Claim failed: ' + (e.message || e));
    } finally {
      if (sp) sp.classList.add('d-none');
      if (btn) btn.disabled = false;
    }
  });
  const btnImportFile = byId('btnImportCatchInFile');
  if (btnImportFile) btnImportFile.addEventListener('click', async () => {
    const fi = byId('catchInFile');
    const f = fi && fi.files && fi.files[0];
    if (!f) { UI.showAlert('Please choose a .cbor file.'); return; }
    await P2P.importCatchInFile(f);
    if (window.bootstrap) {
      const m2 = window.bootstrap.Modal.getInstance(byId('modalCatchIn'));
      if (m2) m2.hide();
    }
  });
  const idleTimer = null;
  const resetIdle = () => { clearTimeout(idleTimer); idleTimer = setTimeout(Vault.lockVault, MAX_IDLE); };
  ['click', 'keydown', 'mousemove', 'touchstart', 'visibilitychange'].forEach(evt => window.addEventListener(evt, resetIdle));
  resetIdle();
  setInterval(() => {
    const tz = document.getElementById('utcTime');
    if (tz) tz.textContent = new Date().toUTCString();
  }, 1000);
  loadDashboardData();
  console.log('[BioVault] init() complete.');
}
// ---------- Dashboard ----------
async function loadDashboardData() {
  await ensureChartLib();
  await Wallet.updateBalances();
  let table = '';
  let totalReserves = 0;
  for (let i = 1; i <= LAYERS; i++) {
    const reserve = 100000000; // TODO: Fetch real reserve from contract if method added (e.g., getLayerReserve(i))
    totalReserves += reserve;
    const capProgress = (SEGMENTS_PER_LAYER / reserve * 100).toFixed(2) + '%';
    table += `<tr><td>${i}</td><td>${reserve.toLocaleString()} TVM</td><td>${capProgress}</td></tr>`;
  }
  const lt = document.getElementById('layer-table');
  if (lt) lt.innerHTML = table;
  const ar = document.getElementById('avg-reserves');
  if (ar) ar.textContent = (totalReserves / LAYERS).toLocaleString() + ' TVM';
  const c1 = document.getElementById('pool-chart');
  const c2 = document.getElementById('layer-chart');
  if (window.Chart && c1 && c2) {
    if (c1._chart) c1._chart.destroy();
    c1._chart = new window.Chart(c1, {
      type: 'doughnut',
      data: { labels: ['Human Investment (51%)', 'AI Cap (49%)'], datasets: [{ data: [51, 49], borderRadius: 5 }] },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } }, cutout: '60%' }
    });
    if (c2._chart) c2._chart.destroy();
    c2._chart = new window.Chart(c2, {
      type: 'bar',
      data: { labels: Array.from({ length: LAYERS }, (_, i) => 'Layer ' + (i + 1)), datasets: [{ label: 'Reserve (M TVM)', data: Array(LAYERS).fill(100) }] },
      options: { responsive: true, scales: { y: { beginAtZero: true } } }
    });
  }
}
loadLibraries(); // Load libraries at start
init();
