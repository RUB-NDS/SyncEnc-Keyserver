// defines the crypto variable
const crypto = window.crypto || window.msCrypto;

// the salt and the secret needed for the password derivation
let salt = null;
let secret = 'aIB8eCQa19Zv6R1LLFsp7odaPQ+fnLgLzRcJ2TF95gM=';
let password = null;
let username = null;


// variables for the communication with the KMS
let xhr = null;
const baseUrl = '/KMS';
// the access token for the communication with the KMS
let access_token;

// variables for the commmunication via PostMessage
let postMessageOrigin = null;
const partnerDomain = 'https://neon.cloud.nds.rub.de';
const partnerFile = '/masterThesisIntegrator/index.html';
const partnerFullPathToFile = partnerDomain + partnerFile;

// variable for writing to the div
const divId = 'myDiv';
let div = null;

const regExpID = new RegExp('^[a-zA-Z0-9]+={0,2}$');
const regExpUsername = new RegExp('^[\\w_\\d]+$');

/**
 * variables for the Web Crypto API use
 */
// solving the challenge
let encryptedChall = null;
let decryptedChall = null;
// imported keys & the export format
let importedPubKey = null;
let importedPrivKey = null;
let wrappedKeyFromKMS = null;
const formatExport = 'jwk';
//generated key
let generatedPubKey = null;
let generatedPrivKey = null;
// key to wrap the privKey
let derivedKey = null;
// exported keys
let exportedPubKeyReadyToSend = null;
let wrappedPrivKey = null;

// variables for the symmetric algorithm used for wrapping and unwrapping the private key
let IV = null;
const symmAlgo = 'AES-GCM';
const symmUsage = ['wrapKey', 'unwrapKey'];
const symmKeyLength = 256;
const symmExtractable = false;

// variables for the key derivation function used to derive the wrapping key
const kdfAlgo = 'PBKDF2';
let kdfSalt = null;
const kdfIterationen = 1000;
const kdfImportedKeyUsage = ['deriveKey'];
const kdfImportedKeyExtractable = false;
const hashAlgoKDF = 'SHA-512';

// variables for the asymmetric algorithm used for encryption and decryption
const asymmAlgo = 'RSA-OAEP';
const asymmExtractable = true;
const asymmUsage = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
const asymmAlgoModulusLength = 4096;
const asymmAlgoPublicKey = new Uint8Array([0x01, 0x00, 0x01]);
const hashAlgoRSA = 'SHA-256';
