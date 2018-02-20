/**
 * generates the asymmetric KeyPair
 * name of algorithm, etc are defined in variable.js
 * the two keys are assigned to the two variables generatedPrivKey and generatedPubKey
 *
 * @returns {Promise.<TResult>}
 */
const generateKeyPair = function () {
    return crypto.subtle.generateKey(
        {
            name: asymmAlgo,
            modulusLength: asymmAlgoModulusLength,
            publicExponent: asymmAlgoPublicKey,
            hash: {name: hashAlgoRSA},
        },
        asymmExtractable,
        asymmUsage
    ).then(function (keyPair) {
        generatedPrivKey = keyPair.privateKey;
        generatedPubKey = keyPair.publicKey;
    });
};

/**
 * export the generated public key
 * the format is defined in variables.js
 * result will be stringfied and base64 encoded and to exportedPubKeyReadyToSend assigned
 *
 * @param resolve called if ready
 * @param reject called if error occurred
 * @returns {Promise.<TResult>}
 */
const exportPubKey = function (resolve, reject) {
    return crypto.subtle.exportKey(
        formatExport,
        generatedPubKey
    ).then(function (exportedPubKey) {
        exportedPubKeyReadyToSend = btoa(JSON.stringify(exportedPubKey));
        resolve('Success!');
    }).catch(function (error) {
        reject('ERROR!' + error);
    });
};

/**
 * export the public key
 * checks if the pubKey and the privKey are already generated
 * if not they are generated first
 * checks also if it is already exported
 * calls resolve if ready
 * calls reject if error occurred
 *
 * @returns {Promise}
 */
const exportPubKeyAsJWK = function () {
    return new Promise(function (resolve, reject) {
        if (generatedPubKey === null || generatedPrivKey === null) {
            generateKeyPair().then(function () {
                exportPubKey(resolve, reject);
            }).catch(function (error) {
                reject('ERROR!' + error);
            });
        } else if (exportedPubKeyReadyToSend === null) {
            exportPubKey(resolve, reject);
        } else {
            resolve('Success');
        }
    });
};

/**
 * import the provided public key string, needs to be base64 decoded and json-parsed
 * name of algorithm, etc are defined in variable.js
 * result is assigned to importedPubKey
 *
 * @param publicKey base64 coded and stringified
 * @returns {Promise.<TResult>}
 */
const importPublicKey = function (publicKey) {
    return crypto.subtle.importKey(
        formatExport,
        JSON.parse(atob(publicKey)),
        {
            name: asymmAlgo,
            hash: {name: hashAlgoRSA},
        },
        true,
        ['encrypt','wrapKey']
    ).then(function (impPubKey) {
        importedPubKey = impPubKey;
    });
};

/**
 * decrypt the provided arrayBuffer
 * name of algorithm, etc are defined in variable.js
 * result is converted to a string and base64 encoded
 *
 * @param dataBuffer arrayBuffer needs to be decrypted
 * @returns {Promise.<TResult>} and the encoded decypted string
 */
const rsaDecrypt = function (dataBuffer) {
    return crypto.subtle.decrypt(
        {
            name: asymmAlgo,
            hash: {name: hashAlgoRSA},
        },
        generatedPrivKey,
        dataBuffer
    ).then(function (decrypted) {
        return btoa(arrayBufferToString(decrypted));
    }).catch(function () {
        return null;
    });
};

/**
 * solve the provided encrypted challenge
 * calls resolve if ready
 * calls reject if error occurred
 * result is assigned to decryptedChall
 *
 * @param encChall base64 encrypted challenge
 * @returns {Promise}
 */
const solveChallenge = function (encChall) {
    return new Promise(function (resolve, reject) {
        if (encChall === null) {
            reject('No encrypted challenge given.');
        } else if (generatedPrivKey === null) {
            reject('No private Key generated.');
        } else {
            const encChallBuffer = stringToArrayBuffer(atob(encChall));
            if (encChallBuffer === null) {
                reject('ERROR!');
            }
            rsaDecrypt(encChallBuffer).then(function (decrypted) {
                if (decrypted === null) {
                    reject('ERROR! decrypted is null');
                }
                decryptedChall = decrypted;
                resolve('Success');
            }).catch(function (error) {
                reject('ERROR!' + error);
            });
        }
    });
};

/**
 * encrypt the provided dataBuffer
 * name of algorithm, etc are defined in variable.js
 * result is converted to a string and base64 encoded
 *
 * @param dataBuffer arrayBuffer needs to be encrypted
 * @returns {Promise.<TResult>} and the encoded encrypted string
 */
const rsaEncrypt = function (dataBuffer) {
    return crypto.subtle.encrypt(
        {
            name: asymmAlgo,
            hash: {name: hashAlgoRSA},
        },
        generatedPubKey,
        dataBuffer
    ).then(function (encrypted) {
        return btoa(arrayBufferToString(encrypted));
    }).catch(function () {
        return null;
    });
};

/**
 * wrap the generated private key with the previous derived aes key
 * the IV is randomly generated
 * name of algorithm, etc are defined in variable.js
 * the format is defined in variables.js
 * calls resolve if ready
 * calls reject if error occurred
 * result is assigned to wrappedPrivKey, the wrappedKey contains the IV and the real wrappedKey
 * IV is needed to unwrap the wrappedKey
 *
 * @returns {Promise}
 */
const wrapPrivKeyWithAES = function () {
    return new Promise(function (resolve, reject) {
        IV = crypto.getRandomValues(new Int8Array(12));
        crypto.subtle.wrapKey(
            formatExport,
            generatedPrivKey,
            derivedKey,
            {
                name: symmAlgo,
                iv: IV,
                tagLength: 128,
            }
        ).then(function (wrapped) {
            wrappedPrivKey = btoa(arrayBufferToString(IV)) + '||' + btoa(arrayBufferToString(wrapped));
            resolve('Success!');
        }).catch(function (error) {
            reject('ERROR! ' + error);
        });
    });
};

/**
 * unwrap the key which was got from the KMS
 * it is splitted into the IV and the real wrapped key
 * both are base64 decoded and converted to arrayBuffers
 * name of algorithm, etc are defined in variable.js
 * the format is defined in variables.js
 * calls resolve if ready
 * calls reject if error occurred
 * result is assigned to importedPrivKey
 *
 * @returns {Promise}
 */
const unwrapPrivKeyWithAES = function () {
    return new Promise(function (resolve, reject) {
        const splittedWrappedKey = wrappedKeyFromKMS.split('||');
        // possible that + are replaced with a space, so if spaces are left they need to be replaced with "+"
        IV = stringToArrayBuffer(atob(splittedWrappedKey[0].replace(' ', '+')));
        const wrappedKey = stringToArrayBuffer(atob(splittedWrappedKey[1].replace(' ', '+')));
        if (IV === null || wrappedKey === null) {
            reject('ERROR!');
        }

        crypto.subtle.unwrapKey(
            formatExport,
            wrappedKey,
            derivedKey,
            {
                name: symmAlgo,
                iv: IV,
                tagLength: 128,
            },
            {
                name: asymmAlgo,
                modulusLength: asymmAlgoModulusLength,
                publicExponent: asymmAlgoPublicKey,
                hash: {name: hashAlgoRSA},
            },
            true,
            ['decrypt','unwrapKey']
        ).then(function (unwrappedKey) {
            importedPrivKey = unwrappedKey;
            resolve('Success!');
        }).catch(function (error) {
            reject('ERROR!' + error);
        });
    });
};

/**
 * encrypt the provided arrayBuffer
 * result is assigned to encryptedChall
 *
 * @param challBuffer the arrayBuffer that needs to be encrypted
 * @param resolve called if ready
 * @param reject called if error occurred
 */
const encryptChall = function (challBuffer, resolve, reject) {
    rsaEncrypt(challBuffer).then(function (encrypted) {
        if (encrypted === null) {
            reject('ERROR!: encrypted is null');
        }
        encryptedChall = encrypted;
        resolve('Success');
    }).catch(function (error) {
        reject('ERROR!' + error);
    });
};

/**
 * encrypt the provided base64 encoded string
 * calls resolve if ready
 * calls reject if error occurred
 *
 * @param inputChall base64 encoded string
 * @returns {Promise}
 */
const encryptChallenge = function (inputChall) {
    return new Promise(function (resolve, reject) {
        const challBuffer = stringToArrayBuffer(atob(inputChall));
        if (challBuffer === null) {
            reject('ERROR!');
        }
        if (inputChall === null) {
            reject('No challenge given.');
        } else if (generatedPubKey === null) {
            generateKeyPair().then(function () {
                encryptChall(challBuffer, resolve, reject);
            }).catch(function (error) {
                reject('ERROR!' + error);
            });
        } else {
            encryptChall(challBuffer, resolve, reject);
        }
    });
};

/**
 * derive a symmetric key
 * name of algorithm, etc are defined in variable.js
 * first importKey must be executed and afterwards the real deriveKey function
 * the key is derived by the user password, the secret provided by the IdP and the salt provided by the KMS
 * calls resolve if ready
 * calls reject if error occurred
 * result is assigned to derivedKey
 *
 * @returns {Promise}
 */
const deriveSymmKey = function () {
    return new Promise(function (resolve, reject) {
        const arrayBuffer = new Int8Array(textEncode((atob(secret) + password)));
        kdfSalt = new Uint8Array(textEncode(atob(salt)));
        crypto.subtle.importKey(
            'raw',
            arrayBuffer,
            {'name': kdfAlgo},
            kdfImportedKeyExtractable,
            kdfImportedKeyUsage).then(function (baseKey) {
            crypto.subtle.deriveKey(
                {
                    'name': kdfAlgo,
                    'salt': kdfSalt,
                    'iterations': kdfIterationen,
                    'hash': hashAlgoKDF,
                },
                baseKey,
                {
                    'name': symmAlgo,
                    'length': symmKeyLength,
                },
                symmExtractable,
                symmUsage
            ).then(function (derived) {
                derivedKey = derived;
                resolve('Success!');
            }).catch(function (error) {
                reject('ERROR!' + error);
            });
        }).catch(function (error) {
            reject('ERROR!' + error);
        });
    });
};
