/**
 * checks if the provided response json object has an error
 *
 * @param response json object that needs to be checked
 * @returns {boolean} true if contains error, false otherwise
 */
const isErrorInResponse = function (response) {
    return response.error !== undefined;
};

/**
 * create the XMLHttpRequest
 * sets the Content-type header (needed for XHR)
 *
 * @param method the method used for the XHR-request
 * @param url addition to the base_url (e.g. the api call 'get_public_key')
 */
const openXHR = function (method, url) {
    xhr = new XMLHttpRequest();
    xhr.open(method, baseUrl + url);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
};

/**
 * opens the XHR-request without a bearer token
 * just calls the openXHR method
 *
 * @param method the method used for the XHR-request
 * @param url addition to the base_url (e.g. the api call 'get_public_key')
 */
const openXHRWithOutBearer = function (method, url) {
    openXHR(method, url);
};

/**
 * opens the XHR-request with a bearer token
 * the access token is defined in access_token (variable.js)
 * just calls the openXHR method
 *
 * @param method the method used for the XHR-request
 * @param url addition to the base_url (e.g. the api call 'get_public_key')
 */
const openXHRWithBearer = function (method, url) {
    openXHR(method, url);
    xhr.setRequestHeader('Authorization', 'BEARER ' + access_token);
};

/**
 * called after XHR request that sends the public key
 * checks the server response
 * calls errorOccurred if server responds with an error
 * otherwise takes the challenge and pass it to solve challenge
 * the result will be send to the KMS
 */
const sentPublicKeyToKMS = function () {
    const response = JSON.parse(xhr.responseText);
    if (isErrorInResponse(response)) {
        errorOccurred('sentPublicKeyToKMS', response.error, response.todo);
    } else {
        solveChallenge(response.challenge).then(function () {
            solveChallengeAtKMS();
        });
    }
};

/**
 * called after XHR request that sends the public key
 * checks the server response which should contain the wrappedPrivKey and the salt used for key derivation
 * calls errorOccurred if server responds with an error
 */
const gotWrappedKey = function () {
    const response = JSON.parse(xhr.responseText);
    if (isErrorInResponse((response))) {
        errorOccurred('gotWrappedKey', response.error, response.todo);
    } else {
        salt = response.salt;
        unwrapKey(response.wrappedKey.replace(/\s/g, '+'));
    }
};

/**
 * unwrap the provided key
 * takes the salt and asks for the password to derive the key
 * after key derivation the key used to unwrap the private key
 * the imported key will be send via the postMessage-API
 * @param wrappedKey
 */
const unwrapKey = function (wrappedKey) {
    wrappedKeyFromKMS = wrappedKey;
    deriveSymmKey().then(function () {
        unwrapPrivKeyWithAES().then(function () {
            outputToDiv('the private key is now unwrapped and can be used.');
            const messagePrivKey = {
                'data': 'privKey',
                'key': importedPrivKey,
            };

            responseToParent(messagePrivKey);
        }, function (error) {
            errorOccurred('gotWrappedKey', error
                , 'the private key can not be unwrapped. Please try again or contact system administrator');
        });
    });
};

/**
 * method that trigger the XHR request to get the wrappedKey
 * the wrapped key is accessable at the base_url
 */
const getWrappedKey = function () {
    openXHRWithOutBearer('POST', '/ACS');
    xhr.addEventListener('load', gotWrappedKey);
    xhr.send();
};

/**
 * called after XHR request that sends the solved challenge
 * checks the server response which should contain the salt used for key derivation
 * calls errorOccurred if server responds with an error
 * otherwise takes the salt and asks for the password to derive the key
 * after key derivation the key used to wrap the private key
 */
const solvedChallenge = function () {
    const response = JSON.parse(xhr.responseText);
    if (isErrorInResponse(response)) {
        errorOccurred('solvedChallenge', response.error, response.todo);
    } else {
        salt = response.salt;
        deriveSymmKey().then(function () {
            wrapPrivKeyWithAES().then(function () {
                sendWrappedKeyToKMS();
            }, function (error) {
                errorOccurred('solvedChallenge', error
                    , 'the private key can not be wrapped. Please try again or contact system administrator');
            });
        });
    }
};

/**
 * method that trigger the XHR request to send the solved challenge
 * needs to be send to 'solve_challenge'
 */
const solveChallengeAtKMS = function () {
    openXHRWithBearer('POST', '/solve_challenge');
    xhr.addEventListener('load', solvedChallenge);
    xhr.send('solvedChallenge=' + decryptedChall);
};

/**
 * method that trigger the XHR request to send the solved challenge
 * needs to be send to 'send_pub_key'
 */
const sendPublicKeyToKMS = function () {
    exportPubKeyAsJWK().then(function () {
        openXHRWithBearer('POST', '/send_pub_key');
        xhr.addEventListener('load', sentPublicKeyToKMS);
        xhr.send('pubKey=' + exportedPubKeyReadyToSend);
    });
};

/**
 * called after XHR request that sends the solved challenge
 * checks the server response which should just contain no error
 * calls errorOccurred if server responds with an error
 * otherwise the generated private key will be send via the postMessage-API
 */
const sentWrappedKey = function () {
    const response = JSON.parse(xhr.responseText);
    if (isErrorInResponse(response)) {
        errorOccurred('sentWrappedKey', response.error, response.todo);
    } else {
        outputToDiv('the private key was wrapped and saved at the KMS. From now on it can be accessed via the KMS.');
        const messagePrivKey = {
            'data': 'privKey',
            'key': generatedPrivKey,
        };

        responseToParent(messagePrivKey);
    }
};

/**
 * method that trigger the XHR request to send the wrapped key
 * needs to be send to 'send_wrapped_key'
 */
const sendWrappedKeyToKMS = function () {
    openXHRWithBearer('POST', '/send_wrapped_key');
    xhr.addEventListener('load', sentWrappedKey);
    xhr.send('wrappedKey=' + wrappedPrivKey);
};

/**
 * called after XHR request that asks for the public key (by email or keyNameId)
 * checks the server response which should just contain no error
 * calls errorOccurred and answer via postMessage to parent if server responds with an error
 * otherwise the requested private key will be imported and send via postMessage-API
 */
const getPublicKeyByKMS = function () {
    const response = JSON.parse(xhr.responseText);
    if (isErrorInResponse(response)) {
        errorOccurred('getPublicKeyByKMS', response.error, response.todo);
    } else {
        importPublicKey(response.pubkey).then(function () {
            const messagePubKey = {
                'data': 'pubKey',
                'key': importedPubKey,
                'keyNameId': response.keyNameId,
            };

            responseToParent(messagePubKey);
        }).catch(function (error) {
            errorOccurred('getPublicKeyByKMS', error, 'contact system administrator');
        });
    }
};

/**
 * method that trigger the XHR request to request the public key with the provided keynameid
 * needs to be send to 'get_public_key'
 *
 * @param keynameid the keynameid of the public key
 */
const requestPublicKeyWithIDFromKMS = function (keynameid) {
    openXHRWithOutBearer('GET', '/get_public_key?keynameid=' + keynameid);
    xhr.addEventListener('load', getPublicKeyByKMS);
    xhr.send();
};

/**
 * method that trigger the XHR request to request the public key from the user with the provided mail
 * needs to be send to 'get_public_key'
 *
 * @param mail the mail of the user
 */
const requestPublicKeyWithUsernameFromKMS = function (usern) {
    openXHRWithOutBearer('GET', '/get_public_key?username=' + usern);
    xhr.addEventListener('load', getPublicKeyByKMS);
    xhr.send();
};

