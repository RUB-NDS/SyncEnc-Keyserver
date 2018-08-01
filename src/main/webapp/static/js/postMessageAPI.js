/**
 * method that will be triggered if the iframe responds via the postMessage-API
 * first check if the origin is the expected one, otherwise it should be rejected
 *
 * @param event the event that triggered this message call, contains the data send via postMessage
 */
const receiveMessage = function (event) {
    if (event.origin !== partnerDomain && event.origin !== 'https://dom.dpdns.ovh:8000' &&
       event.origin !== 'https://argon.cloud.nds.rub.de:8080' &&
       event.origin !== 'https://localhost:8080') {
       console.log("Message received from unallowed origin:" + event.origin);
        return;
    }
    console.log("Message received");
    postMessageOrigin = event.origin;

    // check if the task is to get the private key
    if (event.data.task === 'getPrivKey') {
        outputToDiv('Connecting to KMS to get privKey');
        username = event.data.username;
        password = event.data.password;
        /*
            if the user wants the private key the KMS needs to be opened in a popup window
            this is because the idp has a xframe-options which is set to sameorigin, so it can not be loaded in iframe
         */
        const myWindow = window.open(baseUrl + '?user=' + username, 'MsgWindow'
            , `width=${(screen.width * 0.75)}, height=${(screen.height * 0.75)}`);

        /*
            this part is to check if the address of the popup has changed
            if it has changed then it should be checked if it contains the secret needed for the key derivation
         */
        const intervalHandle = setInterval(function () {
            // try catch needed otherwise each time the check with location.href is made a SecurityError is thrown
            try {
                if (myWindow.location.href.match(/ACS/)) {
                    const inner = myWindow.document.body.innerHTML
                        .replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">', '')
                        .replace('</pre>', '');
                    const json = JSON.parse(inner);
                    clearInterval(intervalHandle);
                    myWindow.close();
                    // outputToDiv(actualAddress.split('#secret=')[1]);
                    setTimeout(function () {
                        if (json.error !== undefined) {
                            errorOccurred('', json.error, json.todo);
                        } else if (json.task === 'unwrap') {
                            salt = json.salt;
                            unwrapKey(json.wrappedKey.replace(/\s/g, '+'));
                        } else if (json.task === 'sendPubKey') {
                            access_token = json.accesstoken;
                            sendPublicKeyToKMS();
                        } else {
                            errorOccurred('', 'nothing expected happend', 'contact system administrator');
                        }
                    }, 1000);
                }
            } catch (e) {

            }
        }, 500);


    } else if (event.data.task === 'getPubKey') {
        // if the pubKey should be requested, check if the id or mail is given
        if (event.data.id !== undefined && event.data.id.match(regExpID)) {
            outputToDiv('Connecting to KMS to get pubKey with ID: ' + event.data.id);
            requestPublicKeyWithIDFromKMS(event.data.id);

        } else if (event.data.username !== undefined && event.data.username.match(regExpUsername)) {
            outputToDiv('Connecting to KMS to get pubKey of the user with the username: ' + event.data.username);
            requestPublicKeyWithUsernameFromKMS(event.data.username);
            // if neither the mail nor the id is given in proper way return an error via the postMessage API
        } else {
            const messageError = {
                'data': 'error',
                'info': 'neither mail nor keyNameId given in a proper way.',
            };

            responseToParent(messageError);
        }
    } else {
        outputToDiv('Sorry. Got no correct input.');
        const messageError = {
            'data': 'error',
            'info': 'no input if public key or private key should be requested',
        };

        responseToParent(messageError);
    }
};
// add a listener for the postMessage-API event
window.addEventListener('message', receiveMessage, false);

