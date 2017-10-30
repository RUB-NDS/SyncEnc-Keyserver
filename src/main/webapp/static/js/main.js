// variables for postMessage-API communication
const partnerDomain = 'https://neon.cloud.nds.rub.de';
const partnerFile = '/integrated';
const partnerFullPathToFile = partnerDomain + partnerFile;
// the variables for the iframe the kms communicator is loaded in
const iframeId = 'postMessageIframe';
const iframe = document.getElementById(iframeId);
const iframeContentWindow = iframe.contentWindow;
// in this variable it will be defined whcih key was request
let waitFor = null;
// variables for the div where the outputs are made
const divId = 'myDiv';
let div = null;
// variables used for resizing the iframe
const smaller = 'smaller';
const bigger = 'bigger';

/**
 * resize the iframe which contains the kms communicator
 * in case of communication with the kms the iframe is resized to a bigger size
 * if the communication is ended the iframe is made smaller
 *
 * @param to defines if the iframe should be made smaller or bigger
 */
const resizeIframe = function (to) {
    if (to === bigger) {
        iframe.style.width = '100%';
        iframe.style.height = '50%';
        // if not making it bigger make it smaller
    } else {
        // if (to == smaller)
        iframe.style.width = '10%';
        iframe.style.height = '10%';
    }
};

/**
 * write messages to the div on the page
 * so the user knows what is going on
 * the message will be encoded first
 *
 * @param message the message that should be written to the div
 */
const outputToDiv = function (message) {
    if (div === null) {
        div = document.getElementById(divId);
    }
    div.innerHTML = message;
};

/**
 * called if the private key should be requested
 * the iframe will be resized and made bigger
 * the kms communicator will be triggered with the postMessage-API call
 */
const getPrivKey = function () {
    outputToDiv('Send PostMessage to get PrivKey');
    resizeIframe('bigger');
    const message = {
        'task': 'getPrivKey',
    };
    waitFor = 'privKey';
    iframeContentWindow.postMessage(message, partnerFullPathToFile);
};

/**
 * called if the public key shozld be requested with the keyNameId input
 * the iframe will be resized and made bigger
 * the kms communicator will be triggered with the postMessage-API call
 */
const getPubKey = function () {
    outputToDiv('Send PostMessage to get PubKey');
    resizeIframe('bigger');
    const message = {
        'task': 'getPubKey',
        'id': document.getElementById('idPubKey').value,
    };
    waitFor = 'pubKey';
    iframeContentWindow.postMessage(message, partnerFullPathToFile);
};

/**
 * called if the public key shozld be requested with the email input
 * the iframe will be resized and made bigger
 * the kms communicator will be triggered with the postMessage-API call
 */
const getPubKeyByUser = function () {
    outputToDiv('Send PostMessage to get PubKey');
    resizeIframe('bigger');
    const mail = document.getElementById('email').value;
    const message = {
        'task': 'getPubKey',
        'email': mail,
    };
    waitFor = 'pubKey';
    iframeContentWindow.postMessage(message, partnerFullPathToFile);
};

/**
 * method that will be triggered if the iframe responds via the postMessage-API
 * first check if the origin is the expected one, otherwise it should be rejected
 *
 * @param event the event that triggered this message call, contains the data send via postMessage
 */
const receiveMessage = function (event) {
    if (event.origin !== partnerDomain) {
        return;
    }
    /*
        check if the sent data is the one this script is waiting for
        otherwise resize the iframe, make an output for the user
     */
    if (event.data.data !== waitFor) {
        outputToDiv('Error occured while getting ' + waitFor);
        return;
    }

    // if the private key was sent, work with the private key
    if (event.data.data === 'privKey') {
        resizeIframe(smaller);
        outputToDiv('ok i got my privKey ' + event.data.key);

    // if the public key was sent, work with the public key
    } else if (event.data.data === 'pubKey') {
        resizeIframe(smaller);
        outputToDiv('ok i got the pubKey ' + event.data.key);

    // if an error was send provide the information to the user
    } else if (event.data.data === 'error') {
        outputToDiv('an error occured. ' + event.data.info);

    // if none of the above conditions fulfill something unexpected happen
    } else {
        outputToDiv('something unexpected happend.');
    }
};
// add a listener for the postMessage-API event
window.addEventListener('message', receiveMessage, false);
