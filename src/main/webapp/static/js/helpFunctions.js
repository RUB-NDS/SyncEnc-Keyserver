/**
 * convert the provided string to arrayBuffer
 *
 * @param byteString that needs to be converted
 * @returns {*} null if error occurred, the arrayBuffer otherwise
 */
const stringToArrayBuffer = function (byteString) {
    try {
        let byteArray = new Int8Array(byteString.length);
        for (let i = 0; i < byteString.length; i++) {
            byteArray[i] = byteString.codePointAt(i);
        }
        return byteArray;
    } catch (e) {
        return null;
    }
};

/**
 * convert the provided arrayBuffer to a string
 *
 * @param arrayBuffer that needs to be converted
 * @returns {*} null if an error occurred, the string otherwise
 */
const arrayBufferToString = function (arrayBuffer) {
    try {
        const byteArray = new Uint8Array(arrayBuffer);
        let byteString = '';
        for (let i = 0; i < byteArray.byteLength; i++) {
            byteString += String.fromCodePoint(byteArray[i]);
        }
        return byteString;
    } catch (e) {
        return null;
    }
};

/**
 * encode the provided string
 * encode the string with the TextEncoded if it exists
 * otherwise it uses the provided algorithm which does the same
 *
 * @param str the string that needs to be encoded
 * @returns {*} returns the encoded string as arrayBuffer
 */
const textEncode = function (str) {
    if (window.TextEncoder) {
        return new TextEncoder('utf-8').encode(str);
    }
    const utf8 = unescape(encodeURIComponent(str));
    const result = new Uint8Array(utf8.length);
    for (let i = 0; i < utf8.length; i++) {
        result[i] = utf8.charCodeAt(i);
    }
    return result;
};

/**
 * send response via PostMessage-API to the parent
 * postMessageOrigin contains the origin that should get the message
 *
 * @param message that should be send via PostMessage
 */
const responseToParent = function (message) {
    parent.postMessage(message, postMessageOrigin);
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
        div.innerHTML = '';
    }
    div.innerHTML += message + '<br/>';
};

/**
 * write errors to the div
 * sends an error to the parent element
 *
 * @param func contains the name of the function where the error occurred
 * @param errorMessage describes what is the problem
 * @param todostring describes what is to do
 */
const errorOccurred = function (func, errorMessage, todostring) {
    const errorString = `Error in ${func}.<br/>${errorMessage}<br/>${todostring}<br/><br/>`;
    outputToDiv(errorString);
    const messageError = {
        'data': 'error',
        'info': 'An error occured on the server.',
    };

    responseToParent(messageError);
};

