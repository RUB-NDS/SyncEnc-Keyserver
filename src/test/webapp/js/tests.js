QUnit.test('testing helpfunctions: stringToArrayBuffer', function (assert) {
    const inputEmpty = '';
    const expectedOutputEmpty = new Int8Array();
    
    assert.deepEqual(stringToArrayBuffer(inputEmpty), expectedOutputEmpty, '');

    const inputShort = 'myShortInput';
    const expectedOutputShort = new Int8Array([109, 121, 83, 104, 111, 114, 116, 73, 110, 112, 117, 116]);
    assert.deepEqual(stringToArrayBuffer(inputShort), expectedOutputShort, '');

    const inputLong = 'myLongLongInputmyLongLongInputmyLongLongInputmyLongLongInputmyLongLongInputmyLongLongInput';
    const expectedOutputLong = new Int8Array([109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117,
        116, 109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117, 116, 109, 121, 76, 111, 110,
        103, 76, 111, 110, 103, 73, 110, 112, 117, 116, 109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73,
        110, 112, 117, 116, 109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117, 116, 109, 121,
        76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117, 116]);
    assert.deepEqual(expectedOutputLong, stringToArrayBuffer(inputLong), '');

    const inputBadNull = null;
    assert.equal(stringToArrayBuffer(inputBadNull), null, '');
});

QUnit.test('testing helpfunctions: arrayBufferToString', function (assert) {
    const inputEmpty = new Int8Array();
    const expectedOutputEmpty = '';
    assert.equal(arrayBufferToString(inputEmpty), expectedOutputEmpty, '');

    const inputShort = new Int8Array([109, 121, 83, 104, 111, 114, 116, 73, 110, 112, 117, 116]);
    const expectedOutputShort = 'myShortInput';
    assert.equal(arrayBufferToString(inputShort), expectedOutputShort, '');

    const inputLong = new Int8Array([109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117,
        116, 109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117, 116, 109, 121, 76, 111, 110,
        103, 76, 111, 110, 103, 73, 110, 112, 117, 116, 109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73,
        110, 112, 117, 116, 109, 121, 76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117, 116, 109, 121,
        76, 111, 110, 103, 76, 111, 110, 103, 73, 110, 112, 117, 116]);
    const expectedOutputLong = 'myLongLongInputmyLongLongInputmyLongLongInputmyLongLongInputmyLongLongInputmyLongLongInput';
    assert.equal(arrayBufferToString(inputLong), expectedOutputLong, '');

    const inputBadNull = null;
    const expectedOutputBadNull = '';
    assert.equal(arrayBufferToString(inputBadNull), expectedOutputBadNull, '');

    const inputBadEmpty = '';
    const expectedOutputBadEmpty = '';
    assert.equal(arrayBufferToString(inputBadEmpty), expectedOutputBadEmpty, '');
});

QUnit.test('testing helpfunctions: stringToArrayBuffer and arrayBufferToString', function (assert) {
    const inputEmpty = '';
    assert.equal(arrayBufferToString(stringToArrayBuffer(inputEmpty)), inputEmpty, '');

    const inputShort = 'myShortInput';
    assert.equal(arrayBufferToString(stringToArrayBuffer(inputShort)), inputShort, '');

    const inputLong = 'myLongLongInputmyLongLongInputmyLongLongInputmyLongLongInputmyLongLongInputmyLongLongInput';
    assert.equal(arrayBufferToString(stringToArrayBuffer(inputLong)), inputLong, '');
});


QUnit.test('testing kmsCommunication: isErrorInResponse', function (assert) {
    const responseWithError = {'error': 'an error'};
    assert.ok(isErrorInResponse(responseWithError), '');

    const responseWithoutError = {'fine': 'no error'};
    assert.notOk(isErrorInResponse(responseWithoutError), '');
});


QUnit.test('testing webCrypto: generateKeyPair', function (assert) {
    const done = assert.async(1);
    generateKeyPair().then(function () {
        assert.notDeepEqual(generatedPrivKey, null, '');
        done();
    });
});

QUnit.test('testing webCrypto: exportPubKeyAsJWK', function (assert) {
    const done = assert.async(1);
    exportPubKeyAsJWK().then(function () {
        assert.notDeepEqual(exportedPubKeyReadyToSend, null, '');
        done();
    });
});

QUnit.test('testing webCrypto: importPublicKey', function (assert) {
    const done = assert.async(1);
    const pubKeyString = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlIjoiQVFBQiIsImV4dCI6dHJ1ZSwia2V5X29wcyI6WyJlbmNyeXB0Il0s' +
        'Imt0eSI6IlJTQSIsIm4iOiJ4UlFVbEFIdWRLN0piR0RsYmhaMGVXMjltdlFUMTlGQWl6T2NhRTQxdHVEV2F6NGdyNk80a1VUdjJXaXotX' +
        '3dpQ3pHeVZrRmI4VlpTVFhvQ01sVVVvcmtzVDRWb2xxNWtaU2R5RHZiMzdXVDduelJfcjBlLUNVMy01ZEw0TzJwSU9kVHBfdkt0bmU2MG' +
        'kzc0ZmV3RaeVFSQnVTODd0Yzk5LTFJa2h6cnhUbWJkczhiNWZQZTBZek5EZ1NhVDMyM0pYdmhocU5PYy1RRTlIM1hhRVhyYmNWcFBzX0R' +
        'FQ190c0xnN2NEb3Q0TWFCeGtuMmpQSHNkOGtSRGNJMG9yd2JMamVadzFzWkJldVROZFdKZDFGNFROTWdaN2VwY3lVeVFocG5oeldRemRM' +
        'cG1PRjQ4VExacHQyMDVTTDBNNVl1WXNmOGhXaVphOVJPcUkwTWd4NzhtXzFlVmtvXzNEZmt1VUhLQUdUdkVOanJmLS1mcTBnTVhMUHZBd' +
        'Us4cXVwLUYxY1RkNkt2eHhTa2Fwb04xV0hFV1c5eEJHVzZsaS1fSmkzOXBHMHhOcjUzMkstWVJtMkxIZXFXUjhJYVhDZG45aTZJX255Y0' +
        'tRQ0xmdEpESHNZRHFmYXBfUncyUjV3Z3VfRXlUTkZON2xXU2NqeFh3LUNnWG1QYmw4RG5kRFF4a2hlNDdMRHJsaTAwc0FZT2lDLUdvN3N' +
        'rME5JcTFPUHFfRjZfZEJnWl92aXdwbkViX0lOX3ByMjhFdkVtLXBRbFJ0NzhMeXVzTU5hVlczWUFzWWVMbENrUFc0MVA3MERRcmVIQ05a' +
        'TFRJaW5USXFBcWNNdkxrTWZPcWZ0eVRQUFN4RWt4SGtwUEI4SUwxY281VjlpNHhKcUhteU9SX3JtRUl4T29ldW9SZ19DVSJ9';

    importPublicKey(pubKeyString).then(function () {
        assert.equal(importedPubKey.algorithm.name, 'RSA-OAEP', '');
        assert.equal(importedPubKey.algorithm.hash.name, 'SHA-256', '');
        // assert.equal(importedPubKey.algorithm.modulusLength, 4096, '');
        // assert.deepEqual(importedPubKey.algorithm.publicExponent, new Uint8Array([1, 0, 1]), '');
        done();
    });
});

QUnit.test('testing webCrypto: rsaEncrypt and rsaDecrypt', function (assert) {
    const done = assert.async(1);
    const challenge = btoa('challenge');
    const challBuffer = stringToArrayBuffer(atob(challenge));
    rsaEncrypt(challBuffer).then(function (encrypted) {
        if (encrypted === null) {
            console.log('failed');
            assert.ok(false, 'encrypted is null');
            done();
        }
        rsaDecrypt(stringToArrayBuffer(atob(encrypted))).then(function (decrypted) {
            if (decrypted === null) {
                assert.ok(false, 'decrypted is null');
                done();
            }
            assert.equal(decrypted, challenge, '');
            done();
        });
    });

});

QUnit.test('testing webCrypto: encryptChallenge and solveChallenge', function (assert) {
    const done = assert.async(1);
    const challenge = btoa('challenge');
    encryptChallenge(challenge).then(function () {
        solveChallenge(encryptedChall).then(function () {
            assert.equal(decryptedChall, challenge, '');
            done();
        });
    });
});

QUnit.test('testing webCrypto: deriveSymmKey', function (assert) {
    const done = assert.async(1);
    nonce = btoa('nonce');
    secret = btoa('secret');
    const expectedKey = {
        'algorithm': {
            'length': 256,
            'name': 'AES-GCM',
        },
        'extractable': false,
        'type': 'secret',
        'usages': [
            'wrapKey',
            'unwrapKey',
        ],
    };
    deriveSymmKey('password').then(function () {
        assert.equal(derivedKey.algorithm.length, expectedKey.algorithm.length, '');
        assert.equal(derivedKey.algorithm.name, expectedKey.algorithm.name, '');
        assert.equal(derivedKey.extractable, expectedKey.extractable, '');
        assert.equal(derivedKey.type, expectedKey.type, '');
        assert.deepEqual(derivedKey.usages, expectedKey.usages, '');
        done();
    });
});

QUnit.test('testing webCrypto: wrapPrivKeyWithAES', function (assert) {
    const done = assert.async(1);
    wrapPrivKeyWithAES().then(function () {
        assert.ok(wrappedPrivKey.match(/^[0-9A-Za-z\+\/]{16}\|\|[0-9A-Za-z\+\/=]{4296}$/), '');
        done();
    });
});

QUnit.test('testing webCrypto: unwrapPrivKeyWithAES', function (assert) {
    const done = assert.async(1);
    wrappedKeyFromKMS = wrappedPrivKey;
    unwrapPrivKeyWithAES().then(function () {
        assert.deepEqual(importedPrivKey, generatedPrivKey, '');
        done();
    });
});
