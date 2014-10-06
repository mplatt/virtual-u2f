/**
 * Internal Token Logic
 */

/**
 * Namespace for the U2F api.
 */
window.u2f = window.u2f || {};

/**
 * Message types for messsages to/from the extension
 * @const
 * @type {{U2F_REGISTER_REQUEST: string, U2F_SIGN_REQUEST: string, U2F_REGISTER_RESPONSE: string, U2F_SIGN_RESPONSE: string}}
 */
u2f.MessageTypes = {
    'U2F_REGISTER_REQUEST': 'u2f_register_request',
    'U2F_SIGN_REQUEST': 'u2f_sign_request',
    'U2F_REGISTER_RESPONSE': 'u2f_register_response',
    'U2F_SIGN_RESPONSE': 'u2f_sign_response'
};

/**
 * Response status codes
 * @const
 * @type {{OK: number, OTHER_ERROR: number, BAD_REQUEST: number, CONFIGURATION_UNSUPPORTED: number, DEVICE_INELIGIBLE: number, TIMEOUT: number}}
 */
u2f.ErrorCodes = {
    "OK": 0,
    "OTHER_ERROR": 1,
    "BAD_REQUEST": 2,
    "CONFIGURATION_UNSUPPORTED": 3,
    "DEVICE_INELIGIBLE": 4,
    "TIMEOUT": 5
};

/**
 * Crypto Configuration
 */

// Generated through jsrsasign library (hex):
//		var secp256r1 = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
//		secp256r1.generateKeyPairHex();

/**
 * ECDSA-secp256r1 Attestation Keys
 * @const
 */
var ATTESTATION_KEY = {
    "private": "d30c9cac7da2b4a7d71b002a40a3b59a96ca508ba9c7dc617d982c4b11d952e6",
    "public": "04c3c91f252e20107b5e8deab1902098f7287071e45418b898ce5ff17ca725ae78c33cc701c0746011cbbbb58b08b61d20c05e75d501a3f8f7a1673fbe3263aebe"
};

/*
 * SHA256withECDSA Attestation Certificate
 */

// Generated through jsrsasign library:
//    var ecdsa = new KJUR.crypto.ECDSA({
//        "curve": "secp256r1"
//    });
//
//    ecdsa.setPrivateKeyHex("d30c9cac7da2b4a7d71b002a40a3b59a96ca508ba9c7dc617d982c4b11d952e6");
//    ecdsa.setPublicKeyHex("04c3c91f252e20107b5e8deab1902098f7287071e45418b898ce5ff17ca725ae78c33cc701c0746011cbbbb58b08b61d20c05e75d501a3f8f7a1673fbe3263aebe");
//
//    var tbsc = new KJUR.asn1.x509.TBSCertificate();
//    tbsc.setSerialNumberByParam({
//        "int": 1
//    });
//    tbsc.setSignatureAlgByParam({
//        "name": "SHA256withECDSA"
//    });
//    tbsc.setIssuerByParam({
//        "str": "/C=DE/O=Untrustworthy CA Organisation/ST=Berlin/CN=Untrustworthy CA"
//    });
//    tbsc.setNotBeforeByParam({
//        "str": "20140924120000Z"
//    });
//    tbsc.setNotAfterByParam({
//        "str": "21140924120000Z"
//    });
//    tbsc.setSubjectByParam({
//        "str": "/C=DE/O=virtual-u2f-manufacturer/ST=Berlin/CN=virtual-u2f-v0.0.1"
//    });
//
//    tbsc.setSubjectPublicKeyByGetKey(ecdsa);
//
//    var cert = new KJUR.asn1.x509.Certificate({
//        "tbscertobj": tbsc,
//        "prvkeyobj" : ecdsa
//    });
//
//    cert.sign();
//    console.log(cert.getPEMString());

// Resulting PEM String
//
//    -----BEGIN CERTIFICATE-----
//        MIIBtDCCAVigAwIBAgIBATAMBggqhkjOPQQDAgUAMGExCzAJBgNVBAYTAkRFMSYw
//    JAYDVQQKDB1VbnRydXN0d29ydGh5IENBIE9yZ2FuaXNhdGlvbjEPMA0GA1UECAwG
//    QmVybGluMRkwFwYDVQQDDBBVbnRydXN0d29ydGh5IENBMCIYDzIwMTQwOTI0MTIw
//    MDAwWhgPMjExNDA5MjQxMjAwMDBaMF4xCzAJBgNVBAYTAkRFMSEwHwYDVQQKDBh2
//    aXJ0dWFsLXUyZi1tYW51ZmFjdHVyZXIxDzANBgNVBAgMBkJlcmxpbjEbMBkGA1UE
//    AwwSdmlydHVhbC11MmYtdjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
//    w8kfJS4gEHtejeqxkCCY9yhwceRUGLiYzl/xfKclrnjDPMcBwHRgEcu7tYsIth0g
//    wF511QGj+PehZz++MmOuvjAMBggqhkjOPQQDAgUAA0gAMEUCIQCOuSBXofNBTxt5
//    GljmB6ukZhyTYfvEuollXIo77BBo2gIgFZCodvCAR99gjiOyKqCq0ksNScl1MwCv
//    MraQc/ChpNs=
//        -----END CERTIFICATE-----


// Resulting human readable certificate representation
// (created by openSLL: openssl x509 -noout -text -in u2f.pem)
//
//        Data:
//            Version: 3 (0x2)
//        Serial Number: 1 (0x1)
//        Signature Algorithm: ecdsa-with-SHA256
//            Issuer: C=DE, O=Untrustworthy CA Organisation, ST=Berlin, CN=Untrustworthy CA
//        Validity
//        Not Before: Sep 24 12:00:00 2014 GMT
//        Not After : Sep 24 12:00:00 2114 GMT
//        Subject: C=DE, O=virtual-u2f-manufacturer, ST=Berlin, CN=virtual-u2f-v0.0.1
//        Subject Public Key Info:
//            Public Key Algorithm: id-ecPublicKey
//        Public-Key: (256 bit)
//        pub:
//            04:c3:c9:1f:25:2e:20:10:7b:5e:8d:ea:b1:90:20:
//            98:f7:28:70:71:e4:54:18:b8:98:ce:5f:f1:7c:a7:
//            25:ae:78:c3:3c:c7:01:c0:74:60:11:cb:bb:b5:8b:
//            08:b6:1d:20:c0:5e:75:d5:01:a3:f8:f7:a1:67:3f:
//            be:32:63:ae:be
//        ASN1 OID: prime256v1
//        Signature Algorithm: ecdsa-with-SHA256
//            30:45:02:21:00:8e:b9:20:57:a1:f3:41:4f:1b:79:1a:58:e6:
//            07:ab:a4:66:1c:93:61:fb:c4:ba:89:65:5c:8a:3b:ec:10:68:
//        da:02:20:15:90:a8:76:f0:80:47:df:60:8e:23:b2:2a:a0:aa:
//            d2:4b:0d:49:c9:75:33:00:af:32:b6:90:73:f0:a1:a4:db


// Resulting ASN.1 DER certificate
// (created by openSLL: openssl x509 -outform der -in u2f.pem -out u2f.der)
//
//		30 82 01 B4 30 82 01 58 A0 03 02 01 02 02 01 01
//      30 0C 06 08 2A 86 48 CE 3D 04 03 02 05 00 30 61
//      31 0B 30 09 06 03 55 04 06 13 02 44 45 31 26 30
//      24 06 03 55 04 0A 0C 1D 55 6E 74 72 75 73 74 77
//      6F 72 74 68 79 20 43 41 20 4F 72 67 61 6E 69 73
//      61 74 69 6F 6E 31 0F 30 0D 06 03 55 04 08 0C 06
//      42 65 72 6C 69 6E 31 19 30 17 06 03 55 04 03 0C
//      10 55 6E 74 72 75 73 74 77 6F 72 74 68 79 20 43
//      41 30 22 18 0F 32 30 31 34 30 39 32 34 31 32 30
//      30 30 30 5A 18 0F 32 31 31 34 30 39 32 34 31 32
//      30 30 30 30 5A 30 5E 31 0B 30 09 06 03 55 04 06
//      13 02 44 45 31 21 30 1F 06 03 55 04 0A 0C 18 76
//      69 72 74 75 61 6C 2D 75 32 66 2D 6D 61 6E 75 66
//      61 63 74 75 72 65 72 31 0F 30 0D 06 03 55 04 08
//      0C 06 42 65 72 6C 69 6E 31 1B 30 19 06 03 55 04
//      03 0C 12 76 69 72 74 75 61 6C 2D 75 32 66 2D 76
//      30 2E 30 2E 31 30 59 30 13 06 07 2A 86 48 CE 3D
//      02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04
//      C3 C9 1F 25 2E 20 10 7B 5E 8D EA B1 90 20 98 F7
//      28 70 71 E4 54 18 B8 98 CE 5F F1 7C A7 25 AE 78
//      C3 3C C7 01 C0 74 60 11 CB BB B5 8B 08 B6 1D 20
//      C0 5E 75 D5 01 A3 F8 F7 A1 67 3F BE 32 63 AE BE
//      30 0C 06 08 2A 86 48 CE 3D 04 03 02 05 00 03 48
//      00 30 45 02 21 00 8E B9 20 57 A1 F3 41 4F 1B 79
//      1A 58 E6 07 AB A4 66 1C 93 61 FB C4 BA 89 65 5C
//      8A 3B EC 10 68 DA 02 20 15 90 A8 76 F0 80 47 DF
//      60 8E 23 B2 2A A0 AA D2 4B 0D 49 C9 75 33 00 AF
//      32 B6 90 73 F0 A1 A4 DB

/**
 * ASN.1 DER hexadecimal certificate representation
 * @type {string}
 * @const
 */
var ATTESTATION_CERTIFICATE = "308201b430820158a003020102020101300c06082a8648ce3d04030205003061310b300906035504061302444531263024060355040a0c1d556e7472757374776f72746879204341204f7267616e69736174696f6e310f300d06035504080c064265726c696e3119301706035504030c10556e7472757374776f727468792043413022180f32303134303932343132303030305a180f32313134303932343132303030305a305e310b30090603550406130244453121301f060355040a0c187669727475616c2d7532662d6d616e756661637475726572310f300d06035504080c064265726c696e311b301906035504030c127669727475616c2d7532662d76302e302e313059301306072a8648ce3d020106082a8648ce3d03010703420004c3c91f252e20107b5e8deab1902098f7287071e45418b898ce5ff17ca725ae78c33cc701c0746011cbbbb58b08b61d20c05e75d501a3f8f7a1673fbe3263aebe300c06082a8648ce3d040302050003480030450221008eb92057a1f3414f1b791a58e607aba4661c9361fbc4ba89655c8a3bec1068da02201590a876f08047df608e23b22aa0aad24b0d49c9753300af32b69073f0a1a4db";

/**
 * Name of the key store string in local storage
 * @type {string}
 * @const
 */
var KEY_STORE_NAME = "virtual-u2f-key-store-0.0.1";

/**
 * The "future use" byte to add to a message
 * @type {string}
 * @const
 */
var FUTURE_USE_BYTE = '00';

/**
 * The "reserved" byte to add to a register request
 * @type {string}
 * @const
 */
var RESERVED_BYTE = '05';

/**
 * The control byte for "enforce-user-presence-and-sign"
 * @type {string}
 * @const
 */
var CONTROL_BYTE = '03';

/**
 * The byte indicating user presence
 * @type {string}
 * @const
 */
var USER_PRESENCE_BYTE = '01';

/**
 * The storage for the current request
 */
var _currentRequest = {};

/*
 * The event that is emitted should user presence be confirmed.
 */
var userPresenceTest = new Event("userPresence");

window.addEventListener("userPresence", function(){
    handleCurrentRequest();
}, false);

chrome.runtime.onMessageExternal.addListener(function (request, sender, sendResponse) {
    "use strict";
    request["started"] = new Date().getTime();
    storeRequest(request, sender, sendResponse);

    /*
     * Always return true!
     * https://code.google.com/p/chromium/issues/detail?id=343007
     */
    return true;
});

/**
 * Handles a register request
 * @param request
 * @param sender
 * @param sendResponse
 */
var handleRegisterRequest = function (request, sender, sendResponse) {
    "use strict";

    /*
     * The new keypair for this RP
     */
    var keyPair = generateKeyPair();
    var clientData = getClientDataStringFromRequest(request);
    var clientDataHash = sha256Digest(clientData);
    var applicationId = getApplicationIdFromRequest(request);
    var applicationIdHash = sha256Digest(applicationId);
    var keyHandle = generateKeyHandle();
    var keyHandleLength = getKeyHandleLengthString(keyHandle);
    var signature = signHex(ATTESTATION_KEY.private, getRegistrationSignatureBaseString(applicationIdHash, clientDataHash, keyHandle, keyPair.ecpubhex));

    var response = RESERVED_BYTE + keyPair.ecpubhex + keyHandleLength + keyHandle + ATTESTATION_CERTIFICATE + signature;

    var sessionID = getSessionIdFromRequest(request);

    safeToKeyStore(applicationId, keyHandle, keyPair);

    /*
     * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll. 175-182
     */
    sendResponse({
        // websafe-base64(raw registration response message)
        registrationData: hextob64(response),

        // websafe-base64(UTF8(stringified(client data)))
        bd: clientData,

        // session id originally passed to handleRegistrationRequest
        sessionId :sessionID
    });
    return;
};

/**
 * Handles a sign request
 * @param request
 * @param sender
 * @param sendResponse
 */
var handleSignRequest = function (request, sender, sendResponse) {
    "use strict";
    if (!isValidKeyHandleForAppId(b64tohex(getKeyHandleFromRequest(request)), getApplicationIdFromRequest(request))) {
        sendResponse({
            errorCode: u2f.ErrorCodes.DEVICE_INELIGIBLE,
            errorMessage: "Not a valid device for this key handle/app id combination"
        });
    } else {
        var clientData = getClientDataStringFromRequest(request);
        var clientDataHash = sha256Digest(clientData);
        var applicationId = getApplicationIdFromRequest(request);
        var applicationIdHash = sha256Digest(applicationId);
        var sessionID = getSessionIdFromRequest(request);
        var challenge = getChallengeFromRequest(request);
        var counter = getKeyByHandle(b64tohex(getKeyHandleFromRequest(request))).counter;
        var counterHex = counterPadding(counter);

        var signature = signHex(getKeyByHandle(b64tohex(getKeyHandleFromRequest(request))).private, getSignSignatureBaseString(applicationIdHash, counterHex, clientDataHash));

        var sign = hextob64(USER_PRESENCE_BYTE + counterHex + signature);
        /*
         * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll.254 - 265
         */
        sendResponse({
            // websafe-base64(client data)
            bd : clientData,

            // websafe-base64(raw response from U2F device)
            sign : sign,

            // challenge originally passed to handleSignRequest
            challenge : challenge,

            // session id originally passed to handleSignRequest
            sessionId : sessionID,

            // application id originally passed to handleSignRequest
            app_id : applicationId
        });

        if (counter >= 65535) {
            resetCounter(b64tohex(getKeyHandleFromRequest(request)), getApplicationIdFromRequest(request));
        } else {
            increaseCounter(b64tohex(getKeyHandleFromRequest(request)), getApplicationIdFromRequest(request));
        }


    }
};

/**
 * Padds an integer for counter byte use
 * @param num
 * @returns {string}
 */
var counterPadding = function (num) {
    return ("0000" + num.toString(16)).substr(-4);
}

/**
 * Determines whether a provided key handle belongs to a key that may be used by the app with the provided app id.
 * @param keyHandle
 * @param appId
 * @returns {boolean}
 */
var isValidKeyHandleForAppId = function (keyHandle, appId) {
    "use strict";
    var key = getKeyByHandle(keyHandle);

    if (key === null) {
        return false;
    }

    if (key.appId === appId) {
        return true;
    } else {
        return false;
    }
};

/**
 *
 * @param keyHandle
 * @param appId
 */
var resetCounter = function (keyHandle, appId) {
    "use strict";
    var keyStore = getKeyStore();

    for (var k in keyStore) {
        if (keyStore[k].keyHandle.toLowerCase() ===  keyHandle.toLowerCase()) {
            keyStore[k].counter = 0;
            break;
        }
    }

    replaceKeyStore(keyStore);
};

/**
 *
 * @param keyHandle
 * @param appId
 */
var increaseCounter = function (keyHandle, appId) {
    "use strict";
    var keyStore = getKeyStore();

    for (var k in keyStore) {
        if (keyStore[k].keyHandle.toLowerCase() ===  keyHandle.toLowerCase()) {
            keyStore[k].counter = ++keyStore[k].counter;
            break;
        }
    }

    replaceKeyStore(keyStore);
};

/**
 * Retrieves a key by its handle or null if no key by that handle exists.
 * @param keyHandle
 * @returns {Object|null}
 */
var getKeyByHandle = function (keyHandle) {
    "use strict";
    var keyStore = getKeyStore();
    for (var k in keyStore) {
        var key = keyStore[k];
        if (key.keyHandle.toLowerCase() ===  keyHandle.toLowerCase()) {
            return key;
        }
    }
    return null;
};

/**
 * Stores a request for later use
 *
 * @param request
 * @param sender
 * @param sendResponse
 * @returns {{}}
 */
var storeRequest = function (request, sender, sendResponse) {
    "use strict";
    /**
     * @type {request: *, sender: *, sendResponse: *}}
     * @private
     */
    _currentRequest = {
        request : request,
        sender : sender,
        sendResponse : sendResponse
    };
    return _currentRequest;
};

var handleCurrentRequest = function () {
    "use strict";
    /*
     * Check if the current request object is properly set
     */
    if (typeof _currentRequest.request !== "undefined" && _currentRequest.request !== null) {
        /*
         * Check if the request has already timed out
         */
        var now = new Date().getTime();
        if (_currentRequest.request.started + _currentRequest.request.timeout >= now) {
            switch (_currentRequest.request.type) {
                case u2f.MessageTypes.U2F_REGISTER_REQUEST:
                    handleRegisterRequest(_currentRequest.request, _currentRequest.sender, _currentRequest.sendResponse);
                    break;
                case u2f.MessageTypes.U2F_SIGN_REQUEST:
                    handleSignRequest(_currentRequest.request, _currentRequest.sender, _currentRequest.sendResponse);
                    break;
                default:
                    throw new Error("Invalid Request Type");
                    break;
            }
        }
        _currentRequest = {};
    }
    return;
};

/**
 * Generates a new random generateKeyPair
 * @returns {Array} associative array of hexadecimal string of private and public key
 */
var generateKeyPair = function () {
    "use strict";
    /**
     *
     * @type {KJUR.crypto.ECDSA}
     */
    var secp256r1 = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
    return secp256r1.generateKeyPairHex();
};

/**
 * Signs a given message with a given private key
 * Example at http://kjur.github.io/jsrsasign/sample-ecdsa.html
 *
 * @param privateKey The private key to sign the message with
 * @param message The message to sign
 * @returns {String} the signature bytes as a hexadecimal string
 */
var signHex = function (privateKey, message) {
    "use strict";
    /**
     * The signature object to sign a message with a given private key.
     * @type {KJUR.crypto.Signature}
     */
    var sig = new KJUR.crypto.Signature({
        'alg': 'SHA256withECDSA',
        'prov': 'cryptojs/jsrsa'
    });

    sig.initSign({
        'ecprvhex': privateKey,
        'eccurvename': 'secp256r1'
    });

    sig.updateHex(message);

    return sig.sign();
};

/**
 * Gets a signature base String for registration
 *
 * @param applicationParameter
 * @param challengeParameter
 * @param keyHandle
 * @param userPublicKey
 * @returns {string} The signature base string
 */
var getRegistrationSignatureBaseString = function (applicationParameter, challengeParameter, keyHandle, userPublicKey) {
    "use strict";
    return FUTURE_USE_BYTE + applicationParameter + challengeParameter + keyHandle + userPublicKey;
};

/**
 * Gets a signature base String for signin
 *
 * @param applicationParameter
 * @param challengeParameter
 * @param keyHandle
 * @param userPublicKey
 * @returns {string} The signature base string
 */
var getSignSignatureBaseString = function (applicationParameter, counter, challenge) {
    "use strict";
    return applicationParameter + USER_PRESENCE_BYTE + counter + challenge;
};

/**
 * Dispatches the user presence event
 */
var handleButtonPress = function () {
    "use strict";
    window.dispatchEvent(userPresenceTest);
    return;
};

var handleSignIn = function () {
    "use strict";
    currentRequest.sendResponse({
        "success": "sign"
    });
    return;
};

/**
 * Converts a decimal number < 256 to a heaxadecimal byte representation.
 * @param {Integer} dec Decimal number < 255
 * @returns {string}
 */
var decimalNumberToHexByte = function (dec) {
    "use strict";
    if (dec > 255) {
        throw new Error("Number exceeds a byte.");
    }
    return (dec + 0x10000).toString(16).substr(-2);
};

/**
 * Creates a SHA256 has of a string
 * @param {String} s String do hash
 * @returns {String} Hexadecimal digest
 */
var sha256Digest = function (s) {
    "use strict";
    var sha = new KJUR.crypto.MessageDigest({
        alg: 'sha256',
        prov: 'cryptojs'
    });
    sha.updateString(s)
    return sha.digest();
};

var arrayBufferToB64 = function (arrayBuffer) {
    "use strict";
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
};

var Uint8ToHex = function (uint) {
    "use strict";
    var s = '';
    for (var i = 0; i < uint.length; i++) {
        s += uint[i].toString(16);
    }
    return s;
};

var stringToUint = function (s) {
    "use strict";
    var uint = new Uint8Array(s.length);

    for (var i = 0, j = s.length; i < j; ++i) {
        uint[i] = s.charCodeAt(i);
    }

    return uint;
};

var prepareSignableData = function (appId, challenge, callback) {
    "use strict";
    window.crypto.subtle.digest({
        name: "SHA-256"
    }, stringToUint(appId)).then(function (appIdDigest) {
        window.crypto.subtle.digest({
            name: "SHA-256"
        }, stringToUint(challenge)).then(function (challengeDigest) {
            callback(appIdDigest, challengeDigest);
        }, function (error) {
            throw new Error("Can't Digest Challenge")
        });
    }, function (error) {
        throw new Error("Can't Digest App ID")
    });
    return;
};

var prepareChallengeSha256 = function (challenge, callback) {
    "use strict";
    window.crypto.subtle.digest({
        name: "SHA-256"
    }, stringToUint(challenge)).then(function (fullChallengeDigest) {
        callback(fullChallengeDigest);
    }, function (error) {
        throw new Error("Can't Digest Full Challenge")
    });
    return;
};

var generateKeyHandle = function () {
    "use strict";
    //return stohex("dummy_key_handle");
    return stohex("bogus_" + new Date().getTime());
};

var addToKeyStore = function (key) {
    "use strict";
    var keyStore = JSON.parse(localStorage.getItem(KEY_STORE_NAME));

    if (keyStore === null) {
        keyStore = {};
    }

    keyStore[key.keyHandle] = key;

    localStorage.setItem(KEY_STORE_NAME, JSON.stringify(keyStore));
    return;
};

var replaceKeyStore = function (keyStore) {
    "use strict";
    localStorage[KEY_STORE_NAME] = JSON.stringify(keyStore);
    return;
};

var emptykeyStore = function () {
    "use strict";
    localStorage[KEY_STORE_NAME] = "{}";
    return;
};

var getKeyStore = function () {
    "use strict";
    return JSON.parse(localStorage.getItem(KEY_STORE_NAME));
};

var getPrivateAttestationKey = function () {
    "use strict";
    return ATTESTATION_KEY.private;
};

var getPublicAttestationKey = function () {
    "use strict";
    return ATTESTATION_KEY.public;
};

var getAttestationCertificate = function () {
    "use strict";
    return ATTESTATION_CERTIFICATE;
};

var getSessionIdFromRequest = function (request) {
    "use strict";
    switch (request.type) {
        case u2f.MessageTypes.U2F_REGISTER_REQUEST:
            return request.registerRequests[0].sessionId;
            break;
        case u2f.MessageTypes.U2F_SIGN_REQUEST:
            return request.signRequests[0].sessionId;
            break;
        default:
            throw new Error("Invalid Request Type");
            break;
    }
};

var getClientDataStringFromRequest = function (request) {
    "use strict";
    switch (request.type) {
        case u2f.MessageTypes.U2F_REGISTER_REQUEST:
            return JSON.stringify(request.registerRequests[0].challenge);
            break;
        case u2f.MessageTypes.U2F_SIGN_REQUEST:
            return JSON.stringify(request.signRequests[0].challenge);
            break;
        default:
            throw new Error("Invalid Request Type");
        break;
    }
};

var getChallengeFromRequest = function (request) {
    return getClientDataStringFromRequest(request).challenge;
};

var getApplicationIdFromRequest = function (request) {
    "use strict";
    switch (request.type) {
        case u2f.MessageTypes.U2F_REGISTER_REQUEST:
            return request.registerRequests[0].app_id;
            break;
        case u2f.MessageTypes.U2F_SIGN_REQUEST:
            return request.signRequests[0].app_id;
            break;
        default:
            throw new Error("Invalid Request Type");
        break;
    }
};

var getKeyHandleFromRequest = function (request) {
    "use strict";
    switch (request.type) {
        case u2f.MessageTypes.U2F_SIGN_REQUEST:
            return request.signRequests[0].keyHandle;
            break;
        default:
            throw new Error("Invalid Request Type");
            break;
    }
};

var getKeyHandleLengthString = function (keyHandle) {
    "use strict";
    return decimalNumberToHexByte(keyHandle.length / 2);
};

var safeToKeyStore = function(applicationId, keyHandle, keyPair) {
    "use strict";
    addToKeyStore({
        "generated" : (new Date()),
        "appId" : applicationId,
        "keyHandle" : keyHandle,
        "public" : keyPair.ecpubhex,
        "private" : keyPair.ecprvhex,
        "counter" : 0
    });
    return;
};