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
//		var ecdsa = new KJUR.crypto.ECDSA({
//			"curve": "secp256r1"
//		 });
//		 
//		 ecdsa.setPrivateKeyHex("34162facb11cc9c9f2e7f6f952e9164d954ef5d309fdba1032784bfab9bfd37b");
//		 ecdsa.setPublicKeyHex("04361f015c81c6b8cf7a14a4856f19f6a3e4101f7b8b4ca4bdb1270180625cbefe0eb8534defbb73bb6506312b8287830e13137de499cb61508303fd6f8b5b186f");
//		 
//		 var tbsc = new KJUR.asn1.x509.TBSCertificate();
//		 tbsc.setSerialNumberByParam({
//		 	"int": 1
//		 });
//		 tbsc.setSignatureAlgByParam({
//		 	"name": "SHA256withECDSA"
//		 });
//		 tbsc.setIssuerByParam({
//		 	"str": "/C=DE/O=Untrustworthy CA Organisation/ST=Berlin/CN=Untrustworthy CA"
//		 });
//		 tbsc.setNotBeforeByParam({
//		 	"str": "20140924120000Z"
//		 });
//		 tbsc.setNotAfterByParam({
//		 	"str": "21140924120000Z"
//		 });
//		 tbsc.setSubjectByParam({
//		 	"str": "/C=DE/O=virtual-u2f-manufacturer/ST=Berlin/CN=virtual-u2f-v0.0.1"
//		});
//		 
//		 tbsc.setSubjectPublicKeyByGetKey(ecdsa);
//		 
//		 var cert = new KJUR.asn1.x509.Certificate({
//		 	"tbscertobj": tbsc,
//			"prvkeyobj" : ecdsa
//		 });
//		 
//		 cert.sign();
//		 console.log(cert.getPEMString());

// Resulting PEM String
//
//		-----BEGIN CERTIFICATE-----
//		MIIBtTCCAVigAwIBAgIBATAMBggqhkjOPQQDAgUAMGExCzAJBgNVBAYTAkRFMSYw
//		JAYDVQQKDB1VbnRydXN0d29ydGh5IENBIE9yZ2FuaXNhdGlvbjEPMA0GA1UECAwG
//		QmVybGluMRkwFwYDVQQDDBBVbnRydXN0d29ydGh5IENBMCIYDzIwMTQwOTI0MTIw
//		MDAwWhgPMjExNDA5MjQxMjAwMDBaMF4xCzAJBgNVBAYTAkRFMSEwHwYDVQQKDBh2
//		aXJ0dWFsLXUyZi1tYW51ZmFjdHVyZXIxDzANBgNVBAgMBkJlcmxpbjEbMBkGA1UE
//		AwwSdmlydHVhbC11MmYtdjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
//		Nh8BXIHGuM96FKSFbxn2o+QQH3uLTKS9sScBgGJcvv4OuFNN77tzu2UGMSuCh4MO
//		ExN95JnLYVCDA/1vi1sYbzAMBggqhkjOPQQDAgUAA0kAMEYCIQCp0prGaSpsoTsV
//		u2TndPPrgZK9ofJgp2oxV7pGefiGQQIhANGruIBEOvZe+mBMoc0pBDsL7414FrT7
//		zS7V2mSylCdR
//		-----END CERTIFICATE-----

// Resulting human readable certificate representation
// (created by openSLL: openssl x509 -noout -text -in u2f.pem)
//
//		Data:
//		    Version: 3 (0x2)
//		    Serial Number: 1 (0x1)
//		Signature Algorithm: ecdsa-with-SHA256
//		    Issuer: C=DE, O=Untrustworthy CA Organisation, ST=Berlin, CN=Untrustworthy CA
//		    Validity
//		        Not Before: Sep 24 12:00:00 2014 GMT
//		        Not After : Sep 24 12:00:00 2114 GMT
//		    Subject: C=DE, O=virtual-u2f-manufacturer, ST=Berlin, CN=virtual-u2f-v0.0.1
//		    Subject Public Key Info:
//		        Public Key Algorithm: id-ecPublicKey
//		            Public-Key: (256 bit)
//		            pub: 
//		                04:36:1f:01:5c:81:c6:b8:cf:7a:14:a4:85:6f:19:
//		                f6:a3:e4:10:1f:7b:8b:4c:a4:bd:b1:27:01:80:62:
//		                5c:be:fe:0e:b8:53:4d:ef:bb:73:bb:65:06:31:2b:
//		                82:87:83:0e:13:13:7d:e4:99:cb:61:50:83:03:fd:
//		                6f:8b:5b:18:6f
//		            ASN1 OID: prime256v1
//		Signature Algorithm: ecdsa-with-SHA256
//		     30:46:02:21:00:a9:d2:9a:c6:69:2a:6c:a1:3b:15:bb:64:e7:
//		     74:f3:eb:81:92:bd:a1:f2:60:a7:6a:31:57:ba:46:79:f8:86:
//		     41:02:21:00:d1:ab:b8:80:44:3a:f6:5e:fa:60:4c:a1:cd:29:
//		     04:3b:0b:ef:8d:78:16:b4:fb:cd:2e:d5:da:64:b2:94:27:51

// Resulting ASN.1 DER certificate
// (created by openSLL: openssl x509 -outform der -in u2f.pem -out u2f.der)
//
//		30 82 01 B5 30 82 01 58 A0 03 02 01 02 02 01 01 30 0C 06 08 2A 86 48
//		CE 3D 04 03 02 05 00 30 61 31 0B 30 09 06 03 55 04 06 13 02 44 45 31
//		26 30 24 06 03 55 04 0A 0C 1D 55 6E 74 72 75 73 74 77 6F 72 74 68 79
//		20 43 41 20 4F 72 67 61 6E 69 73 61 74 69 6F 6E 31 0F 30 0D 06 03 55
//		04 08 0C 06 42 65 72 6C 69 6E 31 19 30 17 06 03 55 04 03 0C 10 55 6E
//		74 72 75 73 74 77 6F 72 74 68 79 20 43 41 30 22 18 0F 32 30 31 34 30
//		39 32 34 31 32 30 30 30 30 5A 18 0F 32 31 31 34 30 39 32 34 31 32 30
//		30 30 30 5A 30 5E 31 0B 30 09 06 03 55 04 06 13 02 44 45 31 21 30 1F
//		06 03 55 04 0A 0C 18 76 69 72 74 75 61 6C 2D 75 32 66 2D 6D 61 6E 75
//		66 61 63 74 75 72 65 72 31 0F 30 0D 06 03 55 04 08 0C 06 42 65 72 6C
//		69 6E 31 1B 30 19 06 03 55 04 03 0C 12 76 69 72 74 75 61 6C 2D 75 32
//		66 2D 76 30 2E 30 2E 31 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08
//		2A 86 48 CE 3D 03 01 07 03 42 00 04 36 1F 01 5C 81 C6 B8 CF 7A 14 A4
//		85 6F 19 F6 A3 E4 10 1F 7B 8B 4C A4 BD B1 27 01 80 62 5C BE FE 0E B8
//		53 4D EF BB 73 BB 65 06 31 2B 82 87 83 0E 13 13 7D E4 99 CB 61 50 83
//		03 FD 6F 8B 5B 18 6F 30 0C 06 08 2A 86 48 CE 3D 04 03 02 05 00 03 49
//		00 30 46 02 21 00 A9 D2 9A C6 69 2A 6C A1 3B 15 BB 64 E7 74 F3 EB 81
//		92 BD A1 F2 60 A7 6A 31 57 BA 46 79 F8 86 41 02 21 00 D1 AB B8 80 44
//		3A F6 5E FA 60 4C A1 CD 29 04 3B 0B EF 8D 78 16 B4 FB CD 2E D5 DA 64
//		B2 94 27 51

/**
 * ASN.1 DER hexadecimal certificate representation
 * @const
 */
var ATTESTATION_CERTIFICATE = "308201b530820158a003020102020101300c06082a8648ce3d04030205003061310b300906035504061302444531263024060355040a0c1d556e7472757374776f72746879204341204f7267616e69736174696f6e310f300d06035504080c064265726c696e3119301706035504030c10556e7472757374776f727468792043413022180f32303134303932343132303030305a180f32313134303932343132303030305a305e310b30090603550406130244453121301f060355040a0c187669727475616c2d7532662d6d616e756661637475726572310f300d06035504080c064265726c696e311b301906035504030c127669727475616c2d7532662d76302e302e313059301306072a8648ce3d020106082a8648ce3d03010703420004361f015c81c6b8cf7a14a4856f19f6a3e4101f7b8b4ca4bdb1270180625cbefe0eb8534defbb73bb6506312b8287830e13137de499cb61508303fd6f8b5b186f300c06082a8648ce3d04030205000349003046022100a9d29ac6692a6ca13b15bb64e774f3eb8192bda1f260a76a3157ba4679f88641022100d1abb880443af65efa604ca1cd29043b0bef8d7816b4fbcd2ed5da64b2942751";

/**
 * Name of the key store string in local storage
 * @const
 */
var KEY_STORE_NAME = "virtual-u2f-key-store-0.0.1";

/**
 * The "future use" byte to add to a message
 * @const
 */
var FUTURE_USE_BYTE = '00';

/**
 * The "reserved" byte to add to a register request
 * @const
 */
var RESERVED_BYTE = '05';

/*
 * The event that is emitted should user presence be confirmed.
 */
var userPresenceTest = new Event("userPresence");

chrome.runtime.onMessageExternal.addListener(function (request, sender, sendResponse) {
    "use strict";
    /*
     * Do not handle the response immediately but wait for the user presence
     * test to complete.
     */
    window.addEventListener("userPresence", function (e) {
        switch (request.type) {
            case u2f.MessageTypes.U2F_REGISTER_REQUEST:
                handleRegisterRequest(request, sender, sendResponse);
                break;
            case u2f.MessageTypes.U2F_SIGN_REQUEST:

                break;
            default:
                throw new Error("Invalid Rrequest Type");
                break;
        }
    }, false);

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
    var signature = signHex(ATTESTATION_KEY.private, getSignatureBaseString(applicationIdHash, clientDataHash, keyHandle, keyPair.ecpubhex));

    var response = RESERVED_BYTE + keyPair.ecpubhex + keyHandleLength + keyHandle + ATTESTATION_CERTIFICATE + signature;

    safeToKeyStore(applicationId, keyHandle, keyPair);

    sendResponse({
        "registrationData": hextob64(response),
        "clientData": clientData
    });
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
 * Gets a signature base String
 *
 * @param applicationParameter
 * @param challengeParameter
 * @param keyHandle
 * @param userPublicKey
 * @returns {string} The signature base string
 */
var getSignatureBaseString = function (applicationParameter, challengeParameter, keyHandle, userPublicKey) {
    "use strict";

    return FUTURE_USE_BYTE + applicationParameter + challengeParameter + keyHandle + userPublicKey;
};

/**
 * Dispatches the user presence event
 */
var handleButtonPress = function () {
    "use strict";
    window.dispatchEvent(userPresenceTest);
};

var handleSignIn = function () {
    "use strict";
    currentRequest.sendResponse({
        "success": "sign"
    });
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
};

var generateKeyHandle = function () {
    "use strict";
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
};

var emptykeyStore = function () {
    "use strict";
    localStorage[KEY_STORE_NAME] = "{}";
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
    return request.registerRequests[0].registrationData.sessionId;
};

var getClientDataStringFromRequest = function (request) {
    "use strict";
    return JSON.stringify(request.registerRequests[0].registrationData);
};


var getApplicationIdFromRequest = function (request) {
    "use strict";
    return request.registerRequests[0].registrationData.app_id;
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
};