/**
 * SHA/ECDSA Configuration
 */

/* 
 * ECDSA-secp256r1 Attestation Keys in Base64 Representation
 * 
 * Generated through jsrsasign library:
 * 		var secp256r1 = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
 * 		secp256r1.generateKeyPairHex();
 */
var ATTESTATION_KEY = {
	"private" : "34162facb11cc9c9f2e7f6f952e9164d954ef5d309fdba1032784bfab9bfd37b",
	"public" : "04361f015c81c6b8cf7a14a4856f19f6a3e4101f7b8b4ca4bdb1270180625cbefe0eb8534defbb73bb6506312b8287830e13137de499cb61508303fd6f8b5b186f"
};

/*
 * PEM formatted String of the assertion certificate
 * 
 * Certificate:
 * 	Data:
 * 		Version: 3 (0x2)
 * 		Serial Number: 1 (0x1)
 * 	Signature Algorithm: ecdsa-with-SHA256
 * 		Issuer: C=DE, O=u2f-dummy-issuer, CN=CA
 * 		Validity
 * 			Not Before: Sep 24 12:00:00 2014 GMT
 * 			Not After : Jan  1 00:00:00 2030 GMT
 * 		Subject: C=DE, O=u2f-dummy-subject, CN=virtual-u2f-v0.0.1
 * 		Subject Public Key Info:
 * 			Public Key Algorithm: id-ecPublicKey
 * 				Public-Key: (256 bit)
 * 				pub: 
 * 					04:36:1f:01:5c:81:c6:b8:cf:7a:14:a4:85:6f:19:
 * 					f6:a3:e4:10:1f:7b:8b:4c:a4:bd:b1:27:01:80:62:
 * 					5c:be:fe:0e:b8:53:4d:ef:bb:73:bb:65:06:31:2b:
 * 					82:87:83:0e:13:13:7d:e4:99:cb:61:50:83:03:fd:
 * 					6f:8b:5b:18:6f
 * 				ASN1 OID: prime256v1
 * 	Signature Algorithm: ecdsa-with-SHA256
 * 		30:44:02:20:7b:40:1d:87:00:90:84:e3:04:61:e3:e9:93:69:
 * 		56:b1:6c:8e:88:8a:7c:d4:13:ab:ab:6e:b3:1e:fe:da:74:da:
 * 		02:20:5b:06:46:13:14:d9:70:fe:80:38:ea:fd:22:14:ee:b0:
 * 		4a:dd:db:c8:60:b6:7d:00:57:86:b3:88:c9:45:a3:3f
 * 
 * 
 * 
 * Generated through jsrsasign library:
 * 
 * var ecdsa = new KJUR.crypto.ECDSA({
 * 	"curve": "secp256r1"
 * });
 * 
 * ecdsa.setPrivateKeyHex("34162facb11cc9c9f2e7f6f952e9164d954ef5d309fdba1032784bfab9bfd37b");
 * ecdsa.setPublicKeyHex("04361f015c81c6b8cf7a14a4856f19f6a3e4101f7b8b4ca4bdb1270180625cbefe0eb8534defbb73bb6506312b8287830e13137de499cb61508303fd6f8b5b186f");
 * 
 * var tbsc = new KJUR.asn1.x509.TBSCertificate();
 * tbsc.setSerialNumberByParam({
 * 	"int": 1
 * });
 * tbsc.setSignatureAlgByParam({
 * 	"name": "SHA256withECDSA"
 * });
 * tbsc.setIssuerByParam({
 * 	"str": "/C=DE/O=u2f-dummy-issuer/CN=CA"
 * });
 * tbsc.setNotBeforeByParam({
 * 	"str": "20140924120000Z"
 * });
 * tbsc.setNotAfterByParam({
 * 	"str": "20300101000000Z"
 * });
 * tbsc.setSubjectByParam({
 * 	"str": "/C=DE/O=u2f-dummy-subject/CN=virtual-u2f-v0.0.1"
 * });
 * 
 * tbsc.setSubjectPublicKeyByGetKey(ecdsa);
 * 
 * var cert = new KJUR.asn1.x509.Certificate({
 * 	"tbscertobj": tbsc,
 * 	"prvkeyobj" : ecdsa
 * });
 * 
 * cert.sign();
 * console.log(cert.getPEMString());
 */
var X509_PEM = "-----BEGIN CERTIFICATE-----" +
               "MIIBbzCCARSgAwIBAgIBATAMBggqhkjOPQQDAgUAMDUxCzAJBgNVBAYTAkRFMRkw" +
               "FwYDVQQKDBB1MmYtZHVtbXktaXNzdWVyMQswCQYDVQQDDAJDQTAiGA8yMDE0MDky" +
               "NDEyMDAwMFoYDzIwMzAwMTAxMDAwMDAwWjBGMQswCQYDVQQGEwJERTEaMBgGA1UE" +
               "CgwRdTJmLWR1bW15LXN1YmplY3QxGzAZBgNVBAMMEnZpcnR1YWwtdTJmLXYwLjAu" +
               "MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDYfAVyBxrjPehSkhW8Z9qPkEB97" +
               "i0ykvbEnAYBiXL7+DrhTTe+7c7tlBjErgoeDDhMTfeSZy2FQgwP9b4tbGG8wDAYI" +
               "KoZIzj0EAwIFAANHADBEAiB7QB2HAJCE4wRh4+mTaVaxbI6IinzUE6urbrMe/tp0" +
               "2gIgWwZGExTZcP6AOOr9IhTusErd28hgtn0AV4aziMlFoz8=" +
               "-----END CERTIFICATE-----";

var KEY_STORE_NAME = "virtual-u2f-key-store-0.0.1";

var currentRequest = null;

chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
	currentRequest = {
			request : request,
			sender : sender,
			sendResponse : sendResponse
	};
	
	/*
	 * Always return true!
	 * https://code.google.com/p/chromium/issues/detail?id=343007
	 */
	return true;
});

var handleButtonPress = function () {
	if (currentRequest !== null) {
		switch (currentRequest.request.type) {
		case "register":
			handleRegistration();
			break;
		case "sign":
			handleSignIn();
			break;
		default:
			currentRequest.sendResponse({
				"error" : "Unknown Request Type"
			});
			break;
		}
	}
};
	  
var handleRegistration = function () {
	"use strict";
	
	/**
	 * Request holder object (including callbacks).
	 */
	var r = currentRequest;
	
	/**
	 * First data object for registration request.
	 * @typedef {{
	 *   version: string,
	 *   challenge: string,
	 *   appId: string
	 * }}
	 */
	var sr = r.request.request.signRequests[0];
	
	prepareSignableData(sr.appId, sr.challenge, function(appIdDigest, challengeDigest) {
		prepareChallengeSha256(JSON.stringify({
			typ : "navigator.id.finishEnrollment",
			/*
			 * TODO Clearify if this should use digested challenge as in
			 * Google demo or raw challenge as in 
			 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf. Sticking
			 * with raw challenge for now...
			 */
			//challenge : arrayBufferToB64(challengeDigest),
			challenge : sr.challenge,
			cid_pubkey : "unused", // TODO
			origin : sr.appId
		}), function(fullChallengeDigest) {
			
			var applicationSha256 = appIdDigest;		// aka. APP_ID_ENROLL_SHA256
			var challengeSha256 = fullChallengeDigest;	// aka. BROWSER_DATA_ENROLL_SHA256
			
			generateKeyPair(applicationSha256, challengeSha256, function(keyPair){
				generateKeyHandle(applicationSha256, keyPair, function(keyHandle){
					console.log("keyHandle");
					console.log(keyHandle);
					
					/*
					 * This key is appropriately constructed. Save it.
					 */
					addToKeyStore({
						"generated" : (new Date()),
						"appId" : sr.appId,
						"keyHandle" : keyHandle,
						"public" : keyPair.ecpubhex,
						"private" : keyPair.ecprvhex
					});
					
					/*
					 * Current Request is done. Set to null
					 */
					currentRequest = null;
					
					r.sendResponse({
						nada : "nada"
					});	
				});
			});
		});
	});
};

var handleSignIn = function () {
	"use strict";
	currentRequest.sendResponse({
		"success" : "sign"
	});
};

var arrayBufferToB64 = function (arrayBuffer) {
	return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
};

var stringToUint = function (s) {
	var uint = new Uint8Array(s.length);
	
	for (var i = 0, j = s.length; i < j; ++i){
		uint[i] = s.charCodeAt(i);
	}
	
	return uint;
};

var prepareSignableData = function (appId, challenge, callback) {
	window.crypto.subtle.digest({
		name : "SHA-256"
	}, stringToUint(appId)).then(function(appIdDigest) {
		window.crypto.subtle.digest({
			name : "SHA-256"
		}, stringToUint(challenge)).then(function(challengeDigest) {
			callback(appIdDigest, challengeDigest);
		}, function(error) {
			throw new Error("Can't Digest Challenge")
		});
	}, function(error) {
		throw new Error("Can't Digest App ID")
	});	
};

var prepareChallengeSha256 = function (challenge, callback) {
	window.crypto.subtle.digest({
		name : "SHA-256"
	}, stringToUint(challenge)).then(function(fullChallengeDigest) {			
		callback(fullChallengeDigest);
	}, function(error) {
		throw new Error("Can't Digest Full Challenge")
	});
};


var generateKeyPair = function (applicationSha256, challengeSha256, callback) {
	callback(new KJUR.crypto.ECDSA({
		"curve": "secp256r1"
	}).generateKeyPairHex());
};

var generateKeyHandle = function (applicationSha256, keyPair, callback) {
	callback("key_" + new Date().getTime());
};

var addToKeyStore = function (key) {
	var keyStore = JSON.parse(localStorage.getItem(KEY_STORE_NAME));
	
	if (keyStore === null) {
		keyStore = {};
	}
	
	keyStore[key.keyHandle] = key;
	
	localStorage[KEY_STORE_NAME] = JSON.stringify(keyStore);
};

var emptykeyStore = function () {
	localStorage[KEY_STORE_NAME] = "{}";
};

var getKeyStore = function () {
	console.log("getKeyStore");
	return JSON.parse(localStorage.getItem(KEY_STORE_NAME));
};