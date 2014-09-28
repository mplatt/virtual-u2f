/**
 * Imitates the message flow as shown in 'FIDO U2F Raw Message Formats'
 * documentation (fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf) with
 * jsrsasign
 */

/*
 * 7.1 Registration Example
 */
//var registrationExample = function() {
	/*
	 *	INPUT DATA
	 */
	
	// p. 18 l. 290-291
	// beginning with 0x04 as per specifications
	var PUBLIC_ATTESTATION_KEY = '048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101';
	
	// p. 18 l. 288
	var PRIVATE_ATTESTATION_KEY = 'f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664';
	
	// p. 18 l. 315-323
	var ATTESTATION_CERT = '3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df';
	
	// p. 18 l. 325 - 328
	var CLIENT_DATA = '{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}';
	
	// p. 19 l. 332
	var APPLICATION_ID = 'http://example.com';
	
	// p. 19. l. 340-341
	// beginning with 0x04 as per specifications
	var PUBLIC_KEY = '04b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9';
	
	// p. 19 l. 338
	var PRIVATE_KEY = '9a9684b127c5e3a706d618c86401c7cf6fd827fd0bc18d24b0eb842e36d16df1';
	
	// p. 19 l. 343-345
	var KEY_HANDLE = '2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25';
	
	/*
	 *	OUTPUT DATA
	 */
	// p. 19 l. 330
	var CLIENT_DATA_HASH = '4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb';
	
	// p. 19 l. 334
	var APPLICATION_ID_HASH = 'f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4';
	
	// p. 19 l- 347 - 352
	var SIGNATURE_BASE_STRING = '00f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c44142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c2504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9';
	
	// p. 19 l. 357 - 371
	var RESPONSE_MESSAGE = '0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871';
	
	// p. 19 l .354 - 355
	var SIGNATURE = '304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871';
	
	/*
	 * PREPARE TESTS
	 */
	var edcsaCurve = new KJUR.crypto.ECDSA({
		"curve": "secp256r1"
	});
	
	/*
	 * CONVENIENCE METHODS
	 */
	var sha256Digest = function (s) {
		var sha = new KJUR.crypto.MessageDigest({
			alg: 'sha256',
			prov: 'cryptojs'
		});
		sha.updateString(s)
		return sha.digest();
	};
	
	var hexToByteArray = function (hex) {
		var a = [];
		for (var i = 0; i < hex.length; i += 2) {
		    a.push("0x" + hex.substr(i, 2));
		}
		return a;
	};
	
	var decimalNumberToHexByte = function (dec) {
		if (dec > 255) {
			throw new Error("Number exceeds a byte.");
		}
		return (dec + 0x10000).toString(16).substr(-2);
	};
	
	/*
	 * TEST METHODS
	 */
	var applicationIdHashingTest = function (applicationId){
		return sha256Digest(applicationId);
	};
	
	var clientDataHasingTest = function (clientData){
		return sha256Digest(clientData);
	};
	
	var verifySignature = function(publicAttestationKey, signature, hex) {
		var sig = new KJUR.crypto.Signature({
			'alg': 'SHA256withECDSA',
			'prov': 'cryptojs/jsrsa'
		});
		sig.initVerifyByPublicKey({
			'ecpubhex': publicAttestationKey,
			'eccurvename': 'secp256r1'
		});
		sig.updateHex(hex);
		
		return sig.verify(signature);
	};
	
	console.log(verifySignature(PUBLIC_ATTESTATION_KEY, SIGNATURE, SIGNATURE_BASE_STRING));
	
	/*
	 * Central Logic
	 */
	
	var signString = function(privateKey, message) {
		// mit attestation private key
		var sig = new KJUR.crypto.Signature({
			'alg': 'SHA256withECDSA',
			'prov': 'cryptojs/jsrsa'
		});
		
		sig.initSign({
			'ecprvhex': privateKey,
			'eccurvename': 'secp256r1'
		});
		
		sig.updateString(message);
		return sig.sign();
	};
	//console.log(signString(PRIVATE_ATTESTATION_KEY, getSignatureBaseString(sha256Digest(APPLICATION_ID), sha256Digest(CLIENT_DATA), KEY_HANDLE, PUBLIC_KEY)));
	
	var getSignatureBaseString = function(applicationParameter, challengeParameter, keyHandle, userPublicKey) {
		// p. 10 l. 140-142
		var FUTURE_USE_BYTE = '00';
		
		return FUTURE_USE_BYTE + applicationParameter + challengeParameter + keyHandle + userPublicKey;
	};
	//console.log(getSignatureBaseString(sha256Digest(APPLICATION_ID), sha256Digest(CLIENT_DATA), KEY_HANDLE, PUBLIC_KEY));
	
	var getResponse = function(userPublicKey, keyHandle, attestationCertificate, signature) {
		// p. 9 l. 127
		var RESERVED_BYTE = '05';
		
		var keyHandleLength = decimalNumberToHexByte(keyHandle.length / 2);
		
		return RESERVED_BYTE + userPublicKey + keyHandleLength + keyHandle + attestationCertificate;
	};
	//console.log(getResponse(PUBLIC_KEY, KEY_HANDLE, ATTESTATION_CERT));
	
	/*
	 * 	RUN TESTS
	 */
	
	// Application ID Test
	if (applicationIdHashingTest(APPLICATION_ID) === APPLICATION_ID_HASH) {
		console.log("applicationIdHashingTest passed");
	} else {
		console.warn("applicationIdHashingTest failed");
	}
	
	// Client Data Test
	if (clientDataHasingTest(CLIENT_DATA) === CLIENT_DATA_HASH) {
		console.log("clientDataHasingTest passed");
	} else {
		console.warn("clientDataHasingTest failed");
	}
	
	
//};