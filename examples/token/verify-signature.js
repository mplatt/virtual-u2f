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