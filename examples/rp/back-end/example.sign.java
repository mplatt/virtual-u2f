package de.mplatt.idi.virtualu2f.examples.rp.authentication;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.json.JSONException;
import org.json.JSONObject;


/**
 * Servlet implementation class AuthenticationServlet
 */
@SuppressWarnings("serial")
@WebServlet("/authenticate")
public class AuthenticationServlet extends HttpServlet {
	/**
	 * A dummy public key that would have been obtained upon registration. In
	 * the real world this would be associated with a user and fetched from a
	 * database.
	 */
	byte[] publicKey;

	/**
	 * The challenge "we" (the RP application server) posed. In the real world
	 * this would be dynamically generated per request and stored in a database.
	 */
	byte[] CHALLENGE = Base64.decodeBase64("Ym9ndXM=");

	/**
	 * "Our" (the RP's) app ID
	 */
	String APP_ID = "http://127.0.0.1";

	/**
	 * @throws DecoderException
     * @see HttpServlet#HttpServlet()
     */
    public AuthenticationServlet() throws DecoderException {
        super();
        this.publicKey = Hex.decodeHex("04b7d96a68717ad2d2228747440da1bca33df31f234115d32f2e9402fc6323dd8bac1217b26548f726023c59727487a6eb433f2065255550fca5b6f2a3355b9424".toCharArray());
    }

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		/**
		 * The parsed HTTP POST request payload.
		 */
		JSONObject clientDataReceived = new JSONObject(IOUtils.toString(request.getReader()));

		/**
		 * The (base64-decoded) sign parameter is the raw authentication
		 * response message as explained in the U2F Raw Message Formats
		 * document.
		 */
		byte[] sign =  Base64.decodeBase64(clientDataReceived.getString("sign"));

		/**
		 * Bit 0 is set to 1, which means that user presence was verified. (This
		 * version of the protocol doesn’t specify a way to request
		 * authentication responses without requiring user presence.) A
		 * different value of Bit 0, as well as Bits 1 through 7, are reserved
		 * for future use. The values of Bit 1 through 7 SHOULD be 0.
		 */
		byte[] userPresenceByte = getUserPresenceByte(sign);

		/**
		 * This is the big-endian representation of a counter value that the U2F
		 * token increments every time it performs an authentication operation.
		 */
		byte[] counter = getCounterBytes(sign);

		/**
		 * This is a ECDSA signature (on P-256) over the following byte string:
		 *
		 * - The application parameter [32 bytes] from the authentication
		 *   request message.
		 *
		 * - The above user presence byte [1 byte].
		 *
		 * - The above counter [4 bytes].
		 *
		 * - The challenge parameter [32 bytes] from the authentication request
		 *   message.
		 *
		 * The signature is to be verified by the relying party using the public
		 * key obtained during registration.
		 */
		byte[] signature = getSignatureBytes(sign);
		
		try {
			verifyUserPresenceByte(userPresenceByte);
		} catch (Exception e) {
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		
		try {
			verifyBd(clientDataReceived.getString("bd"));
		} catch (Exception e) {
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		try {
			verifyCounterValue(counter);
		} catch (Exception e) {
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		PublicKey pub;
		try {
			pub = getPublicKeyFromBytes(publicKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		
		if (!isValidSignature(pub, getSignatureBaseString(clientDataReceived), signature)) {
			System.out.println("Invalid Signature");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		} else {
			
		}
	}

	/**
	 * Gets a public key object from raw prime256v1 key material.
	 * 
	 * @param pubKey
	 *            The raw public key material
	 * @return The public key extracted
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
		KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
		ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
		ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
		return pk;
	}

	/**
	 * Determines whether a signature provided is valid for a given message and
	 * public key
	 * 
	 * @param pubKey
	 *            The public key belonging to the key pair whose private key
	 *            signed the message
	 * @param message
	 *            The message that was signed
	 * @param signature
	 *            The signature over the message
	 * @return Whether the signature provided is valid for the message and
	 *         public key. This method also returns false should an exception
	 *         occur while validating the signature.
	 */
	private boolean isValidSignature(PublicKey pubKey, byte[] message, byte[] signature)  {
		Signature ecdsaVerify;
		try {
			ecdsaVerify = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
			ecdsaVerify.initVerify(pubKey);
			ecdsaVerify.update(message);
			return ecdsaVerify.verify(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
			return false;
		}
		
	}
	
	private byte[] getSignatureBaseString(JSONObject clientDataReceived) {
		// TODO Auto-generated method stub
		return null;
	}
	
	/**
	 * Verifies the user presence byte for compliance with
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf ll. 212-216
	 * 
	 * @param userPresenceByteArray
	 *            A byte array of the length 1 containing the user presence byte
	 *            on position 0
	 * @throws Exception
	 *             If the value of the byte is not 0x1
	 */
	private void verifyUserPresenceByte(byte[] userPresenceByteArray) throws Exception {
		if (userPresenceByteArray[0] != 0x1) {
			throw new Exception("Invalid user Presence State");
		}
	}
	
	/**
	 * Verifies the value of a counter for plausibility
	 * 
	 * @param counter
	 *            The 4 byte unsigned integer counter value as specified in
	 *            fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf
	 * @throws Exception
	 *             If the count value seems implausible
	 */
	private void verifyCounterValue(byte[] counter) throws Exception {
		// TODO Verifiy counter here

	}
	
	/**
	 * Verifies the "bd" parameter as specified in
	 * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll. 266-289.
	 * 
	 * @param bd
	 *            The bd JSON object as a string
	 * @throws JSONException
	 *             If the bd string is not parsable to JSON
	 * @throws Exception
	 *             If the verification failed
	 */
	private void verifyBd(String bd) throws JSONException, Exception {
		JSONObject obj = new JSONObject(bd);
		verifyCidPubkey(obj.getString("cid_pubkey"));
		verifyChallenge(obj.getString("challenge"));
		verifyOrigin(obj.getString("origin"));
	}
	
	/**
	 * Verifies the "origin" parameter as specified in
	 * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll. 276-279.
	 * 
	 * @param origin
	 *            The origin parameter
	 * @throws Exception
	 *             If the verification failed
	 */
	private void verifyOrigin(String origin) throws Exception {
		// TODO Verification here
	}
	
	/**
	 * Verifies the "challenge" parameter as specified in
	 * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll. 273-275.
	 * 
	 * @param challenge
	 *            The challenge parameter
	 * @throws Exception
	 *             If the verification failed
	 */
	private void verifyChallenge(String challenge) throws Exception {
		if (!Arrays.equals(Base64.decodeBase64(challenge), CHALLENGE)) {
			throw new Exception("Challenge returned doesnt equal challenge posed");
		}
	}
	
	/**
	 * Verifies the "cid_pubkey" parameter as specified in
	 * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll. 280-307.
	 * 
	 * @param cidPubkey
	 *            The cid_pubkey parameter
	 * @throws Exception
	 *             If the verification failed
	 */
	private void verifyCidPubkey(String cidPubkey) throws Exception {
		// TODO Verification here

	}
	
	/**
	 * Retrieves the signature bytes as specified in
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf ll. 220-228
	 * 
	 * @param sign
	 *            The complete sign message received from the authenticator
	 * @return The signature bytes
	 */
	private byte[] getSignatureBytes(byte[] sign) {
		return Arrays.copyOfRange(sign, 5, sign.length);
	}
	
	/**
	 * Retrieves the counter bytes as specified in
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf ll. 217-219
	 * 
	 * @param sign
	 *            The complete sign message received from the authenticator
	 * @return The counter bytes
	 */
	private byte[] getCounterBytes(byte[] sign) {
		return Arrays.copyOfRange(sign, 1, 5);
	}
	
	/**
	 * Retrieves the user presence byte as specified in
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf ll. 212-216
	 * 
	 * @param sign
	 *            The complete sign message received from the authenticator
	 * @return The user presence byte wrapped in an array
	 */
	private byte[] getUserPresenceByte(byte[] sign) {
		return Arrays.copyOfRange(sign, 0, 1);
	}

}