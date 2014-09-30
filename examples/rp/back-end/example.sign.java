package de.mplatt.idi.virtualu2f.examples.rp.authentication;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
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
import org.json.JSONException;
import org.json.JSONObject;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


/**
 * Servlet implementation class AuthenticationServlet
 */
@SuppressWarnings("serial")
@WebServlet("/authenticate")
public class AuthenticationServlet extends HttpServlet {
	/**
	 * A dummy public key that would have been obtain upon registration. In the
	 * real world this would be associated with a user and fetched from a
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
		 * response mes- sage as explained in the U2F Raw Message Formats
		 * document.
		 */
		byte[] sign =  Base64.decodeBase64(clientDataReceived.getString("sign"));

		/**
		 * Bit 0 is set to 1, which means that user presence was verified. (This
		 * version of the protocol doesn’t specify a way to request au-
		 * thentication responses without requiring user presence.) A different
		 * value of Bit 0, as well as Bits 1 through 7, are reserved for future
		 * use. The values of Bit 1 through 7 SHOULD be 0.
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

		PublicKey pub = getPublicKeyFromBytes(publicKey);


		//Boolean validSig = isValidSignature();
	}

	private PublicKey getPublicKeyFromBytes(byte[] pub) {
		ECNamedCurveParameterSpec secp256r1 = ECNamedCurveTable.getParameterSpec("secp256r1");
		ECParameterSpec params = new ECNamedCurveSpec("secp256r1", secp256r1.getCurve(), secp256r1.getG(), secp256r1.getN());

		ECCurve curve = secp256r1.getCurve();
		ECDomainParameters domainParams =  new ECDomainParameters(curve, secp256r1.getG(), secp256r1.getN());
		ECPoint point = (ECPoint) curve.decodePoint(pub);

		ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(point, domainParams);


//	    ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
//	            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
//	            params);
		return null;
	}

	private void verifyCounterValue(byte[] counter) throws Exception {
		// TODO Verifiy counter here

	}

	private void verifyBd(String bd) throws JSONException, Exception {
		JSONObject obj = new JSONObject(bd);
		System.out.println(obj);
		verifyCidPubkey(obj.getString("cid_pubkey"));
		verifyChallenge(obj.getString("challenge"));
		verifyOrigin(obj.getString("origin"));
	}

	private void verifyOrigin(String origin) throws Exception {
		// TODO Verification here
	}

	private void verifyChallenge(String challenge) throws Exception {
		if (!Arrays.equals(Base64.decodeBase64(challenge), CHALLENGE)) {
			throw new Exception("Challenge returned doesnt equal challenge posed");
		}
	}

	private void verifyCidPubkey(String cidPubkey) throws Exception {
		// TODO Verification here

	}

	private byte[] getSignatureBytes(byte[] sign) {
		return Arrays.copyOfRange(sign, 5, sign.length);
	}

	private byte[] getCounterBytes(byte[] sign) {
		return Arrays.copyOfRange(sign, 1, 5);
	}

	private byte[] getUserPresenceByte(byte[] sign) {
		return Arrays.copyOfRange(sign, 0, 1);
	}

}
