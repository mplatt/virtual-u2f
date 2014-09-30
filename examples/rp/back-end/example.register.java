package de.mplatt.idi.virtualu2f.examples.rp.enrollment;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Example RP enrollment servlet
 * 
 * Based on fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf
 */
@SuppressWarnings("serial")
@WebServlet("/enroll")
public class EnrollmentServlet extends HttpServlet {
	private static final String CERTIFICATE_TYPE = "X.509";
	private static final String DIGEST_ALGORITHM = "SHA-256";
	private static final String TEXT_ENCODING = "UTF-8";
	private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
	private static final int KEY_HANDLE_LENGTH_POSITION = 66;
	private static final int KEY_HANDLE_BEGINNING = 67;
	
	private static final String REGISTRATION_DATA_KEY = "registrationData";
	private static final String CLIENT_DATA_KEY = "bd";
	private static final String SESSION_ID_KEY = "sessionId";
	private static final String VERSION_KEY = "version";
	private static final String APP_ID_KEY = "app_id";
	private static final String CHALLENGE_KEY = "challenge";
	
	/**
	 * This JSON object contains the data that the RP has sent to the token. It
	 * should be validated first that the authenticator has actually signed the
	 * data provided and not other data.
	 */
	private static final String CLIENT_DATA_SENT = "{version : 'U2F_V2', challenge : 'Ym9ndXM=', app_id : 'http://127.0.0.1', sessionId : '42'}";

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		request.setCharacterEncoding(TEXT_ENCODING);
		
		/**
		 * The parsed HTTP POST request payload.
		 */
		JSONObject clientDataReceived = new JSONObject(IOUtils.toString(request.getReader()));
		
		/**
		 * The client data sent in a accessible format
		 */
		JSONObject clientDataSent = new JSONObject(CLIENT_DATA_SENT);
		
		/**
		 * A reserved byte [1 byte], which for legacy reasons has the value
		 * 0x05.
		 */
		byte reservedByte;
		
		/**
		 * A user public key [65 bytes]. This is the (uncompressed)
		 * x,y-representation of a curve point on the P-256 NIST elliptic curve.
		 */
		byte[] userPublicKey = new byte[65];
		
		/**
		 * A key handle length byte [1 byte], which specifies the length of the
		 * key handle (see below).
		 */
		byte keyHandleLengthByte;
		
		/**
		 * A key handle [length specified in previous field]. This a handle that
		 * allows the U2F token to identify the generated key pair. U2F tokens
		 * MAY wrap the generated private key and the application id it was
		 * generated for, and output that as the key handle.
		 */
		byte[] keyHandle;
		
		/**
		 * An attestation certificate [variable length]. This is a certificate
		 * in X.509 DER format. Parsing of the X.509 certificate unambiguously
		 * establishes its ending.
		 */
		byte[] attestationCertificate = null;
		
		/**
		 * This is a ECDSA signature (on P-256) over the following byte string:
		 * 
		 * - A byte reserved for future use [1 byte] with the value 0x00. This
		 * will evolve into a byte that will allow RPs to track known-good
		 * applet version of U2F tokens from specific vendors.
		 * 
		 * - The application parameter [32 bytes] from the registration request
		 * message.
		 * 
		 * - The challenge parameter [32 bytes] from the registration request
		 * message.
		 * 
		 * - The above key handle [variable length]. (Note that the key handle
		 * length is not included in the signature base string.)
		 * 
		 * - The above user public key [65 bytes].
		 */
		byte[] signature = null; 
		
		try {
			validateJsonStructure(clientDataReceived);
		} catch (Exception e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		byte[] registrationData = Base64.decodeBase64(clientDataReceived.getString(REGISTRATION_DATA_KEY));
		
		byte[] clientData = Base64.decodeBase64(clientDataReceived.getString(CLIENT_DATA_KEY));
		
		/*
		 * Extract bytes with defined position/length
		 */
		reservedByte = extractReservedByte(registrationData);
		userPublicKey = extractUserPublicKey(registrationData);
		keyHandleLengthByte = extractKeyHandleLengthByte(registrationData);
		
		/**
		 * The length of the key handle (usigned integer).
		 */
		int keyHandleLength = (int) keyHandleLengthByte & 0xFF;
		
		keyHandle = extractKeyHandle(registrationData, keyHandleLength);
		
		/*
		 * Extract bytes with implicit position/length
		 */
		try {
			attestationCertificate = getAttestationCertificate(registrationData, keyHandleLength);
		} catch (Exception e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		/**
		 * The certificate as an X509 certificate object
		 */
		X509Certificate attestationCertificateX509 = null;
		
		try {
			attestationCertificateX509 = generateX509FromBytes(attestationCertificate);
		} catch (CertificateException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		try {
			validateCertificate(attestationCertificateX509);
		} catch (Exception e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		try {
			signature = getSignature(registrationData, keyHandleLength, getCertificateLength(getRemainingBytes(registrationData, keyHandleLength)));
		} catch (Exception e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		PublicKey publicKey = attestationCertificateX509.getPublicKey();
		
		byte[] signatureBaseData = null;
		try {
			signatureBaseData = getSignatureBaseData(clientDataSent.getString(APP_ID_KEY), clientDataReceived.getString(CLIENT_DATA_KEY), keyHandle, userPublicKey);
		} catch (NoSuchAlgorithmException | JSONException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		Boolean validSig;
		
		try {
			validSig = isValidSignature(signature, publicKey, signatureBaseData);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println(e);
			return;
		}
		
		if (!validSig) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			System.out.println("Signature invalid");
			return;
		} else {
			/**
			 * Registration was successful. Safe data user's token data to
			 * database
			 */
			registerUserKey(clientDataSent.getString(SESSION_ID_KEY),
					clientDataSent.getString(APP_ID_KEY),
					clientDataSent.getString(VERSION_KEY), keyHandle, userPublicKey);
			
			/**
			 * Send a response to the client
			 */
			response.setContentType("text/plain");
			response.setCharacterEncoding(TEXT_ENCODING);
			response.getWriter().println("success");
		}
	}

	private void registerUserKey(String sessionID, String appID, String version, byte[] keyHandle, byte[] userPublicKey) {
		// TODO Save this permanently
		System.out.println("sessionID: " + sessionID + " appID: " + appID
				+ " version: " + version + " keyHandle: "
				+ Base64.encodeBase64String(keyHandle) + " user public key: "
				+ Base64.encodeBase64String(userPublicKey));
	}

	/**
	 * Determines whether a given signature signs given signature base data.
	 * 
	 * @param signature
	 *            The signature to use for verification
	 * @param publicKey
	 *            The public key taken from the client certificate used for
	 *            signing
	 * @param signatureBaseData
	 *            The data that was signed
	 * @throws NoSuchAlgorithmException
	 *             The SHA256withECDSA algorithm is not known to the provider
	 * @throws InvalidKeyException
	 *             The key provided is invalid
	 * @throws SignatureException
	 *             The signature provided is not valid
	 */
	private boolean isValidSignature(byte[] signature, PublicKey publicKey, byte[] signatureBaseData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM, new BouncyCastleProvider());
		sig.initVerify(publicKey);
		sig.update(signatureBaseData);
		return sig.verify(signature);
	}

	/**
	 * Constructs a signature base string by concatenating different messages
	 * and message digests in the order specified in
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf ll. 139-149.
	 * 
	 * @param applicationParameter
	 *            The UTF-8 encoded string of the application parameter
	 * @param challengeParameter
	 *            The UTF-8 encoded string the validator sent back
	 * @param keyHandle
	 *            The key handle of the received key
	 * @param userPublicKey
	 *            The public key assigned to the RP
	 * @return The concatenated signature base data
	 * @throws NoSuchAlgorithmException
	 *             If the MessageDigest class doesn't support SHA-256
	 * @throws IOException
	 */
	private byte[] getSignatureBaseData(String applicationParameter, String challengeParameter, byte[] keyHandle, byte[] userPublicKey) throws NoSuchAlgorithmException, IOException {
		MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
		byte[] futureUseByte = new byte[1];
		futureUseByte[0] = 0x00;
		byte[] applicationParameterDigest = digest.digest(applicationParameter.getBytes(TEXT_ENCODING));
		byte[] challengeParameterDigest = digest.digest(challengeParameter.getBytes(TEXT_ENCODING));
		
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		os.write(futureUseByte);
		os.write(applicationParameterDigest);
		os.write(challengeParameterDigest);
		os.write(keyHandle);
		os.write(userPublicKey);
		return os.toByteArray();
	}
	
	/**
	 * Retrieves the signature from the registration data by performing a
	 * "copy of range",
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @param keyHandleLength
	 *            The length of the key handle contained in the registration data
	 *            received
	 * @param certificateLength
	 *            The length of the certificate contained in the registration
	 *            data received
	 * @return The raw signature
	 */
	private byte[] getSignature(byte[] registrationData, int keyHandleLength, int certificateLength) {
		return Arrays.copyOfRange(registrationData, (KEY_HANDLE_BEGINNING + keyHandleLength + certificateLength), registrationData.length);
	}

	/**
	 * Validates if a certificate provided is trusted TODO Implement certificate
	 * verification
	 * 
	 * @param attestationCertificateX509
	 *            The certificate to validate
	 * @throws Exception
	 *             Should the certificate be untrusted
	 */
	@SuppressWarnings("unused")
	private void validateCertificate(X509Certificate attestationCertificateX509) throws Exception {
		if (false) {
			throw new Exception("Untrusted Certificate");
		}
	}
	
	/**
	 * Creates a X.509 certificate from a byte array containing DER certificate
	 * information
	 * 
	 * @param bytes
	 *            The byte array containing the DER certificate
	 * @return The X.509 certificate extracted
	 * @throws CertificateException
	 *             If the X.509 certificate factory can not be instanciated
	 */
	private X509Certificate generateX509FromBytes(byte[] bytes) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_TYPE);
		return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
	}
	
	/**
	 * Extracts the bytes for a X.509 certificate according to the encoding
	 * rules specified in http://tools.ietf.org/html/rfc5280#section-4.1
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @param keyHandleLength
	 *            the length of the key handle contained in the registration
	 *            data received
	 * @return The raw attestation certificate as DER formatted byte array
	 * @throws Exception
	 */
	private byte[] getAttestationCertificate(byte[] registrationData, int keyHandleLength) throws Exception {
		byte[] remainingBytes = getRemainingBytes(registrationData, keyHandleLength);
		return Arrays.copyOfRange(remainingBytes, 0, getCertificateLength(remainingBytes));
	}

	/**
	 * Calculates the length of a certificate contained in a byte array. Here,
	 * the DER formatted certificate bytes have to be positioned at the
	 * beginning of the array. The method will then determine the length of the
	 * DER formatted certificate and will return its length.
	 * 
	 * @param remainingBytes
	 *            A byte array containing a DER formatted certificate beginning
	 *            at the first element of the array
	 * @return The length of the contained certificate
	 * @throws Exception
	 */
	private int getCertificateLength(byte[] remainingBytes) throws Exception {
		if ((remainingBytes[1] & 0xFF) < 0x81) {
			/*
			 * Certificate Length < 128
			 */
			return (remainingBytes[1] & 0xFF) + 2;
		} else if ((remainingBytes[1] & 0xFF) == 0x81) {
			/*
			 * 128 <= Certificate Length < 256
			 */
			return (remainingBytes[2] & 0xFF) + 3;
		} else if ((remainingBytes[1] & 0xFF) == 0x82) {
			/*
			 * 256 <= Certificate Length < 64KiB
			 */
			return (unsignedShortToInt(Arrays.copyOfRange(remainingBytes, 2, 4))) + 4;
		} else {
			/*
			 * Certificate Length > 64KiB (?)
			 */
			throw new Exception("Unsupported certificate length specified");
		}
	}
	
	/**
	 * The method retrieves the remaining bytes from a byte array formatted as
	 * sepcified in fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf section
	 * 3.3. The remaining bytes are the bytes composed of the attestation
	 * certificate bytes and the signature bytes.
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @param keyHandleLength
	 *            The length of the key handle contained in the registration
	 *            data received
	 * @return A byte array containing the attestation certificate bytes and the
	 *         signature bytes
	 * @throws Exception
	 */
	private byte[] getRemainingBytes(byte[] registrationData, int keyHandleLength) throws Exception {
		byte[] remainingBytes = Arrays.copyOfRange(registrationData, (KEY_HANDLE_BEGINNING + keyHandleLength), registrationData.length);
		
		if (remainingBytes[0] != 0x30) {
			throw new Exception("Invalid first byte in presumed X.509 certificate");
		}
		return remainingBytes;
	}
	
	/**
	 * Extracts the key handle from the registration data
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @param length
	 *            The length of the key handle to extract
	 * @return The raw key handle
	 */
	private byte[] extractKeyHandle(byte[] registrationData, int length) {
		return Arrays.copyOfRange(registrationData, KEY_HANDLE_BEGINNING, (KEY_HANDLE_BEGINNING + length));
	}

	/**
	 * Extracts the length of a key handle from registration data
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @return The byte that represents an unsigned integer containing the
	 *         length of the key handle
	 */
	private byte extractKeyHandleLengthByte(byte[] registrationData) {
		return registrationData[KEY_HANDLE_LENGTH_POSITION];
	}
	
	/**
	 * Extracts the 65 byte user public key specified in
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf ll. 128-129 from
	 * registration data.
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @return The 65 byte user public key
	 */
	private byte[] extractUserPublicKey(byte[] registrationData) {
		return Arrays.copyOfRange(registrationData, 1, KEY_HANDLE_LENGTH_POSITION);
	}

	/**
	 * Extracts the reserved byte described in
	 * fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf l. 127 from
	 * registration data
	 * 
	 * @param registrationData
	 *            The registration data received from the authenticator
	 * @return The reserved byte
	 */
	private byte extractReservedByte(byte[] registrationData) {
		return registrationData[0];
	}


	/**
	 * Structurally validates the object provided for registration for
	 * compliance to fido-u2f-javascript-api-v1.0-rd-20140209.pdf section 4.
	 * 
	 * @param jsonObject
	 *            The JSON object containing the data
	 * @throws Exception
	 *             If the structure is invalid
	 */
	private void validateJsonStructure(JSONObject jsonObject) throws Exception {
		System.out.println(jsonObject);
		if (!jsonObject.has(CLIENT_DATA_KEY)) {
			JSONObject inner = jsonObject.getJSONObject(CLIENT_DATA_KEY);
			if (!inner.has("typ") || !inner.has("challenge")
					|| !inner.has("origin") || !inner.has("cid_pubkey")) {
				/*
				 * The data provided is obviously invalid (wrong structure).
				 */
				throw new Exception("Invalid JSON structure");
			}
		}
	}
	
	/**
	 * Converts a two byte array to an integer
	 * http://www.petefreitag.com/item/183.cfm
	 * 
	 * @param b
	 *            a byte array of length 2
	 * @return an int representing the unsigned short
	 */
	public static final int unsignedShortToInt(byte[] b) {
		int i = 0;
		i |= b[0] & 0xFF;
		i <<= 8;
		i |= b[1] & 0xFF;
		return i;
	}

}
