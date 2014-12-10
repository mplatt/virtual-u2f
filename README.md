Virtual FIDO U2F Token Chrome Extension
=======================================

A full JavaScript implementation of a virtual [FIDO U2F](http://fidoalliance.org/specifications/download/) token and a JavaScript API to conveniently access it.

This extension is inspired by Google's [u2f-chrome-extension](https://github.com/google/u2f-ref-code/tree/master/u2f-chrome-extension) but does not require a hardware token.
Google's u2f-chrome-extension is much more elaborate and should be preferred should you have access to a hardware token.
This extension only serves as a last resort for those who require to use a virtual token in absence of available hardware or hardware interfaces or as an educational tool for understanding the internals of a U2F token.

Disclaimer
----------

I have developed this extension as a quick emergency solution because I wanted to work with FIDO U2F technology in my thesis but I was not able to obtain a hardware token that worked as expected.
The extension is based on the FIDO Alliance Universal 2nd Factor (U2F) specification draft as of 2014-02-09, still it does not completely implement it (see *To Do*) and it might even violate it.
Furthermore, since this draft is is not intended to be a basis for any implementations, this extension might not comply with later editions of the specifications.
This extension is a makeshift development tool and should never be used for authentication in any production scenario.

Objective
---------

This extension does three things:

 1. It provides a high level JavaScript API by adding a `window.u2f` object to every page opened in Chrome, similar to Google's [u2f-chrome-extension](https://github.com/google/u2f-ref-code/tree/master/u2f-chrome-extension). This allows websites to access the `window.u2f.register` and `window.u2f.sign` methods.
 2. It provides a user interface, listing tokens and allowing to perform a user presence check by clicking a button.
 3. It provides a JavaScript implementation of a token that emmits messages as specified in [FIDO U2F Raw Message Formats](http://fidoalliance.org/specs/fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf).

Installation
------------

 1. Download and extract the extension to a directory of your choice.
 2. Open Google Chrome's extension manager by opening `chrome://extensions/` or chose *Menu > Settings > Extensions* in the chrome UI.
 3. Make sure *Developer Mode* is checked in the upper right hand corner.
 4. Choose *Load Unpacked Extension*
 5. Navigate to the directory of the downloaded extension. And click *open*.
 6. You should now see *Virtual FIDO U2F Token Extension* in the list of extensions.

Configuration
-------------

#### Make Extension Externally Connectable

For security reasons, in the Chrome extension system you have to manually specify web pages that can talk to an extension. If the domain is not in the list of connectable locations, the extension will fail silently. By default the extension is configured to only be connectable by connections from `127.0.0.1`, `localhost` and `mplatt.github.io` (with the latter being included for historical reasons only). To add other locations you need to open `manifest.json` from the extensions folder in a text editor. Locate the following lines:

```JavaScript
	"externally_connectable": {
		"matches": [
            "*://localhost/*",
            "*://127.0.0.1/*",
            "*://mplatt.github.io/*"
		]
	}
```

Here, you can add web pages where the extension should run. For format and allowed wild cards consult the [Chrome extension documentation](https://developer.chrome.com/extensions/manifest/externally_connectable).

Say, you wanted to be able to connect to the extension through all protocols and from all subdomains of your domain `example.org`. To achieve this you would edit the list of externally connectable locations like that:

```JavaScript
	"externally_connectable": {
		"matches": [
            "*://localhost/*",
            "*://127.0.0.1/*",
            "*://mplatt.github.io/*",
            "*://*.example.org/*"
		]
	}
```

After editing the manifest you need to reload the extension by choosing *reload* in `chrome://extensions/`.

Usage
-----

After installation and configuration you will be able to use the extension as a virtual U2F token. It comes with a little visual user interface that shows what would normally be stored internally. It is hidden under the *FIDO U2F Simulation* button (the tiny USB stick icon with blue and red lines). Click this button to bring up the user interface.

It will expose the following details of your virtual token:

 * The X.509 signature certificate (as DER in hexadecimal format)
 * The private attestation key (this of course would never be exposed with a hardware device and is only shown for debugging)
 * The public attestation key

The following information is displayed for every key generated:

 * The key handle
 * The key generatiohn time
 * The app ID
 * The public (user) key
 * The private (user) key
 * The current number of the authentication counter

Much like the real deal, this extension only provides a single way of user interaction: The user presence test. It is performed by clicking the *Simulate Touch* button.

You can use this interface just like you would use a real hardware token.
Whenever a web application asks you to touch you device to either sign in or register, simply press the *Simulate Touch* button. The extension will mimic the response a regular FIDO hardware token would give and will expose the internal of the keystore to you in the user interface.

Examples
--------

#### Registration/Enrollment

The syntax for registration calls is taken from [fido-u2f-javascript-api-v1.0-rd-20140209.pdf](https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20140209.pdf).

##### RP Client Side

Invoking a register request from the site of a relying party is as simple as calling `window.u2f.register` with the registration data format described in the [specification](https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20140209.pdf).
The example below will try to register with a token using the `U2F_V2` protocol using the challenge `62 6F 67 75 73` (the Base64 encoded ASCII string "bogus") with the application id `http://127.0.0.1` and the session id `42`.
The extension will then return either a message of the type `u2f.RegisterResponse` should the user presence test be successful or `u2f.Error` should the user presence test time out.

```JavaScript
/**
 * Commented example for a registration call prepared by a relying party (RP).
 */
window.u2f.register([
	{
		registrationData: {
			// Version of the protocol that the to-be-registered U2F token must
			// speak. For the version of the protocol described herein, must be
			// "U2F_V2".
			version : "U2F_V2",
			
			// The websafe-base64-encoded challenge.
			// This happens to be text but any binary data is fine...
			challenge : btoa("bogus"),
			
			// The application id that the RP would like to assert. The new key
			// pair that the U2F device generates will be associated with this
			// application id.
			app_id : "http://127.0.0.1",
			
			// A session id created by the RP. The RP can opaquely store things 
			// like expiration times for the registration session, protocol 
			// version used, private key material that certain protocol
			// versions require, etc.
			// The response from the API will include the sessionId. This
			// allows the RP to fire off multiple registration requests, and
			// associate the response with the correct request. (Note: this
			// might be more accurately called "relying_party_state", but for
			// compatibility with existing implementations within Chrome we
			// keep the legacy name.)
			sessionId : "42"
		}
	}
], [{
	// SignData
	//
	// "Additionally, it [the RP] should prepare SignData objects for each U2F
	// token that the user has already registered with the RP (see below) and
	// then call handleRegistrationRequest on a CryptoTokenHandler object."
}], function (data) {
    // registration is complete
	$.ajax({
        url : "/enroll",
        contentType : "application/json",
        dataType : "json",
        processData : false,
        type : "POST",
        data : JSON.stringify(data),
        success : function(data){
            // enroll data sent successfully
        }
    });
}, 20); // use 20s timeout
```

The RP can then forward the data obtained to an application server where the `u2f.RegisterResponse` can be validated.
The following Java program code is an example for the server side validation of the `u2f.RegisterResponse` at the fictitious end point `/enroll`.

The POST request triggered by the `ajax` call above will be along the lines of the following example:

```
POST /de.mplatt.idi.virtualu2f.examples/enroll HTTP/1.1
Host: localhost:8080
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Cache-Control: no-cache
{"registrationData":"BQRt2Aw0hHQyvWcM1yMRuhrIFZbwx4Lj4tuuNNIdg8JoTb2lJyV8QrtIpuwzO0pof5mA+gxwgOgCBfkycrr7GxCEE2JvZ3VzXzE0MTIxNzY1MjAwODQwggG0MIIBWKADAgECAgEBMAwGCCqGSM49BAMCBQAwYTELMAkGA1UEBhMCREUxJjAkBgNVBAoMHVVudHJ1c3R3b3J0aHkgQ0EgT3JnYW5pc2F0aW9uMQ8wDQYDVQQIDAZCZXJsaW4xGTAXBgNVBAMMEFVudHJ1c3R3b3J0aHkgQ0EwIhgPMjAxNDA5MjQxMjAwMDBaGA8yMTE0MDkyNDEyMDAwMFowXjELMAkGA1UEBhMCREUxITAfBgNVBAoMGHZpcnR1YWwtdTJmLW1hbnVmYWN0dXJlcjEPMA0GA1UECAwGQmVybGluMRswGQYDVQQDDBJ2aXJ0dWFsLXUyZi12MC4wLjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATDyR8lLiAQe16N6rGQIJj3KHBx5FQYuJjOX/F8pyWueMM8xwHAdGARy7u1iwi2HSDAXnXVAaP496FnP74yY66+MAwGCCqGSM49BAMCBQADSAAwRQIhAI65IFeh80FPG3kaWOYHq6RmHJNh+8S6iWVcijvsEGjaAiAVkKh28IBH32COI7IqoKrSSw1JyXUzAK8ytpBz8KGk2zBFAiAVym4kHZvDc7HUGQY40TiQZnrqu4nTPXYp87a0xYl55AIhAMS2GpDUj9uZdfV44pbd/AY5ung0Ql0h6aFi8RuCP1A2","clientData":"{\"version\":\"U2F_V2\",\"challenge\":\"Ym9ndXM=\",\"app_id\":\"http://127.0.0.1\",\"sessionId\":\"42\"}"} 
```

##### RP Server Side

We assume, the example servlet receives the data in the request *payload*.
This could be achieved through an ajax call similar to the jQuery example above.
The POST request payload can then be validated by the RP application server.
Should the validation be successful, the RP would store the relevant data in a server side database for future use.

Following is a simplified example implementation of a relying party enrollment servlet in Java 1.6.
This implementation validates the string received and replies with `success` should the registration be successful.

```Java
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

```

#### Sign In

##### RP Client Side

For signing in, the client must first register her authenticator with the RP, providing it with a public key.
Implementation examples for this step are given above.

*After* a user has registered, she can authenticate.
The first step in authentication is a JavaScript call similiar to the one described above from the site of the RP.

An example call can be found below.
Note that the key handle needs to be generated beforehand and is only allowed to be used with the `app_id` specified during registration.
Cross-app usage of keys is not possible.

Please also note that in order to follow this example, you will first need to generate a key.

```JavaScript
/**
 * Commented example for a authentication call prepared by a relying party (RP).
 */
window.u2f.sign([{
    // Version of the protocol that the to-be-registered U2F token must
    // speak. For the version of the protocol described herein, must be
    // "U2F_V2".
    version : "U2F_V2",

    // The websafe-base64-encoded challenge.
    // This happens to be text but any binary data is fine...
    challenge : btoa("bogus"),

    // The application id that the RP would like to assert. The new key
    // pair that the U2F device generates will be associated with this
    // application id.
    app_id : "http://127.0.0.1",

    // A session id created by the RP. The RP can opaquely store things
    // like expiration times for the registration session, protocol
    // version used, private key material that certain protocol
    // versions require, etc.
    // The response from the API will include the sessionId. This
    // allows the RP to fire off multiple registration requests, and
    // associate the response with the correct request. (Note: this
    // might be more accurately called "relying_party_state", but for
    // compatibility with existing implementations within Chrome we
    // keep the legacy name.)
    sessionId : "42",

    // The key handle. This is provided by the relying party, and was obtained
    // by the relying party during registration.
    // This happens to be text but any binary data is fine...
    keyHandle: btoa("dummy_key_handle")
}], function (data) {
    // registration is complete
	$.ajax({
        url : "/authenticate",
        contentType : "application/json",
        dataType : "json",
        processData : false,
        type : "POST",
        data : JSON.stringify(data),
        success : function(data){
            // sign data sent successfully
        }
    });
}, 20); // use 20s timeout
```

The request triggered should be similar to the following:

```
POST /de.mplatt.idi.virtualu2f.examples/authenticate HTTP/1.1
Host: localhost:8080
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Cache-Control: no-cache

{"bd":"{\"typ\":\"navigator.id.getAssertion\",\"challenge\":\"Ym9ndXM=\",\"origin\":\"https://mplatt.github.io\",\"cid_pubkey\":\"unused\"}","sign":"AQAVMEUCIQDsWF3Dgb/oI38yhp7QhgyqKRKZWtYv7uAhLEZdwJe/vQIgFJW3XZbqAFY7yx716I7pkl+WQkfKi/4msKmmXu+irG0=","sessionId":"42","app_id":"http://127.0.0.1"}
```

##### RP Server Side

The following examples shows a fictitious end point `/authenticate` that will receive the registration response data (specified in ll. 254 - 256 of [fido-u2f-javascript-api-v1.0-rd-20140209.pdf](https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20140209.pdf)).
The server application will then validate the response using a database of previously established keys (in this example it is only one static key).

Please note that in the following example, most verification methods are not implemented.
A RP authentication server implementation would need to appropriatly validate the counter value (`verifyCounterValue`), the request origin parameter (`verifyOrigin`) and the cid_publickey parameter (`verifyCidPubkey`).

```Java
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
```

To Do
-----

##### Registration/Enrollment

 * At the moment only the first element of an array of sign requests is used.
 * [fido-u2f-javascript-api-v1.0-rd-20140209.pdf](https://fidoalliance.org/specs/fido-u2f-javascript-api-v1.0-rd-20140209.pdf) states that "Additionally, it [the RP] should prepare SignData objects for each U2F token that the user has already registered with the RP (see below) and then call handleRegistrationRequest on a CryptoTokenHandler object." This is ignored so far.
 * There is no specification compliant check whether a facet id is allowed for an app id yet.

##### Authentication/Signing

 * So far, only the control byte `0x03` ("enforce-user-presence-and-sign") is supported.

Cryptographic Internals
-----------------------

#### Attestation Certificate

The virtual token contains a self signed X.509 attestation certificate to sign challenges:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=DE, O=Untrustworthy CA Organisation, ST=Berlin, CN=Untrustworthy CA
        Validity
            Not Before: Sep 24 12:00:00 2014 GMT
            Not After : Sep 24 12:00:00 2114 GMT
        Subject: C=DE, O=virtual-u2f-manufacturer, ST=Berlin, CN=virtual-u2f-v0.0.1
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:c3:c9:1f:25:2e:20:10:7b:5e:8d:ea:b1:90:20:
                    98:f7:28:70:71:e4:54:18:b8:98:ce:5f:f1:7c:a7:
                    25:ae:78:c3:3c:c7:01:c0:74:60:11:cb:bb:b5:8b:
                    08:b6:1d:20:c0:5e:75:d5:01:a3:f8:f7:a1:67:3f:
                    be:32:63:ae:be
                ASN1 OID: prime256v1
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:8e:b9:20:57:a1:f3:41:4f:1b:79:1a:58:e6:
         07:ab:a4:66:1c:93:61:fb:c4:ba:89:65:5c:8a:3b:ec:10:68:
         da:02:20:15:90:a8:76:f0:80:47:df:60:8e:23:b2:2a:a0:aa:
         d2:4b:0d:49:c9:75:33:00:af:32:b6:90:73:f0:a1:a4:db
```

PEM Format:

```
-----BEGIN CERTIFICATE-----
MIIBtDCCAVigAwIBAgIBATAMBggqhkjOPQQDAgUAMGExCzAJBgNVBAYTAkRFMSYw
JAYDVQQKDB1VbnRydXN0d29ydGh5IENBIE9yZ2FuaXNhdGlvbjEPMA0GA1UECAwG
QmVybGluMRkwFwYDVQQDDBBVbnRydXN0d29ydGh5IENBMCIYDzIwMTQwOTI0MTIw
MDAwWhgPMjExNDA5MjQxMjAwMDBaMF4xCzAJBgNVBAYTAkRFMSEwHwYDVQQKDBh2
aXJ0dWFsLXUyZi1tYW51ZmFjdHVyZXIxDzANBgNVBAgMBkJlcmxpbjEbMBkGA1UE
AwwSdmlydHVhbC11MmYtdjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
w8kfJS4gEHtejeqxkCCY9yhwceRUGLiYzl/xfKclrnjDPMcBwHRgEcu7tYsIth0g
wF511QGj+PehZz++MmOuvjAMBggqhkjOPQQDAgUAA0gAMEUCIQCOuSBXofNBTxt5
GljmB6ukZhyTYfvEuollXIo77BBo2gIgFZCodvCAR99gjiOyKqCq0ksNScl1MwCv
MraQc/ChpNs=
-----END CERTIFICATE-----
```

#### Attestation Key Pair

The *ECDSA-secp256r1* key pair used for attestation is the following:

Private Key:

```
D3 0C 9C AC 7D A2 B4 A7 D7 1B 00 2A 40 A3 B5 9A
96 CA 50 8B A9 C7 DC 61 7D 98 2C 4B 11 D9 52 E6
```

Public Key:

```
04 C3 C9 1F 25 2E 20 10 7B 5E 8D EA B1 90 20 98
F7 28 70 71 E4 54 18 B8 98 CE 5F F1 7C A7 25 AE
78 C3 3C C7 01 C0 74 60 11 CB BB B5 8B 08 B6 1D
20 C0 5E 75 D5 01 A3 F8 F7 A1 67 3F BE 32 63 AE
BE
```

Third Party Software/Licenses
-----------------------------

This project is released under the terms of the MIT license.

#### Google's U2F Chrome Plugin

The structure/method signatures of *api.js* are taken from [Google's U2F Chrome Plugin](https://github.com/google/u2f-ref-code/blob/master/u2f-chrome-extension/u2f-api.js).

> Copyright (c) 2013, Google Inc.
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
>
> Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
>
> Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
>
> Neither the name of Google Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### jQuery v2.1.1

The user interface works with [jQuery 2](http://jquery.com/):

> (c) 2005, 2014 jQuery Foundation, Inc. | jquery.org/license

#### jsrsasign 4.2.2


> The 'jsrsasign'(RSA-Sign JavaScript Library) License
> 
> Copyright (c) 2010-2013 Kenji Urushima
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
> THE SOFTWARE.
