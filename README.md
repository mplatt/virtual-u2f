Virtual FIDO U2F Token Chrome Extension
=======================================

A full JavaScript implementation of a virtual [FIDO U2F](http://fidoalliance.org/specifications/download/) token and a JavaScript API to conveniently access it.

This extension is inspired by Google's [u2f-chrome-extension](https://github.com/google/u2f-ref-code/tree/master/u2f-chrome-extension) but does not require a hardware token.
Google's u2f-chrome-extension is much more elaborate and should be preferred should you have access to a hardware token.
This extension only serves as a last resort for those who require to use a virtual token in absence of available hardware or hardware interfaces.

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

For security reasons, in the Chrome extension system you have to manually specify web pages that can talk to an extension. If the domain is not in the list of connectable locations, the extension will fail silently. By default the extension is configured to only be connectable by http connections from 127.0.0.1 (this excludes `localhost`). To add other locations you need to open `manifest.json` from the extensions folder in a text editor. Locate the following lines:

```JavaScript
	"externally_connectable": {
		"matches": [
			"http://127.0.0.1/*"
		]
	}
```

Here, you can add web pages where the extension should run. For format and allowed wild cards consult the [Chrome extension documentation](https://developer.chrome.com/extensions/manifest/externally_connectable).

Say, you wanted to be able to connect to the extension through all protocols and from all subdomains of your domain example.org. To achieve this you would edit the list of externally connectable locations like that:

```JavaScript
	"externally_connectable": {
		"matches": [
			"http://127.0.0.1/*",
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

##### RP Client Side

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
	console.log(data);
}, 20); // use 20s timeout
```

##### RP Server Side

```Java
 TO BE DONE
```

#### Sign In

##### RP Client Side

```JavaScript
 TO BE DONE
```

##### RP Server Side

```Java
 TO BE DONE
```

To Do
-----

 * **Implement Authentication**
 * At the moment only the first element of an array of sign requests is used.
 * `fido-u2f-javascript-api-v1.0-rd-20140209.pdf` states that "Additionally, it [the RP] should prepare SignData objects for each U2F token that the user has already registered with the RP (see below) and then call handleRegistrationRequest on a CryptoTokenHandler object." This is ignored so far.
 * There is no specification compliant check whether a facet id is allowed for an app id yet.

Cryptographic Internals
-----------------------

#### Attestation Certificate

The virtual token constains a self signed X.509 attestation certificate to sign challenges:

```
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
                04:36:1f:01:5c:81:c6:b8:cf:7a:14:a4:85:6f:19:
                f6:a3:e4:10:1f:7b:8b:4c:a4:bd:b1:27:01:80:62:
                5c:be:fe:0e:b8:53:4d:ef:bb:73:bb:65:06:31:2b:
                82:87:83:0e:13:13:7d:e4:99:cb:61:50:83:03:fd:
                6f:8b:5b:18:6f
            ASN1 OID: prime256v1
Signature Algorithm: ecdsa-with-SHA256
     30:46:02:21:00:a9:d2:9a:c6:69:2a:6c:a1:3b:15:bb:64:e7:
     74:f3:eb:81:92:bd:a1:f2:60:a7:6a:31:57:ba:46:79:f8:86:
     41:02:21:00:d1:ab:b8:80:44:3a:f6:5e:fa:60:4c:a1:cd:29:
     04:3b:0b:ef:8d:78:16:b4:fb:cd:2e:d5:da:64:b2:94:27:51
```

PEM Format:

```
-----BEGIN CERTIFICATE-----
MIIBtTCCAVigAwIBAgIBATAMBggqhkjOPQQDAgUAMGExCzAJBgNVBAYTAkRFMSYw
JAYDVQQKDB1VbnRydXN0d29ydGh5IENBIE9yZ2FuaXNhdGlvbjEPMA0GA1UECAwG
QmVybGluMRkwFwYDVQQDDBBVbnRydXN0d29ydGh5IENBMCIYDzIwMTQwOTI0MTIw
MDAwWhgPMjExNDA5MjQxMjAwMDBaMF4xCzAJBgNVBAYTAkRFMSEwHwYDVQQKDBh2
aXJ0dWFsLXUyZi1tYW51ZmFjdHVyZXIxDzANBgNVBAgMBkJlcmxpbjEbMBkGA1UE
AwwSdmlydHVhbC11MmYtdjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
Nh8BXIHGuM96FKSFbxn2o+QQH3uLTKS9sScBgGJcvv4OuFNN77tzu2UGMSuCh4MO
ExN95JnLYVCDA/1vi1sYbzAMBggqhkjOPQQDAgUAA0kAMEYCIQCp0prGaSpsoTsV
u2TndPPrgZK9ofJgp2oxV7pGefiGQQIhANGruIBEOvZe+mBMoc0pBDsL7414FrT7
zS7V2mSylCdR
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