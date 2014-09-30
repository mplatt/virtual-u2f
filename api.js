/**
 * U2F JavaScript API
 *
 * Method stubs based on Google's U2F Chrome Extension
 * https://github.com/google/u2f-ref-code/blob/master/u2f-chrome-extension/
 */
(function () {
    'use strict';

    /**
     * ID of the extension to talk to
     * @const
     * @type {string}
     */
    var EXTENSION_ID = "iomeponhhjanajlkbdjnfjicdhcfjbmd";

    /**
     * Default time out in seconds
     * @const
     * @type {number}
     */
    var TIMEOUT = 60;

    /**
     * Namespace for the U2F api.
     * @type {*|Window.u2f|{}}
     */
    window.u2f = window.u2f || {};

    /**
     * Message types for messsages to/from the extension
     * @const
     * @enum {string}
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
     * @enum {number}
     */
    u2f.ErrorCodes = {
        'OK': 0,
        'OTHER_ERROR': 1,
        'BAD_REQUEST': 2,
        'CONFIGURATION_UNSUPPORTED': 3,
        'DEVICE_INELIGIBLE': 4,
        'TIMEOUT': 5
    };

    /**
     * A message type for registration requests
     * @typedef {{type: u2f.MessageTypes, signRequests: Array.<u2f.SignRequest>, registerRequests: ?Array.<u2f.RegisterRequest>, timeoutSeconds: ?number, requestId: ?number}}
     */
    u2f.Request;

    /**
     * A message for registration responses
     * @typedef {{type: u2f.MessageTypes, responseData: (u2f.Error | u2f.RegisterResponse | u2f.SignResponse), requestId: ?number}}
     */
    u2f.Response;

    /**
     * An error object for responses
     * @typedef {{errorCode: u2f.ErrorCodes, errorMessage: ?string}}
     */
    u2f.Error;

    /**
     * Data object for a single sign request.
     * @typedef {{version: string, challenge: string, keyHandle: string, appId: string}}
     */
    u2f.SignRequest;

    /**
     * Data object for a sign response.
     * @typedef {{keyHandle: string, signatureData: string, clientData: string}}
     */
    u2f.SignResponse;

    /**
     * Data object for a registration request.
     * @typedef {{version: string, challenge: string, appId: string}}
     */
    u2f.RegisterRequest;

    /**
     * Data object for a registration response.
     * @typedef {{registrationData: string, clientData: string}}
     */
    u2f.RegisterResponse;

    // High-level JS API

    /**
     * Dispatches register requests to available U2F tokens. An array of sign
     * requests identifies already registered tokens.
     * @param {Array.<u2f.RegisterRequest>} registerRequests
     * @param {Array.<u2f.SignRequest>} signRequests
     * @param {function((u2f.Error|u2f.RegisterResponse))} callback
     * @param {number=} opt_timeoutSeconds
     */
    u2f.register = function (registerRequests, signRequests, callback, opt_timeoutSeconds) {
    	// TODO check for existence of all non-opt parameters
    	
        /**
         * Whether the call has been answered yet. Either by response or by timeout message.
         * @type {boolean}
         */
        var answered;

        if (!originAllowed(registerRequests) || !originAllowed(signRequests)) {
            //throw new Error("Origin not allowed");
            console.warn("Origin host does not match app_id host.");
        }

        /**
         * @type {{type: (u2f.MessageTypes.U2F_REGISTER_REQUEST|u2f.MessageTypes.U2F_SIGN_REQUEST), signRequests: Array.<u2f.SignRequest>, registerRequests: Array.<u2f.RegisterRequest>, timeoutSeconds: number}}
         */
        var req = {
            type: u2f.MessageTypes.U2F_REGISTER_REQUEST,
            signRequests: transformRequestChallenge(signRequests, u2f.MessageTypes.U2F_SIGN_REQUEST),
            registerRequests: transformRequestChallenge(registerRequests, u2f.MessageTypes.U2F_REGISTER_REQUEST)
        };

        answered = false;

        var timeout = setTimeout(function () {
            if (!answered) {
                answered = true;
                callback({
                    errorCode: u2f.ErrorCodes.TIMEOUT,
                    errorMessage: "Request timed out"
                });
            }
        }, (typeof opt_timeoutSeconds !== 'undefined' ? (opt_timeoutSeconds * 1000) : (u2f.EXTENSION_TIMEOUT_SEC *1000)));

        chrome.runtime.sendMessage(EXTENSION_ID, req, function (response) {
            if (!answered) {
                answered = true;
                callback(response);
            }
        });
    };

    /**
     * Checks whether the origins specified in the requests are applicable for their app ids
     * TODO This simplistic check does not comply with the specification. See "FIDO U2F Application Isolation through
     * Facet Identification".
     *
     * @param {Array.<u2f.Request>} requests The requests which should be validated
     * @returns {boolean} Whether the origins specified in the requests are applicable for their app ids
     */
    var originAllowed = function(requests) {
        if (typeof requests !== "undefined" && requests !== null) {
            return true;
        }

        for (var i = 0; i < requests.length; i++) {
            if (!String.beginsWithIgnoreCase(getOriginFromRequest(), requests[i].appId)) {
                return false;
            }
        }
        return true;
    };

    /**
     * Transforms the requests from simple binary only challenge requests to requests that have a proper client data
     * structure as defined in fido-u2f-raw-message-formats-v1.0-rd-20140209.pdf.
     *
     * @param {Array.<u2f.Request>} requests The requests which should be validated
     * @param {u2f.MessageTypes.U2F_REGISTER_REQUEST|u2f.MessageTypes.U2F_SIGN_REQUEST} type The request type
     */
    function transformRequestChallenge (requests, type) {
        for (var i = 0; i < requests.length; i++) {
            var request = requests[i];
            var originalChallenge = request.challenge;
            request.challenge = {};

            request.challenge.typ = (function(type){
                if (type === u2f.MessageTypes.U2F_REGISTER_REQUEST) {
                    // the constant ‘navigator.id.finishEnrollment’ for registration
                   return "navigator.id.finishEnrollment";
                } else if (type === u2f.MessageTypes.U2F_SIGN_REQUEST) {
                    // the constant ‘navigator.id.getAssertion’ for authentication
                    return "navigator.id.getAssertion";
                } else {
                    return null;
                }
            })(type);

            // the websafe-base64-encoded challenge provided by the relying party
            request.challenge.challenge = originalChallenge;

            // the facet id of the caller, i.e., the web origin of the relying party.
            // (Note: this might be more accurately called 'facet_id', but
            // for compatibility with existing implementations within Chrome we keep
            // the legacy name.)
            //
            // As per fido-u2f-application-isolation-through-facet-identification-v1.0-rd-20140209.pdf
            // the facet id is "a platform-specific identifier (URI) for an
            // application facet".
            // The specification states that "For the Web, the facet id is the
            // web origin, written as a URI without a path (e.g.,
            // 'https://login.paypal.com' (default ports are omitted))."
            //
            // Thus, it is appropriate to use the origin of the request as
            // origin/facet id parameter.
            request.challenge.origin = getOriginFromRequest();

            // The Channel ID public key used by this browser to communicate with the
            // above origin. This parameter is optional, and missing if the browser
            // doesn’t support Channel ID. It is present and set to the constant
            // ‘unused’ if the browser supports Channel ID, but is not using
            // Channel ID to talk to the above origin (presumably because the origin
            // server didn’t signal support for the Channel ID TLS extension).
            // Otherwise (i.e., both browser and origin server at the above
            // origin support Channel ID), it is present and of type JwkKey
            // TODO Implement JwkKey support
            request.challenge.cid_pubkey = "unused";

            requests[i] = request;
        }

        return requests;
    }

    /**
     * Gets the request origin in a format compliant to
     * fido-u2f-application-isolation-through-facet-identification-v1.0-rd-20140209.pdf
     * @returns {string} The origin URL of the request where default ports are ommitted
     */
    var getOriginFromRequest = function() {
        return location.protocol + '//' + location.hostname + (location.port ? ':' + location.port : '');
    };
})();