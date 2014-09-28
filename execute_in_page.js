/**
 * @fileoverview U2F JavaScript API
 * 
 * Method stubs based on Google's U2F Chrome Extension 
 * https://github.com/google/u2f-ref-code/blob/master/u2f-chrome-extension/
 * 
 * Code used is Copyright 2014 Google Inc. All rights reserved
 * Use of this source code is governed by a BSD-style license that can be found
 * in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

(function(){
	'use strict';
	
	/**
	 * ID of the extension to talk to
	 * @const
	 */
	var ext = "jbajmoemaliemjjifbbonkbngbemppcl";
	
	/** 
	 * Namespace for the U2F api.
	 * @type {Object}
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
	 * @typedef {{
	 *   type: u2f.MessageTypes,
	 *   signRequests: Array.<u2f.SignRequest>,
	 *   registerRequests: ?Array.<u2f.RegisterRequest>,
	 *   timeoutSeconds: ?number,
	 *   requestId: ?number
	 * }}
	 */
	u2f.Request;
	
	/**
	 * A message for registration responses
	 * @typedef {{
	 *   type: u2f.MessageTypes,
	 *   responseData: (u2f.Error | u2f.RegisterResponse | u2f.SignResponse),
	 *   requestId: ?number
	 * }}
	 */
	u2f.Response;
	
	/**
	 * An error object for responses
	 * @typedef {{
	 *   errorCode: u2f.ErrorCodes,
	 *   errorMessage: ?string
	 * }}
	 */
	u2f.Error;
	
	/**
	 * Data object for a single sign request.
	 * @typedef {{
	 *   version: string,
	 *   challenge: string,
	 *   keyHandle: string,
	 *   appId: string
	 * }}
	 */
	u2f.SignRequest;
	
	/**
	 * Data object for a sign response.
	 * @typedef {{
	 *   keyHandle: string,
	 *   signatureData: string,
	 *   clientData: string
	 * }}
	 */
	u2f.SignResponse;
	
	/**
	 * Data object for a registration request.
	 * @typedef {{
	 *   version: string,
	 *   challenge: string,
	 *   appId: string
	 * }}
	 */
	u2f.RegisterRequest;
	
	/**
	 * Data object for a registration response.
	 * @typedef {{
	 *   registrationData: string,
	 *   clientData: string
	 * }}
	 */
	u2f.RegisterResponse;
	
	
	// Low level MessagePort API support
	
	/**
	 * Sets up a MessagePort to the U2F extension using the
	 * available mechanisms.
	 * @param {function((MessagePort|u2f.WrappedChromeRuntimePort_))} callback
	 */
	u2f.getMessagePort = function(callback) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * Connects directly to the extension via chrome.runtime.connect
	 * @param {function(u2f.WrappedChromeRuntimePort_)} callback
	 * @private
	 */
	u2f.getChromeRuntimePort_ = function(callback) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * A wrapper for chrome.runtime.Port that is compatible with MessagePort.
	 * @param {Port} port
	 * @constructor
	 * @private
	 */
	u2f.WrappedChromeRuntimePort_ = function(port) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * Posts a message on the underlying channel.
	 * @param {Object} message
	 */
	u2f.WrappedChromeRuntimePort_.prototype.postMessage = function(message) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * Emulates the HTML 5 addEventListener interface. Works only for the
	 * onmessage event, which is hooked up to the chrome.runtime.Port.onMessage.
	 * @param {string} eventName
	 * @param {function({data: Object})} handler
	 */
	u2f.WrappedChromeRuntimePort_.prototype.addEventListener = function(eventName, handler) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * Sets up an embedded trampoline iframe, sourced from the extension.
	 * @param {function(MessagePort)} callback
	 * @private
	 */
	u2f.getIframePort_ = function(callback) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	
	// High-level JS API
	
	/**
	 * Default extension response timeout in seconds.
	 * @const
	 */
	u2f.EXTENSION_TIMEOUT_SEC = 30;
	
	/**
	 * A singleton instance for a MessagePort to the extension.
	 * @type {MessagePort|u2f.WrappedChromeRuntimePort_}
	 * @private
	 */
	u2f.port_ = null;
	
	/**
	 * Callbacks waiting for a port
	 * @type {Array.<function((MessagePort|u2f.WrappedChromeRuntimePort_))>}
	 * @private
	 */
	u2f.waitingForPort_ = [];
	
	/**
	 * A counter for requestIds.
	 * @type {number}
	 * @private
	 */
	u2f.reqCounter_ = 0;
	
	/**
	 * A map from requestIds to client callbacks
	 * @type {Object.<number,(function((u2f.Error|u2f.RegisterResponse))
	 *                       |function((u2f.Error|u2f.SignResponse)))>}
	 * @private
	 */
	u2f.callbackMap_ = {};
	
	/**
	 * Creates or retrieves the MessagePort singleton to use.
	 * @param {function((MessagePort|u2f.WrappedChromeRuntimePort_))} callback
	 * @private
	 */
	u2f.getPortSingleton_ = function(callback) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * Handles response messages from the extension.
	 * @param {MessageEvent.<u2f.Response>} message
	 * @private
	 */
	u2f.responseHandler_ = function(message) {
		throw new Error("Low level MessagePort API support is not implemented");
	};
	
	/**
	 * Dispatches an array of sign requests to available U2F tokens.
	 * @param {Array.<u2f.SignRequest>} signRequests
	 * @param {function((u2f.Error|u2f.SignResponse))} callback
	 * @param {number=} opt_timeoutSeconds
	 */
	u2f.sign = function(signRequests, callback, opt_timeoutSeconds) {
		console.log("chrome.runtime.sendMessage --> sign");
		chrome.runtime.sendMessage(ext, {
				type : "sign",
				request : {
					signRequests : [{
						appId: "http://127.0.0.1/",
						challenge: "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
						version: "U2F_V2"
					}],
					callback : callback,
					opt_timeoutSeconds : opt_timeoutSeconds
				}
			},
			function(response) {
				console.log(response);
				// TODO callback();
			}
		);
//	  u2f.getPortSingleton_(function(port) {
//	    var reqId = ++u2f.reqCounter_;
//	    u2f.callbackMap_[reqId] = callback;
//	    var req = {
//	      type: u2f.MessageTypes.U2F_SIGN_REQUEST,
//	      signRequests: signRequests,
//	      timeoutSeconds: (typeof opt_timeoutSeconds !== 'undefined' ?
//	        opt_timeoutSeconds : u2f.EXTENSION_TIMEOUT_SEC),
//	      requestId: reqId
//	    };
//	    port.postMessage(req);
//	  });
	};
	
	/**
	 * Dispatches register requests to available U2F tokens. An array of sign
	 * requests identifies already registered tokens.
	 * @param {Array.<u2f.RegisterRequest>} registerRequests
	 * @param {Array.<u2f.SignRequest>} signRequests
	 * @param {function((u2f.Error|u2f.RegisterResponse))} callback
	 * @param {number=} opt_timeoutSeconds
	 */
	u2f.register = function(registerRequests, signRequests, callback, opt_timeoutSeconds) {
		chrome.runtime.sendMessage(ext, {
				type : "register",
				request : {
					signRequests : [{
						appId: "http://127.0.0.1/",
						challenge: "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
						version: "U2F_V2"
					}],
					callback : callback,
					opt_timeoutSeconds : opt_timeoutSeconds
				}
			},
			function(response) {
				console.log(response);
				// TODO callback();
			}
		);
//	  u2f.getPortSingleton_(function(port) {
//	    var reqId = ++u2f.reqCounter_;
//	    u2f.callbackMap_[reqId] = callback;
//	    var req = {
//	      type: u2f.MessageTypes.U2F_REGISTER_REQUEST,
//	      signRequests: signRequests,
//	      registerRequests: registerRequests,
//	      timeoutSeconds: (typeof opt_timeoutSeconds !== 'undefined' ?
//	        opt_timeoutSeconds : u2f.EXTENSION_TIMEOUT_SEC),
//	      requestId: reqId
//	    };
//	    port.postMessage(req);
//	  });
	};
})();