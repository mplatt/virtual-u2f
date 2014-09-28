/**
 * Scirpt element that that contains the API script.
 * @type {HTMLElement}
 */
var s = document.createElement("script");
s.src = chrome.extension.getURL("api.js");
(document.head||document.documentElement).appendChild(s);
s.parentNode.removeChild(s);