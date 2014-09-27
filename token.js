var currentRequest = null;

chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
	currentRequest = {
			request : request,
			sender : sender,
			sendResponse : sendResponse
	};
	
	/*
	 * Always return true!
	 * https://code.google.com/p/chromium/issues/detail?id=343007
	 */
	return true;
});

var handleButtonPress = function () {
	if (currentRequest !== null) {
		currentRequest.sendResponse({
			"waiting time" : "is the hardest time"
		});
	}
	
	currentRequest = null;
}
