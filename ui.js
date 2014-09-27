var bkg = chrome.extension.getBackgroundPage();

$(document).ready(function() {
	$("#touch").on("click", function(e) {
		e.preventDefault();
		bkg.handleButtonPress();
	});
});