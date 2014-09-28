var bkg = chrome.extension.getBackgroundPage();

$(document).ready(function() {
	$("#touch").on("click", function(e) {
		e.preventDefault();
		bkg.handleButtonPress();
	});
	
	$("#empty").on("click", function(e) {
		e.preventDefault();
		bkg.emptykeyStore();
	});
	
	var updateKeyList = function (keys) {
		var DELETEABLE_CLASS_NAME = "deleteable";
		
		var keysUi = $("#keys");
		
		if (jQuery.isEmptyObject(keys)) {
			$("#nokeys").show();
		} else {
			$("#nokeys").hide();
		}
		
		/*
		 * Mark all keys as deleteable first
		 */
		keysUi.find(".key").addClass(DELETEABLE_CLASS_NAME);
		
		for (var key in keys) {
			var keyUi = keysUi.find("#" + key);
			var keyO = keys[key];
			
			if (keyUi.length > 0) {
				/*
				 * Key already exists remove deleteable marker
				 */
				keyUi.removeClass(DELETEABLE_CLASS_NAME);
			} else {
				/*
				 * Key doesn't exist in UI. Create!
				 */
				keysUi.append("<div id=\"key\" class=\"key\"><h4>Key Handle <strong>" + keyO.keyHandle + "</strong><br>" + keyO.generated + "</h4><h5>App ID <strong>" + keyO.appId + "</strong></h5><h6>Public Key:</h6><p>" + keyO.public + "</p><h6>Private Key:</h6><p>" + keyO.private + "</p></div>")
			}
		}
		
		/*
		 * Remove nodes marked as deleteable
		 */
		keysUi.find("." + DELETEABLE_CLASS_NAME).remove();
	};
	
	/*
	 * Poll keystore for new key
	 */
	var timer;
	
	(function updateUI(){
		updateKeyList(bkg.getKeyStore());
		timer = window.setTimeout(updateUI, 1200);
	})();
});