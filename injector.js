var s = document.createElement("script");
s.src = chrome.extension.getURL("execute_in_page.js");
(document.head||document.documentElement).appendChild(s);
s.parentNode.removeChild(s);