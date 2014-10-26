
// Global variables
var JAVA_READY_FLAG = false;

// Get the applet object
function getJAgoraBridge(){
	return document.getElementById('JAgoraJSBridge');
}

// Applet reports it is ready to use
function javaSocketBridgeReady(){
	JAVA_READY_FLAG = true;
        alert("Applet Ready!");
}