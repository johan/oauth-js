/*
  OAuth.js
  by Rod Begbie
  
  Distributed under the BSD License
  http://www.opensource.org/licenses/bsd-license.php
*/


// Prevent crashing on browsers without the superb Firebug debugging tool
if (!window.console || !console.firebug)
{
    var names = ["log", "debug", "info", "warn", "error", "assert", "dir", "dirxml",
    "group", "groupEnd", "time", "timeEnd", "count", "trace", "profile", "profileEnd"];

    window.console = {};
    for (var i = 0; i < names.length; ++i)
        window.console[names[i]] = function() {}
}


function OAuth() {
    this.token = "";
    this.token_secret = "";
    this.consumer_key = "";
    this.consumer_secret = "";
    this.nonce = "";
    this.timestamp = -1;

    this.version = "1.0";
    this.signature_method = "HMAC-SHA1"; // Currently hard-coded.  Future versions may allow more control.
    
    this.url = "";
    this.params = "";
    
    this.getSignature = _getSignature;
    this.getOAuthParams = _getOAuthParams;
    this.updateTimestamp = _updateTimestamp;
    this.parseTokens = _parseTokens;
    
    function _updateTimestamp() {
        this.timestamp = timeStamp();
        this.nonce = randomString();
    }
    
    function timeStamp() {
    	var d = new Date();
    	return Math.floor(d.getTime()/1000);
    }

    function randomString() {
    	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
    	var string_length = 6;
    	var randomstring = '';
    	for (var i=0; i<string_length; i++) {
    		var rnum = Math.floor(Math.random() * chars.length);
    		randomstring += chars.substring(rnum,rnum+1);
    	}
    	return randomstring;
    }

    function _getOAuthParams() {
        var params = {	"oauth_consumer_key": this.consumer_key,
    					"oauth_version": this.version,
    					"oauth_signature_method": this.signature_method,
    					"oauth_nonce": this.nonce,
    					"oauth_timestamp": this.timestamp
    	};
    	if (this.token) {
		    // Don't include oauth_token if it's not set
		    // (ma.gnolia.com freaked when I did)
    	    params["oauth_token"] = this.token;
    	}
    	return params;
    }

    function _getSignature(method, url, params) {
        // merge params with oauth_ parameters
        oauthParams = this.getOAuthParams();
        for (param in params) {
            oauthParams[param] = params[param];
        }
        
    	// sort param keys
    	keys = new Array();
    	for (key in oauthParams) {
    		keys.push(key);
    	}
    	keys.sort();
	
    	//build paramstring
    	paramArray = new Array();
    	for (i=0; i < keys.length; i++) {
		    key = keys[i];
		    paramArray.push(_oauthEncode(key + "=" + oauthParams[key]));
    	}
    	paramstring = paramArray.join(encodeURIComponent("&"));
	
	    // TODO: "Normalize" the URL.
	
    	// Build the Signature Base String
    	base = method.toUpperCase() + "&" +
    			_oauthEncode(url) + "&" +
    			paramstring;
    			
    	console.debug("Base string: " + base);
    	
    	key = this.consumer_secret + "&" + this.token_secret;
	
    	// Base 64 MD5 it
    	signature = b64_hmac_sha1(key, base) + "=";
    	console.debug("Signature: " + signature)
	
    	return signature;
    }
    
    function _parseTokens(tokenString) {
        var bits = tokenString.split("&");
        for (bit in bits) {
            keyval = bits[bit].split("=");
            if (keyval[0] == "oauth_token") {
                this.token = keyval[1];
            } else if (keyval[0] == "oauth_token_secret") {
                this.token_secret = keyval[1];
            } else {
                console.warn("Unknown parameter in response: " + bit)
            }
        }
    }
    
    function _oauthEncode(parameter) {
        parameter = encodeURIComponent(parameter);
        
        // Now replace the values which encodeURIComponent doesn't do
        // encodeURIComponent ignores: - _ . ! ~ * ' ( )
        // OAuth dictates the only ones you can ignore are: - _ . ~
        // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
        
        parameter = parameter.replace("!", "%21", "g");
        parameter = parameter.replace("*", "%2A", "g");
        parameter = parameter.replace("'", "%27", "g");
        parameter = parameter.replace("(", "%28", "g");
        parameter = parameter.replace(")", "%29", "g");
        
        return parameter;
    }

}