/*
 * Copyright 2008 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Here's some JavaScript software that's useful for implementing OAuth.

// The HMAC-SHA1 signature method calls functions defined by
// http://pajhome.org.uk/crypt/md5/sha1.js

/* An OAuth message is represented like this:
   {method: "GET", action: "http://server.com/path", parameters: ...}

   The parameters may be either a map {name: value, name2: value2}
   or an Array of name-value pairs [[name, value], [name2, value2]].
   The latter representation is more powerful: it supports parameters
   in a specific sequence, or several parameters with the same name;
   for example [["a", 1], ["b", 2], ["a", 3]].
 */
var OAuth; if (OAuth == null) OAuth = {};

OAuth.setProperties = function setProperties(into, from) {
    for (var key in from) {
        into[key] = from[key];
    }
}

OAuth.setProperties(OAuth, // utility functions
{
    percentEncode: function(s) {
        if (s == null) {
            return "";
        }
        if (s instanceof Array) {
            var e = "";
            for (var i in s) {
                if (e != "") e += '&';
                e += percentEncode(s[i]);
            }
            return e;
        }
        s = encodeURIComponent(s);
        // Now replace the values which encodeURIComponent doesn't do
        // encodeURIComponent ignores: - _ . ! ~ * ' ( )
        // OAuth dictates the only ones you can ignore are: - _ . ~
        // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
        s = s.replace("!", "%21", "g");
        s = s.replace("*", "%2A", "g");
        s = s.replace("'", "%27", "g");
        s = s.replace("(", "%28", "g");
        s = s.replace(")", "%29", "g");
        return s;
    }
,
    decodePercent: decodeURIComponent
,
    getParameterList: function(parameters) {
        if (parameters == null) {
            return null;
        }
        if (typeof parameters != "object") {
            return decodeForm(parameters + "");
        }
        if (parameters instanceof Array) {
            return parameters;
        }
        var list = [];
        for (var p in parameters) {
            list.push([p, parameters[p]]);
        }
        return list;
    }
,
    getParameterMap: function(parameters) {
        if (parameters == null) {
            return null;
        }
        if (typeof parameters != "object") {
            return getParameterMap(decodeForm(parameters + ""));
        }
        if (parameters instanceof Array) {
            var map = {};
            for (var p in parameters) {
                var key = parameters[p][0];
                if (map[key] === undefined) { // first value wins
                    map[key] = parameters[p][1];
                }
            }
            return map;
        }
        return parameters;
    }
,
    formEncode: function(parameters) {
        var form = "";
        var list = OAuth.getParameterList(parameters);
        if (list != null) {
            for (var p in list) {
                var value = list[p][1];
                if (value == null) value = "";
                if (form != "") form += '&';
                form += OAuth.percentEncode(list[p][0])
                  +'='+ OAuth.percentEncode(value);
            }
        }
        return form;
    }
,
    decodeForm: function(form) {
        var list = [];
        var nvps = form.split('&');
        for (var n in nvps) {
            var nvp = nvps[n];
            var equals = nvp.indexOf('=');
            var name;
            var value;
            if (equals < 0) {
                name = OAuth.decodePercent(nvp);
                value = null;
            } else {
                name = OAuth.decodePercent(nvp.substring(0, equals));
                value = OAuth.decodePercent(nvp.substring(equals + 1));
            }
            list.push([name, value]);
        }
        return list;
    }
,
    setParameter: function(message, name, value) {
        var parameters = message.parameters;
        if (parameters instanceof Array) {
            for (var p in parameters) {
                if (parameters[p][0] == name) {
                    if (value === undefined) {
                        parameters.splice(p, 1);
                    } else {
                        parameters[p][1] = value;
                        value = undefined;
                    }
                }
            }
            if (value !== undefined) {
                parameters.push([name, value]);
            }
        } else {
            parameters = OAuth.getParameterMap(parameters);
            parameters[name] = value;
            message.parameters = parameters;
        }
    }
,
    setParameters: function(message, parameters) {
        var list = OAuth.getParameterList(parameters);
        for (var i in list) {
            OAuth.setParameter(message, list[i][0], list[i][1]);
        }
    }
,
    setTimestampAndNonce: function(message) {
        OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
        OAuth.setParameter(message, "oauth_nonce", OAuth.nonce(6));
    }
,
    addToURL: function(url, parameters) {
        newURL = url;
        if (parameters != null) {
            var toAdd = OAuth.formEncode(parameters);
            if (toAdd.length > 0) {
                var q = url.indexOf('?');
                if (q < 0) newURL += '?';
                else       newURL += '&';
                newURL += toAdd;
            }
        }
        return newURL;
    }
,
    timestamp: function() {
        var d = new Date();
        return Math.floor(d.getTime()/1000);
    }
,
    nonce: function(length) {
        var chars = OAuth.nonce.CHARS;
        var result = "";
        for (var i = 0; i < length; ++i) {
            var rnum = Math.floor(Math.random() * chars.length);
            result += chars.substring(rnum, rnum+1);
        }
        return result;
    }
});

OAuth.nonce.CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";

/** An abstract algorithm for signing messages. */
OAuth.SignatureMethod = function OAuthSignatureMethod() {
}

OAuth.setProperties(OAuth.SignatureMethod.prototype, // instance members
{
    /** Add a signature to the message. */
    sign: function(message) {
        var signature = this.getSignature(OAuth.SignatureMethod.getBaseString(message));
        OAuth.setParameter(message, "oauth_signature", signature);
        return signature; // just in case someone's interested
    }
,
    /** Get the key string for signing. */
    getKey: function() {
        var key = OAuth.percentEncode(this.accessor.consumerSecret)
            +"&"+ OAuth.percentEncode(this.accessor.tokenSecret);
        return key;
    }
});

// Class members:
OAuth.setProperties(OAuth.SignatureMethod, // class members
{
    /** Instantiate a SignatureMethod for the given methodName. */
    sign: function(message, accessor) {
        var methodName = OAuth.getParameterMap(message.parameters).oauth_signature_method;
        OAuth.SignatureMethod.newMethod(methodName, accessor).sign(message);
    }
,
    /** Instantiate a SignatureMethod for the given methodName. */
    newMethod: function(methodName, accessor) {
        var constructor = OAuth.SignatureMethod.REGISTERED[methodName];
        if (constructor == null) {
            var err = new Error("signature_method_rejected");
            var acceptable = "";
            for (var name in OAuth.SignatureMethod.REGISTERED) {
                if (acceptable != "") acceptable += '&';
                acceptable += OAuth.percentEncode(name);
            }
            err.oauth_acceptable_signature_methods = acceptable;
            throw err;
        }
        var method = new constructor();
        method.oauth_signature_method = methodName;
        method.accessor = accessor;
        return method;
    }
,
    /** A map from signature method name to constructor. */
    REGISTERED : {}
,
    /** Subsequently, the given constructor will be used for the given method. */
    registerMethodClass: function(methodName, constructor) {
        OAuth.SignatureMethod.REGISTERED[methodName] = constructor;
    }
,
    /** Create a subclass of OAuth.SignatureMethod, with the given getSignature function. */
    makeSubclass: function(getSignatureFunction) {
        var subclass = function subclassOfSignatureMethod() {
            this.superClass();
        }; 
        subclass.prototype = new OAuth.SignatureMethod();
        subclass.prototype.superClass = OAuth.SignatureMethod;
        subclass.prototype.constructor = subclass;
        // Delete properties inherited from superClass:
        // delete ... There aren't any.
        subclass.prototype.getSignature = getSignatureFunction;
        return subclass;
    }
,
    getBaseString: function(message) {
        var URL = message.action;
        var q = URL.indexOf('?');
        var parameters;
        if (q < 0) {
            parameters = message.parameters;
        } else {
            // Combine the URL query string with the other parameters:
            parameters = OAuth.decodeForm(URL.substring(q + 1));
            var toAdd = OAuth.getParameterList(message.parameters);
            for (var a in toAdd) {
                parameters.push(toAdd[a]);
            }
            URL = URL.substring(0, q);
        }
        return OAuth.percentEncode(message.method.toUpperCase())
         +'&'+ OAuth.percentEncode(URL)
         +'&'+ OAuth.percentEncode(OAuth.SignatureMethod.normalizeParameters(parameters));
    }
,
    normalizeParameters: function(parameters) {
        if (parameters == null) {
            return "";
        }
        var norm = [];
        var list = OAuth.getParameterList(parameters);
        for (var p in list) {
            var nvp = list[p];
            if (nvp[0] != "oauth_signature") {
                norm.push(nvp);
            }
        }
        norm.sort(function(a,b) {
                      if (a[0] < b[0]) return -1;
                      if (a[0] > b[0]) return 1;
                      if (a[1] < b[1]) return  -1;
                      if (a[1] > b[1]) return 1;
                      return 0;
                  });
        return OAuth.formEncode(norm);
    }
});

OAuth.SignatureMethod.registerMethodClass("PLAINTEXT",
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return this.getKey();
        }
    ));

OAuth.SignatureMethod.registerMethodClass("HMAC-SHA1",
    OAuth.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            b64pad = '=';
            var signature = b64_hmac_sha1(this.getKey(), baseString);
            return signature;
        }
    ));
