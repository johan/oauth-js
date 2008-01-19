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

var OAuth = {};

OAuth.declare = function(scope, members) {
    for (name in members) {
        scope[name] = members[name];
    }
}

OAuth.declare(OAuth, { // class members

    percentEncode: function(s) {
        if (s == null) {
            return "";
        }
        if (s instanceof Array) {
            var e = "";
            for (i = 0; i < s.length; ++i) {
                if (e != "") e += '&';
                e += percentEncode(s[i]);
            }
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
    },

    decodePercent: function(s) {
        return decodeURIComponent(s);
    },

    getParameterList: function(parameters) {
        if (parameters == null) {
            return [];
        }
        if (typeof parameters == "object") {
            if (parameters instanceof Array) {
                return parameters;
            }
            var list = [];
            for (p in parameters) {
                list.push([p, parameters[p]]);
            }
            return list;
        }
        return decodeForm(parameters + "");
    },

    getParameterMap: function(parameters) {
        if (parameters == null) {
            return {};
        }
        if (typeof parameters == "object") {
            if (parameters instanceof Array) {
                var map = {};
                for (p = 0; p < parameters.length; ++p) {
                    map[parameters[p][0]] = parameters[p][1];
                }
                return map;
            }
            return parameters;
        }
        return toParameterMap(decodeForm(parameters + ""));
    },

    formEncode: function(parameters) {
        var form = "";
        var list = OAuth.getParameterList(parameters);
        if (list != null) {
            var first = true;
            for (p = 0; p < list.length; ++p) {
                if (form != "") form += '&';
                form += OAuth.percentEncode(list[p][0])
                  +'='+ OAuth.percentEncode(list[p][1]);
            }
        }
        return form;
    },

    decodeForm: function(form) {
        var list = [];
        for (nvp in form.split('&')) {
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
    },

    setParameter: function(message, name, value) {
        var parameters = message.parameters;
        if (parameters instanceof Array) {
            for (var p = 0; p < parameters.length; ++p) {
                if (parameters[p][0] == name) {
                    if (value == null) {
                        parameters.splice(p, 1);
                    } else {
                        parameters[p][1] = value;
                        value = null;
                    }
                }
            }
            if (value != null) {
                parameters.push([name, value]);
            }
        } else {
            parameters = OAuth.getParameterMap(parameters);
            parameters[name] = value;
            message.parameters = parameters;
        }
    },

    setParameters: function(message, parameters) {
        var list = OAuth.getParameterList(parameters);
        for (var i = 0; i < list.length; ++i) {
            OAuth.setParameter(message, list[i][0], list[i][1]);
        }
    },

    setTimestampAndNonce: function(message) {
        OAuth.setParameter(message, "oauth_timestamp", OAuth.timestamp());
        OAuth.setParameter(message, "oauth_nonce", OAuth.nonce(6));
    },

    timestamp: function() {
        var d = new Date();
        return Math.floor(d.getTime()/1000);
    },

    _NONCE_CHARS: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz",

    nonce: function(length) {
        var chars = OAuth._NONCE_CHARS;
        var result = "";
        for (var i=0; i<length; i++) {
            var rnum = Math.floor(Math.random() * chars.length);
            result += chars.substring(rnum, rnum+1);
        }
        return result;
    },

    addParameters: function(url, parameters) {
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
    },
});

/** An abstract algorithm for signing messages. */
OAuth.SignatureMethod = function () {
}

OAuth.declare(OAuth.SignatureMethod.prototype, { // instance members

    /** Add a signature to the message. */
    sign: function(message) {
        OAuth.setParameter(message, "oauth_signature", this.getSignature(OAuth.SignatureMethod.getBaseString(message)));
    },

    /** Get the key string for signing. */
    getKey: function() {
        var key = OAuth.percentEncode(this.accessor.consumerSecret)
            +"&"+ OAuth.percentEncode(this.accessor.tokenSecret);
        return key;
    },
});

// Class members:
OAuth.declare(OAuth.SignatureMethod, { // class members

    /** Instantiate a SignatureMethod for the given methodName. */
    newMethod: function(methodName, accessor) {
        var constructor = OAuth.SignatureMethod.REGISTERED[methodName];
        if (constructor == null) {
            var err = new Error("signature_method_rejected");
            var acceptable = "";
            for (name in OAuth.SignatureMethod.REGISTERED) {
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
    },

    /** A map from signature method name to constructor. */
    REGISTERED : {},

    /** Subsequently, the given constructor will be used for the given method. */
    registerMethodClass: function(oauth_signature_method, constructor) {
        OAuth.SignatureMethod.REGISTERED[oauth_signature_method] = constructor;
    },

    /** Create a subclass of OAuth.SignatureMethod, with the given getSignature function. */
    makeSubclass: function(getSignatureFunction) {
        getSignatureFunction.tag = "getSignature";
        var subclass = function() {
            this.superclass();
        }; 
        subclass.tag = "extends OAuth.SignatureMethod";
        subclass.prototype = new OAuth.SignatureMethod();
        subclass.prototype.superclass = OAuth.SignatureMethod;
        subclass.prototype.constructor = subclass;
        // Delete properties inherited from superclass:
        // delete ... There aren't any.
        // Since the prototype object was created with the superclass constructor,
        // it has a constructor property that refers to that constructor.  But
        // we want subclass instancess to have a different constructor
        // property, so we've got to reassign this default constructor property.
        subclass.prototype.getSignature = getSignatureFunction;
        return subclass;
    },

    getBaseString: function(message) {
        var parameters;
        var q = message.URL.indexOf('?');
        if (q < 0) {
            parameters = message.parameters;
        } else {
            // Combine the URL query string with the other parameters:
            parameters = OAuth.decodeForm(message.URL.substring(q + 1));
            var toAdd = OAuth.getParameterList(message.parameters);
            for (p = 0; p < toAdd.length; ++p) {
                parameters.push(toAdd[p]);
            }
        }
        return OAuth.percentEncode(message.httpMethod.toUpperCase())
         +'&'+ OAuth.percentEncode(message.URL)
         +'&'+ OAuth.percentEncode(OAuth.SignatureMethod.normalizeParameters(parameters));
    },

    normalizeParameters: function(parameters) {
        if (parameters == null) {
            return "";
        }
        var list = OAuth.getParameterList(parameters);
        var norm = [];
        for (p = 0; p < list.length; ++p) {
            var name = list[p][0];
            if (name != "oauth_signature") {
                norm.push(list[p]);
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
    },
});

OAuth.SignatureMethod.registerMethodClass("PLAINTEXT",
        OAuth.SignatureMethod.makeSubclass(
        function(baseString) { // getSignature
            return this.getKey();
        }
    ));

OAuth.SignatureMethod.registerMethodClass("HMAC-SHA1",
        OAuth.SignatureMethod.makeSubclass(
        function(baseString) { // getSignature
            b64pad = '=';
            var signature = b64_hmac_sha1(this.getKey(), baseString);
            return signature;
        }
    ));
