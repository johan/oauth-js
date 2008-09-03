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

// Here are some unit tests for the software in oauth.js.
// The test data were copied from http://oauth.pbwiki.com/TestCases

function testGetParameterList() {
    var list = OAuth.getParameterList(null);
    if (list == null || !(list instanceof Array) || list.length != 0) {
        alert("getParameterList(null) = " + list);
    }
    var map = OAuth.getParameterMap(null);
    if (map == null || (map instanceof Array) || typeof map != "object") {
        alert("getParameterMap(null) = " + map);
    }
}

var OAUTH_A_BASE_STRING = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&"
    + "file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal";

var BASES = //
    // label, HTTP method, action, parameters, expected
    { "simple"         : ["GET", "http://example.com/", {n: "v"}, "GET&http%3A%2F%2Fexample.com%2F&n%3Dv" ]
    , "no path"        : ["GET", "http://example.com" , {n: "v"}, "GET&http%3A%2F%2Fexample.com%2F&n%3Dv" ]
    , "OAuth A request": ["POST", "https://photos.example.net/request_token",
            { oauth_version: "1.0", oauth_consumer_key: "dpf43f3p2l4k3l03"
            , oauth_timestamp: "1191242090", oauth_nonce: "hsu94j3884jdopsl"
            , oauth_signature_method: "PLAINTEXT", oauth_signature: "ignored"
            }
            , "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&"
                 + "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0" ]
    , "OAuth A access" : ["GET", "http://photos.example.net/photos",
            { file: "vacation.jpg", size: "original"
            , oauth_version: "1.0", oauth_consumer_key: "dpf43f3p2l4k3l03", oauth_token: "nnch734d00sl2jdk"
            , oauth_timestamp: "1191242096", oauth_nonce: "kllo9940pd9333jh"
            , oauth_signature: "ignored", oauth_signature_method: "HMAC-SHA1"
            }
            , OAUTH_A_BASE_STRING ]
    };

function testGetBaseString() {
    for (var label in BASES) {
        try {
            var base = BASES[label];
            var b = 0;
            var method = base[b++];
            var action = base[b++];
            var parameters = base[b++];
            var expected = base[b++];
            var actual = OAuth.SignatureMethod.getBaseString({method: method, action: action, parameters: parameters});
            if (expected != actual) {
                alert(label + "\n" + actual + " (actual)\n" + expected + " (expected)");
            }
        } catch(e) {
            alert(e);
        }
    }
    // alert("tested OAuth.SignatureMethod.getBaseString");
}

var SIGNATURES =
// label, method, consumer secret, token secret, base string, expected
{ "HMAC-SHA1.a"    : [ "HMAC-SHA1", "cs", null, "bs", "egQqG5AJep5sJ7anhXju1unge2I=" ]
, "HMAC-SHA1.b"    : [ "HMAC-SHA1", "cs", "ts", "bs", "VZVjXceV7JgPq/dOTnNmEfO0Fv8=" ]
, "OAuth A access" : [ "HMAC-SHA1", "kd94hf93k423kf44",
                       "pfkkdhi9sl3r4s00", OAUTH_A_BASE_STRING,
                       "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" ]
, "PLAINTEXT"      : [ "PLAINTEXT", "cs", "ts", "bs", "cs&ts" ]
, "OAuth A request": [ "PLAINTEXT", "kd94hf93k423kf44", null, null, "kd94hf93k423kf44&" ]
};

function testGetSignature() {
    for (label in SIGNATURES) {
        try {
            var signature = SIGNATURES[label];
            var s = 0;
            var methodName = signature[s++];
            var consumerSecret = signature[s++];
            var tokenSecret = signature[s++];
            var baseString = signature[s++];
            var expected = signature[s++];
            var signer = OAuth.SignatureMethod.newMethod(methodName,
                         {consumerSecret: consumerSecret, tokenSecret: tokenSecret});
            var actual = signer.getSignature(baseString);
            if (expected != actual) {
                alert(label + "\n" + actual + " (actual)\n" + expected + " (expected)");
            }
        } catch(e) {
            alert(label + ": " + e);
        }
    }
    // alert("tested OAuth.SignatureMethod.getSignature");
}
