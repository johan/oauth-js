var termie =
{ consumerKey   : "key"
, consumerSecret: "secret"
, serviceProvider:
  { signatureMethod     : "HMAC-SHA1"
  , requestTokenURL     : "http://term.ie/oauth/example/request_token.php"
  , userAuthorizationURL: "accessToken.html" // a stub
  , accessTokenURL      : "http://term.ie/oauth/example/access_token.php"
  , echoURL             : "http://term.ie/oauth/example/echo_api.php"
  }
};

var mediamatic =
{ consumerKey   : "e388e4f4d6f4cc10ff6dc0fd1637da370478e49e2"
, consumerSecret: "0b062293b6e29ec91a23b2002abf88e9"
, serviceProvider:
  { signatureMethod     : "HMAC-SHA1"
  , requestTokenURL     : "http://oauth-sandbox.mediamatic.nl/module/OAuth/request_token"
  , userAuthorizationURL: "http://oauth-sandbox.mediamatic.nl/module/OAuth/authorize"
  , accessTokenURL      : "http://oauth-sandbox.mediamatic.nl/module/OAuth/access_token"
  , echoURL             : "http://oauth-sandbox.mediamatic.nl/services/rest/?method=anymeta.test.echo"
  }
};

var consumer = termie;

consumer.signForm =
function signForm(form, etc) {
    form.action = etc.URL.value;
    var accessor = { consumerSecret: etc.consumerSecret.value
                   , tokenSecret   : etc.tokenSecret.value};
    var message = { action: form.action
                  , method: form.method
                  , parameters: {}
                  };
    for (var e = 0; e < form.elements.length; ++e) {
        var input = form.elements[e];
        if (input.name != null && input.name != "" && input.value != null) {
            message.parameters[input.name] = input.value;
        }
    }
    OAuth.setTimestampAndNonce(message);
    OAuth.SignatureMethod.sign(message, accessor);
    var parameterMap = OAuth.getParameterMap(message.parameters);
    for (var p in parameterMap) {
        if (form[p] != null && form[p].name != null && form[p].name != "") {
            form[p].value = parameterMap[p];
        }
    }
    return true;
};
