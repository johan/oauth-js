var termie =
{ consumerKey   : "key"
, consumerSecret: "secret"
, serviceProvider:
  { requestTokenURL     : "http://term.ie/oauth/example/request_token.php"
  , userAuthorizationURL: "accessToken.html"
  , accessTokenURL      : "http://term.ie/oauth/example/access_token.php"
  , signatureMethod     : "HMAC-SHA1"
  }
};

var mediamatic =
{ consumerKey   : "e388e4f4d6f4cc10ff6dc0fd1637da370478e49e2"
, consumerSecret: "0b062293b6e29ec91a23b2002abf88e9"
, serviceProvider:
  { requestTokenURL     : "http://oauth-sandbox.mediamatic.nl/module/OAuth/request_token"
  , userAuthorizationURL: "http://oauth-sandbox.mediamatic.nl/module/OAuth/authorize"
  , accessTokenURL      : "http://oauth-sandbox.mediamatic.nl/module/OAuth/access_token"
  , signatureMethod     : "HMAC-SHA1"
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
                  , parameters: { oauth_consumer_key    : form.oauth_consumer_key.value
                                , oauth_signature_method: form.oauth_signature_method.value
                                }
                  };
    if (form.oauth_token != null) {
        OAuth.setParameter(message, "oauth_token", form.oauth_token.value);
    }
    OAuth.setTimestampAndNonce(message);
    OAuth.SignatureMethod.sign(message, accessor);
    for (var p in OAuth.getParameterMap(message.parameters)) {
        form[p].value = message.parameters[p];
    }
    return true;
};
