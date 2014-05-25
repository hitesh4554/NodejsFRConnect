// NodeJs external modules
var express = require('express'),
    request = require('request'),
    FormData = require('form-data'),
    https = require('https'),
    qs = require('qs'),
    fs = require('fs'),
    util = require('util'),
    sax = require('sax'),
    http = require('http'),
    crypto = require('crypto'),
    url = require('url');

//Facebook API credentials used to OAuth and make API calls
var APP_ID = YOUR_FLICKR_API_ID;
var APP_SECRET = YOUR_FLICKR_API_SECRET;
var REDIRECT_URI = YOUR_REDIRECT_URI;

// URLs
var requestURL = "http://www.flickr.com/services/oauth/request_token";
var authURL = "http://www.flickr.com/services/oauth/authorize";
var tokenURL = "http://www.flickr.com/services/oauth/access_token";
var uploadURL = "http://up.flickr.com/services/upload/";
var serviceURL = "http://api.flickr.com/services/rest/";
var BUDDY_ICON_FORMAT =
  "http://farm%iconfarm%.staticflickr.com/%iconserver%/buddyicons/%id%.jpg";

// Global variables
var tokenSecretDict = {};


/* URL: /user_details
 * Info: The below function will get the user's details
 * from Flickr */
exports.getUserDetails=function (req, response) {
  try {
    var body = req.body;
    if (!body || !body.token || !body.token_secret ||
        !body.fr_user_id) {
      var error = 'missing_params';
      response.end(JSON.stringify({'error': error}));
      return;
    }

    var token = body.token;
    var token_secret = body.token_secret;
    var fr_user_id = body.fr_user_id;

    var reqParams = {};
    reqParams['token'] = token;
    reqParams['token_secret'] = token_secret;
    reqParams['logs'] = logs;
    reqParams['query'] = {
      'method': 'flickr.people.getInfo',
      'user_id': fr_user_id
    };
    services(reqParams, function (err, data) {
      if (err) {
        response.end(JSON.stringify({'error': err}));
        return;
      }
      jsonObject = data['jsonObject'];
      console.log(JSON.stringify(jsonObject));
      if (jsonObject.rsp && jsonObject.rsp.stat=="ok") {
        var pictureUrl = BUDDY_ICON_FORMAT;
        pictureUrl = pictureUrl.replace('%iconfarm%', jsonObject.person.iconfarm)
          .replace('%iconserver%', jsonObject.person.iconserver)
          .replace('%id%', jsonObject.person.id);
        response.end(JSON.stringify({
          'picture_url': pictureUrl, 'data':jsonObject
        }));
      }
      else if(jsonObject.rsp && jsonObject.rsp.stat=="fail") {
        response.end(JSON.stringify({"error":jsonObject.err.code}));
      }
      return;
    });
  }
  catch (e) {
    console.log('CaughtException: '+e.stack);
    response.end(JSON.stringify({'error': e}));
    return;
  }
};

/* URL: /callback
 * Info: Callback route that is called by Flickr once user
 * has authenticated himself */
exports.callback=function (req, response) {
  try {
    var query = req.query;
    console.log('Query: ',req.query);
    if (!query || !query.oauth_token || !query.oauth_verifier) {
      response.end();
      return;
    }
    if (!tokenSecretDict && !tokenSecretDict[query.oauth_token.trim()]) {
      response.end();
      return;
    }
    var oauth_token_secret = tokenSecretDict[query.oauth_token.trim()];

    // Remove this request token key, value pair from global dictonary
    delete tokenSecretDict[query.oauth_token.trim()];

    var flickrOptions = {
      key: APP_ID,
      secret: APP_SECRET,
      oauth_token: query.oauth_token.trim(),
      oauth_verifier: query.oauth_verifier.trim(),
      oauth_token_secret: oauth_token_secret.trim()
    };
    flickrOptions = setAuthVals(flickrOptions);
    console.log("Options: "+util.inspect(JSON.stringify(flickrOptions), false, null));

    var queryArguments = {
      oauth_consumer_key: flickrOptions.key,
      oauth_nonce: flickrOptions.oauth_nonce,
      oauth_signature_method: "HMAC-SHA1",
      oauth_version: "1.0",
      oauth_timestamp: flickrOptions.oauth_timestamp,
      oauth_token: flickrOptions.oauth_token,
      oauth_verifier: flickrOptions.oauth_verifier
    };

    var queryString = formQueryString(queryArguments);
    var data = formBaseString(tokenURL, queryString, "GET");
    var signature = sign(data, flickrOptions.secret, flickrOptions.oauth_token_secret);
    signature = encodeURIComponent(signature);
    var flickrURL = tokenURL+"?"+queryString+"&oauth_signature="+signature;
    console.log('Token URL: '+flickrURL);
    request.get(flickrURL, function(error, resp, body) {
      if(error) {
        console.log("Error occured while requesting "+
          "for AccessToken: ", error);
        response.end();
        return;
      }
      console.log("Body: ",decodeURIComponent(body));
      result = parseRestResponse(decodeURIComponent(body));
      console.log("Result: ", result);
      if(result.oauth_problem) {
        /* Occasionally, this will fail.
         * Rerunning it then succeeds just fine. */
        console.log("Error returned from Flickr for AccessToken: " +
            "", result.oauth_problem);
        response.end();
        return;
      }
      console.log("Response from Flickr: "+
          util.inspect(JSON.stringify(result), false, null));
      result['request_token'] = flickrOptions.oauth_token;
      response.end();
      return;
    });
  }
  catch (e) {
    console.log('CaughtException: '+e.stack);
    response.end();
    return;
  }
};

/* URL: /access_token
 * Info: The below function will get the get Access Token
 * from Flickr */
exports.getAccessToken=function (req, response) {
  try {
    var flickrOptions = {
      key: APP_ID,
      secret: APP_SECRET,
      permissions: "delete"
    };
    flickrOptions = setAuthVals(flickrOptions);

    var queryArguments = {
      oauth_callback:         "",
      oauth_consumer_key:     flickrOptions.key,
      oauth_nonce:            flickrOptions.oauth_nonce,
      oauth_timestamp:        flickrOptions.oauth_timestamp,
      oauth_signature_method: "HMAC-SHA1",
      oauth_version:          "1.0"
    };

    var queryString = formQueryString(queryArguments);
    var data = formBaseString(requestURL, queryString, "GET");
    var signature = sign(data, flickrOptions.secret);
    signature = encodeURIComponent(signature);
    var flickrURL = requestURL+"?"+queryString+"&oauth_signature="+signature;
    console.log('Request URL: '+flickrURL);

    request.get(flickrURL, function(error, resp, body) {
      if(error) {
        console.log("Error occured while requesting "+
          "for RequestToken: ", error);
        response.end(JSON.stringify({"error": error}));
        return;
      }
      resp = parseRestResponse(body);
      if(resp.oauth_problem) {
        /* Occasionally, this will fail.
         * Rerunning it then succeeds just fine. */
        console.log("Error returned from Flickr for RequestToken: " +
          "", resp.oauth_problem);
        response.end(JSON.stringify({"error": "oauth_problem"}));
        return;
      }
      console.log("Response from Flickr: "+
        util.inspect(JSON.stringify(resp), false, null));
      Object.keys(resp).forEach(function(key) {
        flickrOptions[key] = resp[key];
      });
      // Add the token and secret to th global collection
      oauth_token = resp['oauth_token'];
      oauth_token_secret = resp['oauth_token_secret'];
      tokenSecretDict[oauth_token] = oauth_token_secret;
      authFullURL = authURL+"?oauth_token="+flickrOptions.oauth_token+
        "&perms="+flickrOptions.permissions;

      console.log('Auth URL: '+authFullURL);
      console.log("Current Dict values: " + tokenSecretDict);

      response.end(JSON.stringify({"auth_url": authFullURL,
        "token":flickrOptions.oauth_token}));
      return;
    });
  }
  catch (e) {
    console.log('CaughtException: '+e.stack);
    response.end(JSON.stringify({'error': e}));
    return;
  }
};

/* URL: /create_album
 * Info: The below function will create an album in
 * Flickr */
exports.createAlbum=function (req, response) {
  try {
    var body = req.body;
    if (!body || !body.name || !body.description || !body.token ||
      !body.token_secret || !body.primary_fr_id) {
      response.end(JSON.stringify({'error': 'missing_params'}));
      return;
    }

    var name = encodeData(body.name);
    var description = encodeData(body.description);
    var token = body.token;
    var token_secret = body.token_secret;
    var primary_fr_id = body.primary_fr_id;

    reqParams['query'] = {
      'method': 'flickr.photosets.create',
      'title': name,
      'description': description,
      'primary_photo_id': primary_fr_id
    };
    services(reqParams, function (err, data) {
      if (err) {
        console.log(err);
        response.end(JSON.stringify({'error': err}));
        return;
      }
      jsonObject = data['jsonObject'];
      delete reqParams['query'];
      delete reqParams['jsonObject'];
      response.end(JSON.stringify(jsonObject));
      return;
    });
  }
  catch (e) {
    console.log('CaughtException: '+e.stack);
    response.end(JSON.stringify({'error': e}));
    return;
  }
};

function services(reqParams, cb) {
  var token = get_param_data(reqParams, 'token');
  var token_secret = get_param_data(reqParams, 'token_secret');
  var query = get_param_data(reqParams, 'query');
  var error = "";
  if (!query) {
    error = "invalid_request";
    cb(error, reqParams);
    return;
  }

  var method = query.method;
  if (!method) {
    error = "no_method_passed";
    cb(error, reqParams);
    return;
  }

  var http_method = "GET";
  var flickrOptions = {
    key: APP_ID,
    secret: APP_SECRET,
    oauth_token: token,
    oauth_token_secret: token_secret
  };
  flickrOptions = setAuthVals(flickrOptions);

  var queryArguments = {
    oauth_consumer_key: flickrOptions.key,
    oauth_nonce: flickrOptions.oauth_nonce,
    oauth_signature_method: "HMAC-SHA1",
    oauth_version: "1.0",
    oauth_timestamp: flickrOptions.oauth_timestamp,
    oauth_token: flickrOptions.oauth_token
  };
  Object.keys(query).sort().forEach(function(key) {
    queryArguments[key] = query[key];
  });

  var queryString = formQueryString(queryArguments);
  var data = formBaseString(serviceURL, queryString, http_method);
  var signature = sign(data, flickrOptions.secret, flickrOptions.oauth_token_secret);
  signature = encodeURIComponent(signature);
  var flickrURL = serviceURL+"?"+queryString+"&oauth_signature="+signature;

  request.get(flickrURL, function(error, resp, body) {
    if(error) {
      console.log("Error: ",error);
      cb(error, reqParams);
      return;
    }
    xml2js (body, function (err, object) {
      if (err && !object) {
        if (body) {
          err = body.split('&')[0];
        }
        reqParams['jsonObject'] = null;
        cb(err, reqParams);
        return;
      }

      if (object && object.rsp && object.rsp.stat=="fail" &&
      object.err) {
        var error = object.err;
        if (object.err.code=="98") {
          error = "OAuthException";
        }
        else if (object.err.code=="1" || object.err.code=="3") {
          error = null;
        }

        if (error) {
          reqParams['jsonObject'] = object;
          cb(error, reqParams);
          return;
        }
      }
      reqParams['jsonObject'] = object;
      cb(null, reqParams);
      return;
    });
  });
}

/* HMAC-SHA1 data signing */
function sign(data, key, secret) {
    var hmacKey = key+"&"+(secret ? secret : ''),
        hmac = crypto.createHmac("SHA1", hmacKey);
    hmac.update(data);
    var digest = hmac.digest("base64");
    return digest;
}

/* Collapse a number of oauth query arguments into an
 * alphabetically sorted, URI-safe concatenated string. */
function formQueryString(queryArguments) {
    var args = [],
      append = function(key) {
        args.push(key + "=" + queryArguments[key]);
      };
    Object.keys(queryArguments).sort().forEach(append);
    return args.join("&");
}

/* Turn a url + query string into a Flickr API "base string". */
function formBaseString(url, queryString, method) {
    return [method, encodeURIComponent(url), encodeURIComponent(queryString)].join("&");
}

/* Update an options object for use with Flickr oauth
 * so that it has a new timestampe and nonce. */
function setAuthVals(options) {
    var timestamp = "" + Date.now(),
    md5 = crypto.createHash('md5').update(timestamp).digest("hex"),
    nonce = md5.substring(0,32);
    options.oauth_timestamp = timestamp;
    options.oauth_nonce = nonce;
    return options;
}

/* Convert xml to json object. */
function xml2js(xml, callback) {
  // callback signature: function(err, object).
  var obj = {};
  var stack = [];
  // sax has this weird quirk where you have to throw the error to make it quit parsing.
  try {
    var parser = sax.createStream(true, {trim: true});
    parser.on('error', function(err) {
      throw err;
    })
    .on('text', function(text) {
      if (stack.length) {
        stack[stack.length - 1]._content = (stack[stack.length - 1]._content || '') + text;
      }
    })
    .on('opentag', function(node) {
      stack.push(node.attributes);
    })
    .on('closetag', function(node) {
      obj[node] = stack.pop();
    })
    .on('end', function() {
      callback(null, obj);
    });
    parser.end(xml);
  }
  catch (sax_exception) {
    callback(sax_exception);
  }
}

/* Trim start and end space characters. */
function trim(string) {
  return string.replace(/^\s*|\s*$/g, '');
}

/* Parse a API response. */
function parseRestResponse(body) {
  var constituents = body.split("&"),
    response = {},
    keyval;
  constituents.forEach(function(pair) {
    keyval = pair.split("=");
    response[keyval[0]] = keyval[1];
  });
  return response;
}

/* Convert text to Link, if any */
function linkify(inputText) {
  var replacedText, replacePattern1, replacePattern2, replacePattern3;

  //URLs starting with http://, https://, or ftp://
  replacePattern1 = /(\b(https?|ftp):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/gim;
  replacedText = inputText.replace(replacePattern1, '<a href="$1" target="_blank">$1</a>');

  //URLs starting with "www." (without // before it, or it'd re-link the ones done above).
  replacePattern2 = /(^|[^\/])(www\.[\S]+(\b|$))/gim;
  replacedText = replacedText.replace(replacePattern2, '$1<a href="http://$2" target="_blank">$2</a>');

  //Change email addresses to mailto:: links.
  replacePattern3 = /(([a-zA-Z0-9\-\_\.])+@[a-zA-Z\_]+?(\.[a-zA-Z]{2,6})+)/gim;
  replacedText = replacedText.replace(replacePattern3, '<a href="mailto:$1">$1</a>');

  return replacedText;
}

/* Encode data in percent format */
function encodeData(toEncode) {
  if(!toEncode || toEncode==="") return "";
  else {
    var result= encodeURIComponent(toEncode);
    return result.replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
  }
}

