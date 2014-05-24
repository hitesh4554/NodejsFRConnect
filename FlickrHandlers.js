// NodeJs external modules
var express = require('express'),
    request = require('request'),
    FormData = require('form-data'),
    https = require('https'),
    qs = require('qs'),
    fs = require('fs'),
    util = require('util');

//Facebook API credentials used to OAuth and make API calls
var APP_ID = YOUR_FLICKR_API_ID;
var APP_SECRET = YOUR_FLICKR_API_SECRET;
var REDIRECT_URI = YOUR_REDIRECT_URI;
