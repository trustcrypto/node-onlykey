
var { FIDO2Client } = require("@vincss-public-projects/fido2-client");
var fido2 = new FIDO2Client();
        
var EventEmitter = require("events").EventEmitter;

var $window = new EventEmitter();

$window.crypto = require("node-webcrypto-shim");
$window.atob = require("atob");
$window.btoa = require("btoa");
$window.location = {
    hostname: "apps.crp.to" //set to your domain
};

$window.navigator = {
    userAgent: "NODE",
    credentials: {
        get: function(ticket) {
            return fido2.getAssertion(ticket, "https://" + $window.location.hostname)
        }
    }
};


global.window = $window;

var ONLYKEY = require("../../src/onlykey-api.js");

console.log(ONLYKEY)