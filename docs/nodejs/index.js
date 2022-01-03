var { FIDO2Client } = require("@vincss-public-projects/fido2-client");
var fido2 = new FIDO2Client();

// fido2.on("fido2-enter-pin", function(a,b,c){
//     console.log("set pin");
//     // fido2.emit("fido2-enter-pin-replay","0420");
//     fido2.reply("0420");
// });

var EventEmitter = require("events").EventEmitter;

var $window = new EventEmitter();

// $window.crypto = require("node-webcrypto-shim");
const WebCrypto = require('node-webcrypto-ossl');
const webcrypto = new WebCrypto({
//   directory: `${process.env.HOME}/.webcrypto/keys`
});
$window.crypto = webcrypto;


$window.atob = require("atob");
$window.btoa = require("btoa");
$window.location = {
    hostname: "grid.peersocial.io" //set to your domain
};

$window.navigator = {
    vendor: "NODE",
    userAgent: "NODE",
    platform: "Linux",
    credentials: {
        get: function(ticket) {
            return fido2.getAssertion(ticket, "https://" + $window.location.hostname)
        }
    }
};


global.window = $window;

var ONLYKEY = require("../../src/onlykey-api.js");

console.log(ONLYKEY)


var bob = {"pub":"JtwRNfyZm2lJFlzb8FxB2EylEIMYi0_5CcllU1rK0tQ.pllCCKOmirtiEiCirOByd69V49wad7OPvOg5N2puh0c","priv":"pvNcbfyT58RxFMx-UBTZ_PaUPyLCoDOY9dRzs1SWnjo","epub":"MzmNPtcQU4X1T4unYSE7ncWY-4ulbb9dM3S9fWDqgYA.NRuj7mOpZngSOtcV8kwDJqLioUv8V2FIZ1lvNO5Ra2Q","epriv":"G7GkIiEQYb6XbTIY6iFFKmMurjHyGUPJsyTbEnMNIlg"};

var press_required = false;

ONLYKEY.connect(async function() {

    var keyType = 1; //P256R1
    ONLYKEY.derive_public_key("Onlykey Rocks!", keyType, press_required, async function(err, key) {
        ONLYKEY.derive_shared_secret("Onlykey Rocks!", bob.epub, keyType, press_required, async function(err, sharedSecret) {
            
            console.log("key:", key)
            console.log("sharedSecret:", sharedSecret)
        });
    });
});