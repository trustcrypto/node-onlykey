#!/usr/bin/env node

var args = require('minimist')(process.argv.slice(2), {
    // '--': true,
    boolean: ["keypress"],
    alias: {
        keytype: "t",
        keypress: "p"
    },
    default: {
        keytype: 1,
        keypress: false,
        _: ["test", "test2"]
    }
});

args.aditional_seed_data = args._[0] || "Onlykey Rocks!";
args.sharedPub = args._[1];

// console.log(args);
// return;

var { FIDO2Client } = require("@vincss-public-projects/fido2-client");
var fido2 = new FIDO2Client();

// fido2.on("fido2-enter-pin", function(a,b,c){
//     console.log("set pin");
//     // fido2.emit("fido2-enter-pin-replay","0420");
//     fido2.reply("0420");
// });

var EventEmitter = require("events").EventEmitter;

var $window = new EventEmitter();

$window.crypto = require("node-webcrypto-shim");
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

var ONLYKEY = require("./onlykey-api.js");

// console.log(ONLYKEY)


// ONLYKEY.connect(async function() {


// });

// var keyType = 1; //P256R1

if (!args.sharedPub) {
    ONLYKEY.derive_public_key(args.aditional_seed_data, args.keytype, args.keypress, async function(err, key) {

        console.log("epub: ", key)
    });
}
else {

    ONLYKEY.derive_shared_secret(args.aditional_seed_data, args.sharedPub, args.keytype, args.keypress, async function(err, sharedSecret) {

        console.log("sharedSecret: ", sharedSecret)
    });
}