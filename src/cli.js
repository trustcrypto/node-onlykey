#!/usr/bin/env node

// module.exports = function(callback) {

var args = require('minimist')(process.argv.slice(2), {
    // '--': true,
    boolean: [
        "keypress", 
        // "serial",
        "help"
    ],
    alias: {
        keytype: "t",
        keypress: "p",
        help: ["h","?"]
    },
    default: {
        seed:"Onlykey Rocks!",
        keytype: 1,
        keypress: false,
        domnain:'localhost',
        // serial: false,
        help: false
        
    }
});

if(args.help){
    console.log("--help,-h,-?               shows this");
    // console.log("--serial                   developer firmware serial");
    console.log("--keypress,-p              use touch key");
    console.log("--keytype=1,-t=1           1=P256R1,3=CURVE25519");
    console.log("--seed='Onlykey Rocks!'    seed for aditional_data");
    console.log("--secret='pubkey'          pubkey to generate a secret from seed");
    console.log("--domain='localhost'       domain to generate keys for");
    
    
    return;
}

// if (args.serial) {
//     require("./serial.js");
//     return;
// }

if(!process.env.DOMAIN && args.domain)
    process.env.DOMAIN = args.domain;
    
var plugins = [];

plugins.push(require("./window.js")); //load replacement onlykey need for plugin

plugins.push(require("./onlykey-fido2/plugin.js")); //load onlykey plugin for testing

plugins.push(require("./console/console.js")); //load replacement onlykey need for plugin

var EventEmitter = require("events").EventEmitter;

var architect = require("../libs/architect.js");


plugins.push({
    provides: ["app"],
    consumes: ["hub"],
    setup: function(options, imports, register) {
        register(null, {
            app: new EventEmitter()
        });
    }
});

architect.createApp(plugins, function(err, app) {

    if (err) return console.error(err);
    app.services.app.core = app.services;
    for (var i in app.services) {
        app.services.app[i] = app.services[i];
    }
    for (var i in app.services) {
        if (app.services[i].init) app.services[i].init(app);
    }

    // app.services.app.emit("start");

    // callback(null, app);


    var ONLYKEY = app.services.onlykey3rd(args.keytype);

    // ONLYKEY.connect(console.log)

    if (!args.secret) {
        ONLYKEY.derive_public_key(args.seed, args.keytype, args.keypress, async function(err, key) {
            console.log(JSON.stringify({domain: process.env.DOMAIN, seed: args.seed, epub:key }))
        });
    }
    else {

        ONLYKEY.derive_shared_secret(args.seed, args.secret, args.keytype, args.keypress, async function(err, sharedSecret, seedKey) {
            console.log(JSON.stringify({domain: process.env.DOMAIN, seed: args.seed, epub:seedKey, pub: args.secret, sharedSecret: sharedSecret }))
        });
    }
});

// }
