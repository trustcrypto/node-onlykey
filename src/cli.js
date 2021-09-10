// module.exports = function(callback) {

var plugins = [];

plugins.push(require("./onlykey-fido2/plugin.js")); //load onlykey plugin for testing

plugins.push(require("./window.js")); //load replacement onlykey need for plugin

var EventEmitter = require("events").EventEmitter;

var architect = require("../libs/architect.js");


plugins.push({
    provides: ["app", "console"],
    consumes: ["hub"],
    setup: function(options, imports, register) {
        register(null, {
            app: new EventEmitter(),
            console: console
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

    var args = require('minimist')(process.argv.slice(2), {
        // '--': true,
        boolean: ["keypress"],
        alias: {
            keytype: "t",
            keypress: "p"
        },
        default: {
            keytype: 1,
            keypress: false
        }
    });


    args.aditional_seed_data = args._[0] || "Onlykey Rocks!";
    args.sharedPub = args._[1];

    var ONLYKEY = app.services.onlykey3rd(args.keytype);

    // ONLYKEY.connect(console.log)

    if (!args.sharedPub) {
        ONLYKEY.derive_public_key(args.aditional_seed_data, args.keytype, args.keypress, async function(err, key) {
            console.log(JSON.stringify({ epub: key }))
        });
    }
    else {

        ONLYKEY.derive_shared_secret(args.aditional_seed_data, args.sharedPub, args.keytype, args.keypress, async function(err, sharedSecret) {
            console.log(JSON.stringify({ sharedSecret: sharedSecret }))
        });
    }
});

// }
