
module.exports = function(cb){
    var plugins = [];
    
    plugins.push(require("./onlykey-fido2/plugin.js")); //load onlykey plugin for testing
    
    var removeConsole = true;
    
    if(removeConsole)
        plugins.push(require("./console/console.js")); //load replacement onlykey need for plugin
    else
        plugins.push(require("./console/console_debug.js")); //load replacement onlykey need for plugin
        
    var EventEmitter = require("events").EventEmitter;
    
    var architect = require("../libs/wp_architect.js");
    
    
    plugins.push({
        provides: ["app", "window"],
        consumes: ["hub"],
        setup: function(options, imports, register) {
            register(null, {
                app: new EventEmitter(),
                window: window
            });
        }
    });
    
    architect(plugins, function(err, app) {
    
        if (err) return console.error(err);
        app.services.app.core = app.services;
        for (var i in app.services) {
            app.services.app[i] = app.services[i];
        }
        for (var i in app.services) {
            if (app.services[i].init) app.services[i].init(app);
        }
    
        
        cb(app.services.onlykey3rd);
        
    
    });
    

}


