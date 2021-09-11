var express = require("express");
var app = express();
var http = require('http');


var server = http.createServer(app);


app.use("/dist", express.static(__dirname + "/../dist"));
app.use(express.static(__dirname));
// app.use("/libs", express.static(__dirname + "/../libs"));

process.env.PORT = process.env.PORT || 3000;

server.listen(process.env.PORT, () => {
    console.log('listening on *:' + process.env.PORT);
});
