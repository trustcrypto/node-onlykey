var express = require("express");
var app = express();
var http = require('http');
var https = require('https');

var fs = require('fs');
var server;
if(!process.env.PORT){
  process.env.PORT = 3000;
  
  var cert; 
  try{
    server = https.createServer({
      key: fs.readFileSync('_._server.key'),
      cert: cert = fs.readFileSync('_._server.cert')
    }, app);
  }catch(e){}
  if(!cert){
    console.log("need to run this command in terminal in project dir", __dirname);
    console.log("' $ openssl req -nodes -new -x509 -keyout _._server.key -out _._server.cert '");
    server = http.createServer(app);
  }
}else{
  server = http.createServer(app);
}

app.use("/dist", express.static(__dirname + "/../dist"));
app.use(express.static(__dirname));
// app.use("/libs", express.static(__dirname + "/../libs"));

process.env.PORT = process.env.PORT || 3000;

server.listen(process.env.PORT, () => {
    console.log('listening on *:' + process.env.PORT);
});
