var nexe = require('nexe');
var compile = nexe.compile;

compile({
  target: "windows-x64-12.18.2",
  input: './src/cli.js',
  output: './node-onlykey-cli.exe',
  temp: "./.tmp-nexe",
  loglevel:"verbose"
}).then(() => {
  console.log('done: success')
})