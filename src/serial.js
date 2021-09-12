const nodeHID = require('node-hid');

var bytes2string = function bytes2string(bytes) {
	if (!bytes) return;
	var ret = Array.from(bytes).map(function chr(c) {
		return String.fromCharCode(c);
	}).join('');
	return ret;
};

var $hids = {};

var color = {};

// (function(){
	 
// 	// '\033\\[0;' + ansi + 'm
	
// 	var colorRGB = function(c) { return '\x1b[38;2;' + c + 'm'; };
// 	var colorSwatch = {
// 		"red": "255;0;0",
// 		"orange": "255;165;0",
// 		"yellow": "255;255;0",
// 		"green": "50;205;50",
// 		"teal": "0;128;128",
// 		"blue": "0;0;255",
// 		"purple": "128;0;128",
// 		"white": "255;255;255",
// 	};
// 	for (var i in colorSwatch) {
// 		color[i] = colorRGB(colorSwatch[i]);
// 	}
// })();


(function(){
	 
	// '\033\\[0;' + ansi + 'm
	
	var colorRGB = function(c) { return '\033[0;3' + c + 'm'; };
	var colorSwatch = {
		"black": "0",
		"red": "1",
		"green": "2",
		"yellow": "3",
		"blue": "4",
		"purple": "5",
		"teal": "6",
		"white": "7"
		/*
		'30': 'black',
	  '31': 'red',
	  '32': 'green',
	  '33': 'yellow',
	  '34': 'blue',
	  '35': 'purple',
	  '36': 'cyan',
	  '37': 'white'
		*/
	};
	for (var i in colorSwatch) {
		color[i] = colorRGB(colorSwatch[i]);
	}
})();

var output = [];
var tail = "";



function findHID(hid_interface) {
	var hids = nodeHID.devices();

	if (!$hids[hid_interface])
		$hids[hid_interface] = {};

	$hids[hid_interface].finding = true;

	if ($hids[hid_interface].com || $hids[hid_interface].error) {
		$hids[hid_interface].com = false;
		$hids[hid_interface].error = false;
	}

	for (var i in hids) {
		if (hids[i].product == "ONLYKEY") {
			if (hids[i].interface == hid_interface) {
				$hids[hid_interface].com = false;
				$hids[hid_interface].device = hids[i];

			}
		}
	}

	if (!$hids[hid_interface].com && $hids[hid_interface].device) {
		try {
			$hids[hid_interface].com = new nodeHID.HID($hids[hid_interface].device.path);
			process.stdout.write(color.yellow + "Connected onlykey interface " + hid_interface + "\r\n" + color.white);
			$hids[hid_interface].com.on('data', function(data) {
				var $color = (hid_interface == 2 ? color.red : color.white);
				var addNewLines = (hid_interface == 2 ? true : false);
				var bfrstr = bytes2string(data);
				if (bfrstr) {
					bfrstr = bfrstr.replace(/\r\n\r\n/gm, "\r\n")
					var ba = (tail+bfrstr).split('\r\n');
					tail = ba.pop();
					output = output.concat(ba);
					// if (addNewLines) {
					// 	process.stdout.write("\r\n");
					// }
					// process.stdout.write($color);
					// process.stdout.write(highlightText(bfrstr.replace(/\r\n\r\n/gm, "\r\n")));
					// process.stdout.write(color.white);
					// if (addNewLines) {
					// 	process.stdout.write("\r\n");
					// }
				}
			});
			$hids[hid_interface].com.on('error', function(error) {
				$hids[hid_interface] = false;
				process.stdout.write(color.yellow + "Disconnected onlykey interface " + hid_interface + "\r\n" + color.white);
			});
		}
		catch (e) {}
	}

	$hids[hid_interface].finding = false;
}

var looping = false;
setInterval(function() {
	
	var o = output.shift();
	
	if(o){
		process.stdout.write(highlightText(o.replace(/\r\n\r\n/gm, "\r\n")) + '\r\n');
	}
	
	if (looping) return;
	looping = true;
	try {
		loadInterface(3);
	}
	catch (e) {
		console.log(e);
	}
	// try {
	// 	loadInterface(2);
	// }
	// catch (e) {
	// 	console.log(e);
	// }
	looping = false;
}, 1);

function loadInterface(hid_interface) {
	if (!$hids[hid_interface] || !$hids[hid_interface].finding && !$hids[hid_interface].com)
		return findHID(hid_interface);
}

var readline = require('readline'),
	rl = readline.createInterface(process.stdin, process.stdout),
	prefix = '';

rl.on('line', function(line) {
	switch (line.trim()) {
		default: if (line.length) {
			var inter = 3;
			if ($hids[inter] && $hids[inter].com) {
				var messageA = [];
				for (var i = 0; i < line.length; i++) {
					messageA.push(line.charCodeAt(i));
				}
				messageA.push("\n".charCodeAt(0));
				if (process.platform.indexOf("win") > -1)
					process.stdout.write("\n");
				messageA.unshift(0x00);
				$hids[inter].com.write(messageA);
			}
		}
		break;
	}
	rl.setPrompt(prefix, prefix.length);
	rl.prompt();
}).on('close', function() {
	process.exit(0);
});
rl.setPrompt(prefix, prefix.length);
rl.prompt();



function highlightText(text){
	
	var textReplacement = {
		"Sending FIDO response block": color.red,
		"Sending transport response data": color.red,
		"Sending data on OnlyKey via Webauthn": color.red,
		"Stored Data for FIDO Response": color.red,
		"DECRYPTED STATE": color.red,
		"ENCRYPTED STATE": color.red,
		"buffer": color.red,
		"KEY": color.red,
		"IV": color.red,
		"INPUT": color.red,
		
		"FIDO Response": color.red,
		"Shared Secret": color.red,
		"Input Pubkey": color.red,
		"Derived Private": color.red,
		"Returned Public": color.red,
		"Web derivation key": color.red,
		"Compute of public key complete": color.red,
		
		"get_assertion time": color.red,
		"saved": color.red,
		"credentials": color.red,
		"adding user details to output": color.red,
		"sigder_sz": color.red,
		"sigder": color.red,
		"ctap_generate_rng": color.red,
		"Computed Public": color.red,
		"HKDF Key": color.red,
		"salt": color.red,
		"RPID hash": color.red,
		"RPID": color.red,
		"Other data": color.red,
		"Read ECC Private Key": color.red,
		"Reading nonce": color.red,
		"Transit AES Key": color.red,
		"Transit Shared Secret": color.red,
		"IS EXT REQ": color.red,
		"Keyhandle": color.red,
		"stored_apprpid": color.red,
		"rpid": color.red,
		"stored_appid": color.red,
		"OKCONNECT MESSAGE RECEIVE": color.red,
		"UNLOCKED": color.red,
		"Time Already Set": color.red,
		"OnlyKey public": color.red,
		"App public": color.red,
		"Key": color.red,
		"Generating random number of size": color.red,
		"AES KEY": color.red,
		"slot": color.red,
		"hash": color.red,
		"via Webauthn": color.red,
		"_appid": color.red,
		"Ctap buffer": color.red,
		"Keyhandle": color.red,
		"resulting order of creds": color.red,
		"CTAP_pinProtocol": color.red,
		"CTAP_options": color.red,
		"GA_allowList": color.red,
		"GA_clientDataHash": color.red,
		"GA_rpId": color.red,
		"CTAP_GET_ASSERTION": color.red,
		"Received packet":color.red,
		"Recv packet": color.red,
		
		"cbor output structure": color.red,
		"cbor": color.red,
		"AES": color.red,
		"SLOT": color.red,
		
	}
	
	for(var i in textReplacement){
		// if(text.indexOf(i) >= 0)
			text = addTextwithColor(text, i,textReplacement[i]);
	}
	return text;	
}

function addTextwithColor(text, search, $color){
	var regex = new RegExp(search, "g");
	// mystring.replace(regex, "yay")); // alerts "hello yay test yay"
	return text.replace(regex , $color + search + color.white);
}