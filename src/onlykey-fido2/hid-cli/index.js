// module.exports = function() {
var forge = require("node-forge");

//-- commandline args
var optimist = require('optimist')
	.usage('Usage: $0 --cmd [cmd]')
	.demand('cmd')
	.describe('cmd', 'Command to run settime , getlables')
	.alias('cmd', 'c')
	.describe('slot', 'slot id to choose')
	.alias('slot', 's')
	.describe('data', 'additional data')
	.alias('data', 'd')
	.describe('blob', 'blob data')
	.alias('blob', 'b')
	.describe('keytype', 'keytype')
	.alias('keytype', 't')
	.describe('help', 'Show Help')
	.alias('help', 'h').alias('help', '?');

var argv = optimist.argv;

if (argv.help) {
	return optimist.showHelp();
}

//-- INCLUDES

const nodeHID = require('node-hid');

//-- CONST / vars

const messageHeader = [255, 255, 255, 255];

const messageFields = {
	LABEL: 1,
	URL: 15,
	NEXTKEY4: 18, //Before Username
	NEXTKEY1: 16, //After Username
	DELAY1: 17,
	USERNAME: 2,
	NEXTKEY5: 19, //Before OTP
	NEXTKEY2: 3, //After Password
	DELAY2: 4,
	PASSWORD: 5,
	NEXTKEY3: 6, //After OTP
	DELAY3: 7,
	TFATYPE: 8,
	TFAUSERNAME: 9,
	YUBIAUTH: 10,
	LOCKOUT: 11,
	WIPEMODE: 12,
	BACKUPKEYMODE: 20,
	SSHCHALLENGEMODE: 21,
	PGPCHALLENGEMODE: 22,
	SECPROFILEMODE: 23,
	TYPESPEED: 13,
	LEDBRIGHTNESS: 24,
	LOCKBUTTON: 25,
	KBDLAYOUT: 14
};

const messages = {
	OKSETPIN: 225, //0xE1
	OKSETSDPIN: 226, //0xE2
	OKSETPIN2: 227, //0xE3
	OKSETTIME: 228, //0xE4
	OKGETLABELS: 229, //0xE5
	OKSETSLOT: 230, //0xE6
	OKWIPESLOT: 231, //0xE7
	OKSETU2FPRIV: 232, //0xE8
	OKWIPEU2FPRIV: 233, //0xE9
	OKSETU2FCERT: 234, //0xEA
	OKWIPEU2FCERT: 235, //0xEB
	OKGETPUBKEY: 236,
	OKSIGN: 237,
	OKWIPEPRIV: 238,
	OKSETPRIV: 239,
	OKDECRYPT: 240,
	OKRESTORE: 241,
	OKFWUPDATE: 244,
};


const SLOTS = {
	OKSETPIN: 225, //0xE1
	OKSETSDPIN: 226, //0xE2
	OKSETPIN2: 227, //0xE3
	OKSETTIME: 228, //0xE4
	OKGETLABELS: 229, //0xE5
	OKSETSLOT: 230, //0xE6
	OKWIPESLOT: 231, //0xE7
	OKSETU2FPRIV: 232, //0xE8
	OKWIPEU2FPRIV: 233, //0xE9
	OKSETU2FCERT: 234, //0xEA
	OKWIPEU2FCERT: 235, //0xEB
	OKGETPUBKEY: 236,
	OKSIGN: 237,
	OKWIPEPRIV: 238,
	OKSETPRIV: 239,
	OKDECRYPT: 240,
	OKRESTORE: 241,
	OKFWUPDATE: 244,
};


//--PROCESS

switch (argv.cmd) {
	case 'settime':
		setTime();
		break;

	case 'getlabels':
		getLabels();
		break;

	case 'getpub':
		getPub();
		break;

	case 'sign':
		sign();
		break;

	case 'dotest':
		dotest();
		break;

	default:

		console.log("argv", argv);

}



//-- FUNCTIONS

function findHID(hid_interface) {
	var hids = nodeHID.devices();

	for (var i in hids) {
		if (hids[i].product == "ONLYKEY") {
			if (hids[i].interface == hid_interface) {
				return hids[i];
			}
		}
	}
}

function sendMessage(com, options) {

	// var bytesPerMessage = options.contents.length+8;

	var msgId = typeof options.msgId === 'string' ? options.msgId.toUpperCase() : null;
	var slotId = typeof options.slotId === 'number' || typeof options.slotId === 'string' ? options.slotId : null;
	var fieldId = typeof options.fieldId === 'string' || typeof options.fieldId === 'number' ? options.fieldId : null;
	var contents = typeof options.contents === 'number' || (options.contents && options.contents.length) ? options.contents : '';
	var contentType = (options.contentType && options.contentType.toUpperCase()) || 'HEX';

	// callback = typeof callback === 'function' ? callback : ()=>{} ;

	var reportId = 0;

	var bytes = [].concat(messageHeader);
	// var cursor = 0;

	// for (; cursor < messageHeader.length; cursor++) {
	// 	bytes[cursor] = messageHeader[cursor];
	// }

	// if (msgId && messages[msgId]) {
	bytes.push(messages[msgId]);
	// 	cursor++;
	// }

	// if (slotId !== null) {
	// 	// 	bytes[cursor] = strPad(slotId, 2, 0);
	// 	bytes.push(slotId);
	// 	// 	cursor++;
	// }

	// if (fieldId !== null) {
	// 	if (messageFields[fieldId]) {
	// 		bytes[cursor] = strPad(messageFields[fieldId], 2, 0);
	// 	}
	// 	else {
	// 		bytes[cursor] = fieldId;
	// 	}

	// 	cursor++;
	// }

	// bytes = bytes.concat(contents);

	// if (!Array.isArray(contents)) {
	// 	switch (typeof contents) {
	// 		case 'string':
	// 			contents = contents.replace(/\\x([a-fA-F0-9]{2})/g, (match, capture) => {
	// 				return String.fromCharCode(parseInt(capture, 16));
	// 			});

	// 			for (var i = 0; i < contents.length && cursor < bytes.length; i++) {
	// 				if (contents.charCodeAt(i) > 255) {
	// 					throw "I am not smart enough to decode non-ASCII data.";
	// 				}
	// 				bytes[cursor++] = contents.charCodeAt(i);
	// 			}
	// 			break;
	// 		case 'number':
	// 			if (contents < 0 || contents > 255) {
	// 				throw "Byte value out of bounds.";
	// 			}
	// 			bytes[cursor++] = contents;
	// 			break;
	// 	}
	// }
	// else {
	// contents.forEach(function(val) {
	// 	bytes[cursor++] = /*contentType === 'HEX' ? hexStrToDec(val) : */val;
	// });
	// }

	// var pad = 0;
	// for (; cursor < bytes.length;) {
	// 	bytes[cursor++] = pad;
	// }

	// var 
	var messageA; // = Array.from(bytes);
	// console.info("SENDING " + msgId + " to connectionId " + com.path + ":");//, Buffer.from(messageA).toString("HEX").toUpperCase(),bytes);

	for (var i = 0; i < contents.length; i++) {
		if (typeof contents[i] == "string")
			contents[i] = parseInt(hexStrToDec(contents[i]), 10);
		else
			contents[i] = contents[i];
	}

	// console.log(contents)
	// messageA.unshift(reportId); //reportId

	if (!contents) {

		if (slotId !== null) {
			// 	bytes[cursor] = strPad(slotId, 2, 0);
			bytes.push(slotId);
			// 	cursor++;
		}
		messageA = Array.from(bytes);
		var temporary = [].concat(messageA);
		var l = temporary.length;
		// console.log("SEND:",l,":",Buffer.from(temporary).toString("HEX").toUpperCase())
		// console.log(temporary)
		com.write([reportId].concat(temporary));
	}
	else {
		messageA = Array.from(bytes);
		if (contents.length > 57) {
			var chunkLen = (64 - messageA.length) - 2;
			var i, j, temporary, chunk = chunkLen;
			for (i = 0, j = contents.length; i < j; i += chunk) {
				var _chunk = contents.slice(i, i + chunk);

				temporary = [].concat(messageA).concat([slotId, _chunk.length < chunkLen ? _chunk.length : 255]).concat(_chunk);

				for (; 64 > temporary.length;) {
					temporary.push(0);
				}

				// console.log("SEND:",l,":",Buffer.from(temporary).toString("HEX").toUpperCase())
				// console.log(Uint8Array.from(temporary))
				com.write([reportId].concat(temporary));
			}
		}
		else {
			if (slotId !== null) {
				// 	bytes[cursor] = strPad(slotId, 2, 0);
				bytes.push(slotId);
				// 	cursor++;
			}
			messageA = Array.from(bytes);
			temporary = [].concat(messageA).concat(contents);
			// console.log(temporary)
			com.write([reportId].concat(temporary));
		}

	}

	// com.write(messageA);

}

function setTime() {


	var hid = findHID(2);

	if (hid) {
		var com = new nodeHID.HID(hid.path);
		com.path = hid.path;

		com.on("data", function(msg) {
			var msg_string = bytes2string(msg);

			// console.log("handleMessage", msg, msg_string);
			if (msg_string == "INITIALIZED")
				console.log("OnlyKey Locked");
			else if (msg_string.split("v")[0] == "UNLOCKED")
				console.log("OnlyKey UnLock... Time Set!");
			com.close();
		});


		var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
		// console.info("Setting current epoch time =", currentEpochTime);
		var timeParts = currentEpochTime.match(/.{2}/g);
		var options = {
			contents: timeParts,
			msgId: 'OKSETTIME'
		};
		sendMessage(com, options);

		//console.log(hid);
	}
	else {
		console.log("onlykey not detected");
	}

}


function getPub(done) {


	var hid = findHID(2);

	if (hid) {
		var com = new nodeHID.HID(hid.path);
		com.path = hid.path;

		com.on("data", function(msg) {
			// var msg_string = bytes2string(msg);

			msg = Array.from(msg);

			msg = msg.splice(0, 32);
			msg = Buffer.from(msg);
			// console.log(Uint8Array.from(msg))

			// console.log(msg)
			// console.log(msg.toString("base64"));

			com.close();

			if (done)
				done(msg.toString("base64"));

		});
		var crypto = require('crypto');
		var slot = argv.slot ? parseInt(argv.slot, 10) : 132;
		var hash;

		if (slot == 132) {
			hash = crypto.createHash('sha256').update(argv.data).digest();
		}
		else hash = '';
		hash = Array.from(hash);

		// console.log(Buffer.from(hash))
		// console.log(hash instanceof Array,hash);

		hash = [1].concat(hash);

		// if this_slot_id > 100:
		//          if curve_name == 'curve25519':
		//              data = '04' + data
		//          elif curve_name == 'secp256k1':
		//              # Not currently supported by agent, for future use
		//              data = '03' + data
		//          elif curve_name == 'nist256p1':
		//              data = '02' + data
		//          elif curve_name == 'ed25519':
		//              data = '01' + data
		//      else:
		//          data = '00' + data


		var options = {
			contents: hash,
			slotId: parseInt(slot, 10),
			msgId: 'OKGETPUBKEY'
		};
		// console.log(options);

		sendMessage(com, options);

		//console.log(hid);
	}
	else {
		console.log("onlykey not detected");
	}

}



function sign(done) {


	var hid = findHID(2);

	if (hid) {
		var com = new nodeHID.HID(hid.path);
		com.path = hid.path;

		com.on("data", function(msg) {
			// var msg_string = bytes2string(msg);

			if (msg.toString("utf8").indexOf("Error device locked") == 0)
				return;

			// console.log(msg,msg.toString("utf8"), msg.toString("hex"));
			// console.log(msg, msg.toString("base64"));


			msg = Array.from(msg);

			msg = msg.splice(0, 64);
			msg = Buffer.from(msg);

			// console.log(msg)
			// console.log(msg.toString("base64"));

			com.close();

			if (done)
				done(msg.toString("base64"), argv.blob);

		});
		var crypto = require('crypto');
		var slot = argv.slot ? parseInt(argv.slot, 10) : 201;
		var hash = crypto.createHash('sha256').update(argv.data || "").digest();
		var blob = crypto.createHash('sha256').update(argv.blob /*+"lol"*/ || "").digest(); //.toString("hex");
		// blob = Buffer.from(blob)
		// console.log(hash instanceof Array,hash);

		// console.log("blob", argv.blob, blob, Uint8Array.from(blob))
		hash = Array.from(hash);
		hash = [].concat(hash);
		blob = Array.from(Buffer.from(blob)); //.slice(0,16);
		blob = [].concat(blob);

		var cont = [].concat(blob).concat(hash);
		// console.log(Buffer.from(hash))
		// return; 
		// console.log(hash)

		// if this_slot_id > 100:
		//          if curve_name == 'curve25519':
		//              data = '04' + data
		//          elif curve_name == 'secp256k1':
		//              # Not currently supported by agent, for future use
		//              data = '03' + data
		//          elif curve_name == 'nist256p1':
		//              data = '02' + data
		//          elif curve_name == 'ed25519':
		//              data = '01' + data
		//      else:
		//          data = '00' + data


		var options = {
			contents: [].concat(blob).concat(hash),
			slotId: parseInt(slot, 10),
			msgId: 'OKSIGN'
		};
		// console.log(options);
		// console.log(Buffer.from(options.contents).toString("HEX"));

		sendMessage(com, options);

		//console.log(hid);
	}
	else {
		console.log("onlykey not detected");
	}

}

async function getLabels() {

	var hid = findHID(2);

	if (hid) {
		var com = new nodeHID.HID(hid.path);
		com.path = hid.path;

		var messCount = 0;

		com.on("data", function(msg) {
			messCount += 1;
			msg = Array.from(msg);

			var msg_string = bytes2string(msg);

			// console.log("handleMessage", msg, msg_string);
			if (msg_string == "INITIALIZED")
				console.log("OnlyKey Locked");
			else if (msg_string.split("v")[0] == "UNLOCKED")
				console.log("OnlyKey UnLock... Time Set!");

			var slot = msg.shift();
			msg_string = bytes2string(msg);

			if (slot > 9) slot -= 6

			console.log("Slot:", slot, msg_string.split("|"))

			if (messCount == 12)
				com.close();
		});



		sendMessage(com, {
			msgId: 'OKGETLABELS'
		});

		//console.log(hid);
	}
	else {
		console.log("onlykey not detected");
	}

};

async function dotest() {
	getPub(function(pub) {

		sign(function(sig, data) {


			var nacl = require("tweetnacl");

			var forge = require("node-forge");


			var md = forge.md.sha256.create();
			md.update(data, 'utf8');
			md = Uint8Array.from(Buffer.from(md.digest().toHex(), "hex"));
			// md = Uint8Array.from([]);

			// var md = Uint8Array.from(Buffer.from("test","utf8"));
			// console.log(md.length, md);

			var _sig = Uint8Array.from(Buffer.from(sig, 'base64'))
			// console.log(_sig.length, _sig);

			var pk = Uint8Array.from(Buffer.from(pub, 'base64'));
			// var pk = Uint8Array.from(Buffer.from('HmKCPaVEiXwmDNE4KOXE7MYV0dyysXSgJpWdrY/5ErA=', 'base64'));
			// console.log(pk.length, pk)


			console.log("i have pub", pub)
			console.log("i have sig", sig)
			
			
			console.log("TEST", nacl.sign.detached.verify(md, _sig, pk) ? "PASSED" : "FAILED")






		});
	})
}

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));


function strPad(str, places, char) {
	while (str.length < places) {
		str = "" + (char || 0) + str;
	}

	return str;
}


function hexStrToDec(hexStr) {
	return new Number('0x' + hexStr).toString(10);
}

function bytes2string(bytes) {
	if (!bytes) return;
	var ret = Array.from(bytes).map(function chr(c) {
		if (c == 0) return '';
		if (c == 255) return '';
		return String.fromCharCode(c);
	}).join('');
	return ret;
};

function string2bytes(s) {
	var len = s.length;
	var bytes = new Uint8Array(len);
	for (var i = 0; i < len; i++) bytes[i] = s.charCodeAt(i);
	return bytes;
};

// };