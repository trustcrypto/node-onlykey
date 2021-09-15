
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

const nodeHID = require('node-hid');

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

	var msgId = typeof options.msgId === 'string' ? options.msgId.toUpperCase() : null;
	var slotId = typeof options.slotId === 'number' || typeof options.slotId === 'string' ? options.slotId : null;
	var contents = typeof options.contents === 'number' || (options.contents && options.contents.length) ? options.contents : '';
	
	var reportId = 0;

	var bytes = [].concat(messageHeader);
	
	bytes.push(messages[msgId]);
	
	var messageA, temporary;
	
	for (var i = 0; i < contents.length; i++) {
		if (typeof contents[i] == "string")
			contents[i] = parseInt(hexStrToDec(contents[i]), 10);
		else
			contents[i] = contents[i];
	}

	if (!contents) {

		if (slotId !== null) {
			bytes.push(slotId);
		}
		messageA = Array.from(bytes);
		temporary = [].concat(messageA);
		for (; 64 > temporary.length;) {
			temporary.push(0);
		}
		com.write([reportId].concat(temporary));
	}
	else {
		messageA = Array.from(bytes);
		if (contents.length > 57) {
			var chunkLen = (64 - messageA.length) - 2;
			var i, j, chunk = chunkLen;
			for (i = 0, j = contents.length; i < j; i += chunk) {
				var _chunk = contents.slice(i, i + chunk);

				temporary = [].concat(messageA).concat([slotId, _chunk.length < chunkLen ? _chunk.length : 255]).concat(_chunk);

				for (; 64 > temporary.length;) {
					temporary.push(0);
				}
				
				com.write([reportId].concat(temporary));
			}
		}
		else {
			if (slotId !== null) {
				bytes.push(slotId);
			}
			messageA = Array.from(bytes);
			temporary = [].concat(messageA).concat(contents);
			com.write([reportId].concat(temporary));
		}

	}
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
			
			msg = Array.from(msg);

			msg = msg.splice(0, 32);
			msg = Buffer.from(msg);

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

		hash = [1].concat(hash);

		var options = {
			contents: hash,
			slotId: parseInt(slot, 10),
			msgId: 'OKGETPUBKEY'
		};

		sendMessage(com, options);

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

			if (msg.toString("utf8").indexOf("Error device locked") == 0)
				return;
				
			msg = Array.from(msg);

			msg = msg.splice(0, 64);
			msg = Buffer.from(msg);

			com.close();

			if (done)
				done(msg.toString("base64"), argv.blob);

		});
		var crypto = require('crypto');
		var slot = argv.slot ? parseInt(argv.slot, 10) : 201;
		var hash = crypto.createHash('sha256').update(argv.data || "").digest();
		var blob = crypto.createHash('sha256').update(argv.blob /*+"lol"*/ || "").digest(); //.toString("hex");
		
		
		hash = Array.from(hash);
		hash = [].concat(hash);
		blob = Array.from(Buffer.from(blob)); //.slice(0,16);
		blob = [].concat(blob);

		var options = {
			contents: [].concat(blob).concat(hash),
			slotId: parseInt(slot, 10),
			msgId: 'OKSIGN'
		};
	
		sendMessage(com, options);

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

			var _sig = Uint8Array.from(Buffer.from(sig, 'base64'))

			var pk = Uint8Array.from(Buffer.from(pub, 'base64'));

			console.log("i have pub", pub)
			console.log("i have sig", sig)
			console.log("TEST", nacl.sign.detached.verify(md, _sig, pk) ? "PASSED" : "FAILED")

		});
	})
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
