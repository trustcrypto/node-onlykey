var EventEmitter = require("events").EventEmitter;

function API() {

    // define(function(require, exports, module) {
    /* global $ TextEncoder */

    var nacl = require("../libs/nacl");
    var forge = require("../libs/forge.min");


    var onConnection = null;
    var onStatus = null;
    var $onStatus = function(text) {
        if (onStatus) onStatus(text);
        else
            htmlLog(text);
    };

    // window.nacl = nacl;
    // window.forge = forge;

    var crypto = window.crypto;

    var log = console.log;

    var debug_log = console.warn;

    var htmlLog = function() {
        console.log.apply(console, arguments);
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
            args.push(arguments[i]);
        }
        args.join(" ");
        $("#console_output").append($("<span/>").text(args.join(" ")));
        $("#console_output").append($("<br/>"));
    };

    function msg(i) {
        htmlLog(i);
    }


    var sha256 = async function(s) {
        var hash = await crypto.subtle.digest({
            name: 'SHA-256'
        }, new window.TextEncoder().encode(s));
        hash = buf2hex(hash);
        hash = Array.from(hash.match(/.{2}/g).map(hexStrToDec));
        return hash;
    }

    async function digestMessage(message) {
        const msgUint8 = new TextEncoder().encode(message); // encode as (utf-8) Uint8Array
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
        return hashHex;
    }

    async function digestBuff(buff) {
        const msgUint8 = buff;
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
        return hashHex;
    }

    async function digestArray(buff) {
        const msgUint8 = buff;
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
        return hashArray;
    }

    function buf2hex(buffer) {
        // buffer is an ArrayBuffer
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    }

    function _setStatus(newStatus) {
        window._status = newStatus;
        log("Changed window._status to ", newStatus);
    }

    function encode_ctaphid_request_as_keyhandle(cmd, opt1, opt2, opt3, data) {
        debug_log('REQUEST CMD', cmd);
        debug_log('REQUEST OPT1', opt1);
        debug_log('REQUEST OPT2', opt2);
        debug_log('REQUEST OPT3', opt3);
        debug_log('REQUEST DATA', data);
        var addr = 0;

        // should we check that `data` is either null or an Uint8Array?
        data = data || new Uint8Array();

        const offset = 10;

        if (offset + data.length > 255) {
            throw new Error("Max size exceeded");
        }

        // `is_extension_request` expects at least 16 bytes of data
        const data_pad = data.length < 16 ? 16 - data.length : 0;
        var array = new Uint8Array(offset + data.length + data_pad);

        array[0] = cmd & 0xff;

        array[1] = opt1 & 0xff;
        array[2] = opt2 & 0xff;
        array[3] = opt3 & 0xff;
        array[4] = 0x8C; // 140
        array[5] = 0x27; //  39
        array[6] = 0x90; // 144
        array[7] = 0xf6; // 246

        array[8] = 0;
        array[9] = data.length & 0xff;

        array.set(data, offset);

        debug_log('FORMATTED REQUEST:', array);
        return array;
    }

    function decode_ctaphid_response_from_signature(response) {
        // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#using-the-ctap2-authenticatorgetassertion-command-with-ctap1-u2f-authenticators<Paste>
        //
        // compared to `parse_device_response`, the data is encoded a little differently here
        //
        // attestation.response.authenticatorData
        //
        // first 32 bytes: SHA-256 hash of the rp.id
        // 1 byte: zeroth bit = user presence set in U2F response (always 1)
        // last 4 bytes: signature counter (32 bit big-endian)
        //
        // attestation.response.signature
        // signature data (bytes 5-end of U2F response

        debug_log('UNFORMATTED RESPONSE:', response);

        var signature_count = (
            new DataView(
                response.authenticatorData.slice(33, 37)
            )
        ).getUint32(0, false); // get count as 32 bit BE integer

        var signature = new Uint8Array(response.signature);
        var data = null;
        var error_code = signature[0];

        if (error_code === 0) {
            data = signature.slice(1, signature.length);
            if (signature.length < 73 && bytes2string(data.slice(0, 9)) == 'UNLOCKEDv') {
                // Reset shared secret and start over
            }
            else if (signature.length < 73 && bytes2string(data.slice(0, 6)) == 'Error ') {
                // Something went wrong, read the ascii response and display to user
                var msgtext = data.slice(0, getstringlen(data));
                const btmsg = `${bytes2string(msgtext)}. Refresh this page and try again.`;
                //button.textContent = btmsg;
                //button.classList.remove('working');
                //button.classList.add('error');
                _setStatus('finished');
                throw new Error(bytes2string(msgtext));
            }
            else if (window._status === 'waiting_ping' || window._status === 'done_challenge') {
                // got data
                // encrypted_data = data;
                _setStatus('finished');
            }
        }
        else if (error_code == ctap_error_codes['CTAP2_ERR_NO_OPERATION_PENDING']) {
            // No data received, data has already been retreived or wiped due to 5 second timeout

            //button.textContent = 'no data received';
            _setStatus('finished');
            throw new Error('no data received');

        }
        else if (error_code == ctap_error_codes['CTAP2_ERR_USER_ACTION_PENDING']) {
            // Waiting for user to press button or enter challenge
            log('CTAP2_ERR_USER_ACTION_PENDING');
        }
        else if (error_code == ctap_error_codes['CTAP2_ERR_OPERATION_PENDING']) {
            // Waiting for user to press button or enter challenge
            log('CTAP2_ERR_OPERATION_PENDING');
        }

        return {
            count: signature_count,
            status: ctap_error_codes[error_code],
            data: data,
            signature: signature,
        };
    }

    async function ctaphid_via_webauthn(cmd, opt1, opt2, opt3, data, timeout) {
        // if a token does not support CTAP2, WebAuthn re-encodes as CTAP1/U2F:
        // https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#interoperating-with-ctap1-u2f-authenticators
        //
        // the bootloader only supports CTAP1, so the idea is to drop
        // u2f-api.js and the Firefox about:config fiddling
        //
        // problem: the popup to press button flashes up briefly :(
        //

        var keyhandle = encode_ctaphid_request_as_keyhandle(cmd, opt1, opt2, opt3, data);
        var challenge = window.crypto.getRandomValues(new Uint8Array(32));
        var request_options = {
            challenge: challenge,
            allowCredentials: [{
                id: keyhandle,
                type: 'public-key',
            }],
            timeout: timeout,
            // rpId: 'apps.crp.to',
            userVerification: 'discouraged',
            //userPresence: 'false',
            //mediation: 'silent',
            // extensions: {
            //  appid: 'https://apps.crp.to',
            // },
        };

        return window.navigator.credentials.get({
            publicKey: request_options
        }).then(assertion => {
            debug_log("GOT ASSERTION", assertion);
            debug_log("RESPONSE", assertion.response);
            let response = decode_ctaphid_response_from_signature(assertion.response);
            debug_log("RESPONSE:", response);
            if (response.status == 'CTAP2_ERR_USER_ACTION_PENDING') return response.status;
            if (response.status == 'CTAP2_ERR_OPERATION_PENDING') {
                _setStatus('done_challenge');
                return response.status;
            }
            return response.data;
        }).catch(error => {
            debug_log("ERROR CALLING:", cmd, opt1, opt2, opt3, data);
            debug_log("THE ERROR:", error);
            debug_log("NAME:", error.name);
            debug_log("MESSAGE:", error.message);
            if (error.name == 'NS_ERROR_ABORT' || error.name == 'AbortError' || error.name == 'InvalidStateError') {
                _setStatus('done_challenge');
                return 1;
            }
            else if (error.name == 'NotAllowedError' && os == 'Windows') {
                // Win 10 1903 issue
                return 1;
            }
            return Promise.resolve(); // error;
        });

    }

    const ctap_error_codes = {
        0x00: 'CTAP1_SUCCESS',
        0x01: 'CTAP1_ERR_INVALID_COMMAND',
        0x02: 'CTAP1_ERR_INVALID_PARAMETER',
        0x03: 'CTAP1_ERR_INVALID_LENGTH',
        0x04: 'CTAP1_ERR_INVALID_SEQ',
        0x05: 'CTAP1_ERR_TIMEOUT',
        0x06: 'CTAP1_ERR_CHANNEL_BUSY',
        0x0A: 'CTAP1_ERR_LOCK_REQUIRED',
        0x0B: 'CTAP1_ERR_INVALID_CHANNEL',

        0x10: 'CTAP2_ERR_CBOR_PARSING',
        0x11: 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
        0x12: 'CTAP2_ERR_INVALID_CBOR',
        0x13: 'CTAP2_ERR_INVALID_CBOR_TYPE',
        0x14: 'CTAP2_ERR_MISSING_PARAMETER',
        0x15: 'CTAP2_ERR_LIMIT_EXCEEDED',
        0x16: 'CTAP2_ERR_UNSUPPORTED_EXTENSION',
        0x17: 'CTAP2_ERR_TOO_MANY_ELEMENTS',
        0x18: 'CTAP2_ERR_EXTENSION_NOT_SUPPORTED',
        0x19: 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
        0x20: 'CTAP2_ERR_CREDENTIAL_NOT_VALID',
        0x21: 'CTAP2_ERR_PROCESSING',
        0x22: 'CTAP2_ERR_INVALID_CREDENTIAL',
        0x23: 'CTAP2_ERR_USER_ACTION_PENDING',
        0x24: 'CTAP2_ERR_OPERATION_PENDING',
        0x25: 'CTAP2_ERR_NO_OPERATIONS',
        0x26: 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
        0x27: 'CTAP2_ERR_OPERATION_DENIED',
        0x28: 'CTAP2_ERR_KEY_STORE_FULL',
        0x29: 'CTAP2_ERR_NOT_BUSY',
        0x2A: 'CTAP2_ERR_NO_OPERATION_PENDING',
        0x2B: 'CTAP2_ERR_UNSUPPORTED_OPTION',
        0x2C: 'CTAP2_ERR_INVALID_OPTION',
        0x2D: 'CTAP2_ERR_KEEPALIVE_CANCEL',
        0x2E: 'CTAP2_ERR_NO_CREDENTIALS',
        0x2F: 'CTAP2_ERR_USER_ACTION_TIMEOUT',
        0x30: 'CTAP2_ERR_NOT_ALLOWED',
        0x31: 'CTAP2_ERR_PIN_INVALID',
        0x32: 'CTAP2_ERR_PIN_BLOCKED',
        0x33: 'CTAP2_ERR_PIN_AUTH_INVALID',
        0x34: 'CTAP2_ERR_PIN_AUTH_BLOCKED',
        0x35: 'CTAP2_ERR_PIN_NOT_SET',
        0x36: 'CTAP2_ERR_PIN_REQUIRED',
        0x37: 'CTAP2_ERR_PIN_POLICY_VIOLATION',
        0x38: 'CTAP2_ERR_PIN_TOKEN_EXPIRED',
        0x39: 'CTAP2_ERR_REQUEST_TOO_LARGE',
    }

    function chr(c) {
        return String.fromCharCode(c);
    } // Because map passes 3 args

    function noop() {}

    function bytes2string(bytes) {
        var ret = Array.from(bytes).map(chr).join('');
        return ret;
    }

    function getstringlen(bytes) {
        for (var i = 1; i <= bytes.length; i++) {
            log("getstringlen ", i);
            if ((bytes[i] > 122 || bytes[i] < 97) && bytes[i] != 32) return i;
        }
    }

    function bytes2b64(bytes) {
        return u2f_b64(bytes2string(bytes));
    }

    function b642bytes(u2fb64) {
        return string2bytes(u2f_unb64(u2fb64));
    }

    function bytes2b64_B(bytes) {
        return window.btoa(bytes2string(bytes));
    }

    function b642bytes_B(b64) {
        return string2bytes(window.atob(u2fb64));
    }

    function u2f_b64(s) {
        return window.btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function u2f_unb64(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        return window.atob(s + '==='.slice((s.length + 3) % 4));
    }

    function decArr_to_hexdecArr(decArr) {
        var hexdecArr = [];
        for (var i = 0; i < decArr.length; i++) {
            hexdecArr.push(decimalToHexString(decArr[i]));
        }
        return hexdecArr;
    }

    function arrayBufToBase64UrlEncode(buf) {
        var binary = '';
        var bytes = new Uint8Array(buf);
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary)
            .replace(/\//g, '_')
            .replace(/=/g, '')
            .replace(/\+/g, '-');
    }

    function arrayBufToBase64UrlDecode(ba64) {
        var binary = u2f_unb64(ba64);
        var bytes = [];
        for (var i = 0; i < binary.length; i++) {
            bytes.push(binary.charCodeAt(i));
        }

        return new Uint8Array(bytes);
    }

    function decimalToHexString(number) {
        if (number < 0) {
            number = 0xFFFFFFFF + number + 1;
        }
        var val = number.toString(16).toUpperCase();
        if (val.length == 1)
            val = "0" + val;

        return val;
    }

    function arbuf2hex(buffer) {
        var hexCodes = [];
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i += 4) {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            var value = view.getUint32(i)
            // toString(16) will give the hex representation of the number without padding
            var stringValue = value.toString(16)
            // We use concatenation and slice for padding
            var padding = '00000000'
            var paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
        }

        // Join all the hex strings into one
        return hexCodes.join("");
    }

    function arbuf2sha256(hexstr) {
        // We transform the string into an arraybuffer.
        var buffer = new Uint8Array(hexstr.match(/[\da-f]{2}/gi).map(function(h) {
            return parseInt(h, 16)
        }));
        return crypto.subtle.digest("SHA-256", buffer).then(function(hash) {
            return arbuf2hex(hash);
        });
    }

    function mkchallenge(challenge) {
        var s = [];
        for (var i = 0; i < 32; i++) s[i] = String.fromCharCode(challenge[i]);
        return u2f_b64(s.join());
    }

    //-------------------------------------------------------------

    function hexStrToDec(hexStr) {
        return ~~(new Number('0x' + hexStr).toString(10));
    }

    function get_pin(byte) {
        if (byte < 6) return 1;
        else {
            return (byte % 5) + 1;
        }
    }

    var IntToByteArray = function(int) {
        var byteArray = [0,
            0,
            0,
            0
        ];
        for (var index = 0; index < 4; index++) {
            var byte = int & 0xff;
            byteArray[(3 - index)] = byte;
            int = (int - byte) / 256;
        }
        return byteArray;
    };

    // let wait = ms => new Promise(resolve => setTimeout(resolve, ms));

    function string2bytes(s) {
        var len = s.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) bytes[i] = s.charCodeAt(i);
        return bytes;
    }

    function hex_encode(byteArray) {
        return Array.prototype.map.call(byteArray, function(byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    }

    function hex_decode(hexString) {
        var result = [];
        for (var i = 0; i < hexString.length; i += 2) {
            result.push(parseInt(hexString.substr(i, 2), 16));
        }
        return Uint8Array.from(result);
    }


    function decode_key(b64_key) {
        var key = b64_key.split(".");

        if (key.length == 2) {
            return Uint8Array.from([].concat([0x04], arrayBufToBase64UrlDecode(key[0]), arrayBufToBase64UrlDecode(key[1])));
        }
        else {
            return arrayBufToBase64UrlDecode(b64_key);
        }
    }

    function encode_key(uint8array_key) {
        if (uint8array_key.length == 32) {
            return arrayBufToBase64UrlEncode(uint8array_key);
        }
        else if (uint8array_key.length == 65) {
            if (uint8array_key[0] == 0x04)
                return arrayBufToBase64UrlEncode(uint8array_key.slice(1, 33)) + "." + arrayBufToBase64UrlEncode(uint8array_key.slice(33, 66));

        }
        throw "Unknown Key Type to Encode";
    }

    function aesgcm_decrypt(encrypted, key) {
        return new Promise(resolve => {
            forge.options.usePureJavaScript = true;
            log("Key", key);
            var iv = new Uint8Array(12).fill(0);
            log("IV", iv);
            var decipher = forge.cipher.createDecipher('AES-GCM', key.match(/.{2}/g).map(hexStrToDec));
            decipher.start({
                iv: iv,
                tagLength: 0, // optional, defaults to 128 bits
            });
            log("Encrypted", encrypted);
            var buffer = forge.util.createBuffer(Uint8Array.from(encrypted));
            log("Encrypted length", buffer.length());
            log(buffer);
            decipher.update(buffer);
            decipher.finish();
            var plaintext = decipher.output.toHex();
            log("Plaintext", plaintext);
            //log("Decrypted AES-GCM Hex", forge.util.bytesToHex(decrypted).match(/.{2}/g).map(hexStrToDec));
            //encrypted = forge.util.bytesToHex(decrypted).match(/.{2}/g).map(hexStrToDec);
            resolve(plaintext.match(/.{2}/g).map(hexStrToDec));
        });
    }

    function aesgcm_encrypt(plaintext, key) {
        return new Promise(resolve => {
            forge.options.usePureJavaScript = true;
            log("Key", key);
            var iv = new Uint8Array(12).fill(0);
            log("IV", iv);
            //Counter used as IV, unique for each message
            var cipher = forge.cipher.createCipher('AES-GCM', key.match(/.{2}/g).map(hexStrToDec));
            cipher.start({
                iv: iv, // should be a 12-byte binary-encoded string or byte buffer
                tagLength: 0
            });
            log("Plaintext", plaintext);
            cipher.update(forge.util.createBuffer(Uint8Array.from(plaintext)));
            cipher.finish();
            var ciphertext = cipher.output;
            ciphertext = ciphertext.toHex(),
                resolve(ciphertext.match(/.{2}/g).map(hexStrToDec))
        });
    }

    function getOS() {
        var vendor = window.navigator.vendor,
            userAgent = window.navigator.userAgent,
            platform = window.navigator.platform,
            macosPlatforms = ['Macintosh', 'MacIntel', 'MacPPC', 'Mac68K'],
            windowsPlatforms = ['Win32', 'Win64', 'Windows', 'WinCE'],
            iosPlatforms = ['iPhone', 'iPad', 'iPod'],
            os = null;

        if (macosPlatforms.indexOf(platform) !== -1) {
            os = 'Mac OS-' + vendor;
        }
        else if (iosPlatforms.indexOf(platform) !== -1) {
            os = 'iOS-' + vendor;
        }
        else if (windowsPlatforms.indexOf(platform) !== -1) {
            os = 'Windows-' + vendor;
        }
        else if (/Android/.test(userAgent)) {
            os = 'Android-' + vendor;
        }
        else if (!os && /Linux/.test(platform)) {
            os = 'Linux-' + vendor;
        }

        return os;
    }


    var OKversion;
    var browser = "Chrome";

    if (window.navigator.userAgent.toLowerCase().indexOf('firefox') > -1)
        browser = "Firefox";

    var os = getOS();

    var appKey;
    var okPub;
    var sharedsec;

    var OKCMD = {
        OKCONNECT: 228
    };

    var KEYTYPE = {
        NACL: 0,
        P256R1: 1, //encrypt/decrypt
        P256K1: 2, //sign/verify
        CURVE25519: 3
    };

    var KEYACTION = {
        DERIVE_PUBLIC_KEY: 1,
        DERIVE_SHARED_SECRET: 2,
        DERIVE_PUBLIC_KEY_REQ_PRESS: 3,
        DERIVE_SHARED_SECRET_REQ_PRESS: 4
    };

    // function id(s) {
    //     return document.getElementById(s);
    // }

    function onlykey_connect(cb) {
        var delay = 0;

        setTimeout(async function() {
            console.log("-------------------------------------------");
            msg("Requesting OnlyKey Secure Connection (" + getOS() + ")");
            $onStatus("Requesting OnlyKey Secure Connection");

            var cmd = OKCMD.OKCONNECT;

            var message = [255, 255, 255, 255, OKCMD.OKCONNECT]; //Add header and message type
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);
            var env = [browser.charCodeAt(0), os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);
            var encryptedkeyHandle = Uint8Array.from(message); // Not encrypted as this is the initial key exchange

            var enc_resp = 1;
            await ctaphid_via_webauthn(cmd, null, null, null, encryptedkeyHandle, 6000).then(async(response) => {

                if (!response) {
                    msg("Problem setting time on onlykey");
                    $onStatus("Problem setting time on onlykey");
                    return;
                }

                var data = await Promise;

                okPub = response.slice(0, 32);
                console.info("Onlykey transit public", okPub);

                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    console.info("Onlykey transit public", okPub);
                    console.info("App transit public", appKey.publicKey);
                    console.info("Transit shared secret", transit_key);
                    transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    response = await aesgcm_decrypt(encrypted, transit_key);
                }

                var FWversion = bytes2string(response.slice(32 + 8, 32 + 20));
                OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';
                sharedsec = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);

                //msg("message -> " + message)
                msg("OnlyKey " + OKversion + " " + FWversion + " connection established\n");
                $onStatus("OnlyKey " + FWversion + " Connection Established");

                sha256(sharedsec).then((key) => {
                    //log("AES Key", bytes2b64(key));
                    if (typeof cb === 'function') cb(null);
                });
            });
        }, (delay * 1000));

    }

    function onlykey_derive_public_key(additional_d, keytype, press_required, cb) {
        var delay = 0;

        setTimeout(async function() {
            console.log("-------------------------------------------");
            msg("Requesting OnlyKey Derive Public Key");
            $onStatus("Requesting OnlyKey Derive Public Key");

            var cmd = OKCMD.OKCONNECT;
            //Add header and message type
            var message = [255, 255, 255, 255, OKCMD.OKCONNECT];

            //Add current epoch time
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);

            //Add transit pubkey
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);

            //Add Browser and OS codes
            var env = [browser.charCodeAt(0), os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);

            //Add additional data for key derivation
            var dataHash;
            if (!additional_d) {
                // SHA256 hash of empty buffer
                dataHash = await digestArray(Uint8Array.from(new Uint8Array(32)));
            }
            else {
                // SHA256 hash of input data
                dataHash = await digestArray(Uint8Array.from(additional_d)); //sha256 = 32 bytes
            }
            Array.prototype.push.apply(message, dataHash);

            var keyAction = press_required ? KEYACTION.DERIVE_PUBLIC_KEY_REQ_PRESS : KEYACTION.DERIVE_PUBLIC_KEY;

            var enc_resp = 1;
            await ctaphid_via_webauthn(cmd, keyAction, keytype, enc_resp, message, 6000).then(async(response) => {

                if (!response) {
                    msg("Problem Derive Public Key on onlykey");
                    $onStatus("Problem Derive Public Key on onlykey");
                    return;
                }

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                var sharedPub;
                okPub = response.slice(0, 32);

                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    console.info("Onlykey transit public", okPub);
                    console.info("App transit public", appKey.publicKey);
                    console.info("Transit shared secret", transit_key);
                    transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    response = await aesgcm_decrypt(encrypted, transit_key);
                }

                // OnlyKey version and model info
                var FWversion = bytes2string(response.slice(32 + 8, 32 + 20));
                OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) {
                    sharedPub = response.slice(response.length - (32), response.length);
                }
                else {
                    sharedPub = response.slice(response.length - (65), response.length);
                }
                msg("OnlyKey Derive Public Key Complete");

                $onStatus("OnlyKey Derive Public Key Completed ");
                console.info("sharedPub", sharedPub);


                if (keytype == KEYTYPE.P256R1) { //KEYTYPE_P256R1
                    ONLYKEY_ECDH_P256_to_EPUB(sharedPub, function(epub) {
                        if (typeof cb === 'function') cb(null, epub);
                    })
                }
                else if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) { //KEYTYPE_CURVE25519
                    // var eccKey_Pub = elliptic_curve25519.keyFromPublic(sharedPub).getPublic().encode("hex");
                    if (typeof cb === 'function') cb(null, encode_key(sharedPub));
                }

            });
        }, (delay * 1000));

    }

    function onlykey_derive_shared_secret(pubkey, additional_d, keytype, press_required, cb) {
        var delay = 0;
        if (OKversion == 'Original') {
            delay = delay * 4;
        }

        setTimeout(async function() {
            console.log("-------------------------------------------");
            msg("Requesting OnlyKey Shared Secret");
            $onStatus("Requesting OnlyKey Shared Secret");

            var cmd = OKCMD.OKCONNECT;
            //Add header and message type
            var message = [255, 255, 255, 255, OKCMD.OKCONNECT];

            //Add current epoch time
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);

            //Add transit pubkey
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);

            //Add Browser and OS codes
            var env = [browser.charCodeAt(0), os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);

            //Add additional data for key derivation
            if (!additional_d) {
                // SHA256 hash of empty buffer
                var dataHash = await digestArray(Uint8Array.from(new Uint8Array(32)));
            }
            else {
                // SHA256 hash of input data
                var dataHash = await digestArray(Uint8Array.from(additional_d));
            }
            Array.prototype.push.apply(message, dataHash);
            //msg("additional data hash -> " + dataHash)

            //Add input public key for shared secret computation 
            Array.prototype.push.apply(message, pubkey);
            //msg("input pubkey -> " + pubkey)
            //msg("full message -> " + message)

            var keyAction = press_required ? KEYACTION.DERIVE_SHARED_SECRET_REQ_PRESS : KEYACTION.DERIVE_SHARED_SECRET;

            var enc_resp = 1;
            await ctaphid_via_webauthn(cmd, keyAction, keytype, enc_resp, message, 6000).then(async(response) => {

                if (!response) {
                    msg("Problem getting Shared Secret");
                    $onStatus("Problem getting Shared Secret");
                    return;
                }

                var data = await Promise;

                var sharedPub;
                okPub = response.slice(0, 32);

                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    console.info("Transit shared secret", transit_key);
                    transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    response = await aesgcm_decrypt(encrypted, transit_key);
                }

                var FWversion = bytes2string(response.slice(32 + 8, 32 + 20));
                OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                if (keytype == KEYTYPE.NACL || keytype == KEYTYPE.CURVE25519) {
                    sharedPub = response.slice(response.length - (32 + 32), response.length - 32);
                }
                else {
                    sharedPub = response.slice(response.length - (32 + 65), response.length - 32);
                }
                //Private ECC key will be 32 bytes for all supported ECC key types
                sharedsec = response.slice(response.length - 32, response.length);

                console.info("sharedPub", sharedPub);
                console.info("sharedsec", sharedsec);

                msg("OnlyKey Shared Secret Completed\n");
                $onStatus("OnlyKey Shared Secret Completed ");

                var _k; //key to export in AESGCM hex;

                if (keytype == KEYTYPE.P256R1 || keytype == KEYTYPE.P256K1) {

                    _k = await build_AESGCM(sharedsec);

                    // var ssHex = hex_encode(sharedsec)
                    // console.log("ONLYLEY: shared secret hex", ssHex)
                    // console.log("ONLYLEY: derivedBits raw => " , Uint8Array.from(sharedsec));
                    // console.log("derivedBits -> AES-GCM =", _k);

                    if (typeof cb === 'function') cb(null, _k);
                }
                else if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) {
                    // var ssHex = hex_encode(sharedsec)
                    // console.log("ONLYLEY: shared secret hex", ssHex)
                    // console.log("ONLYLEY: derivedBits raw => " , Uint8Array.from(sharedsec));
                    // console.log("derivedBits -> AES-GCM =", _k);
                    _k = await build_AESGCM(sharedsec);
                    if (typeof cb === 'function') cb(null, _k);
                }

            });
        }, (delay * 1000));

    }

    function build_AESGCM(raw_secret) {
        return new Promise(async resolve => {
            var derivedKey = await window.crypto.subtle.importKey('raw', Uint8Array.from(raw_secret), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
            resolve(await window.crypto.subtle.exportKey('jwk', derivedKey).then(({ k }) => k));
        });
    }

    async function EPUB_TO_ONLYKEY_ECDH_P256(ePub, callback) {
        var xdecoded = arrayBufToBase64UrlDecode(ePub.split(".")[0]);
        var ydecoded = arrayBufToBase64UrlDecode(ePub.split(".")[1]);
        var publicKeyRawBuffer = new Uint8Array(65);
        var h = -1;
        for (var i in xdecoded) {
            h++;
            publicKeyRawBuffer[h] = xdecoded[i];
        }
        for (var j in ydecoded) {
            h++;
            publicKeyRawBuffer[h] = ydecoded[j];
        }

        if (publicKeyRawBuffer[0] == 0) {
            publicKeyRawBuffer = Array.from(publicKeyRawBuffer)
            publicKeyRawBuffer.unshift()
            publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer);
        }
        console.log("epub to raw", ePub, publicKeyRawBuffer)
        if (callback)
            callback(publicKeyRawBuffer)
    }

    async function ONLYKEY_ECDH_P256_to_EPUB(publicKeyRawBuffer, callback) {
        //https://stackoverflow.com/questions/56846930/how-to-convert-raw-representations-of-ecdh-key-pair-into-a-json-web-key

        //
        var orig_publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer);

        //console.log("publicKeyRawBuffer  B", publicKeyRawBuffer)
        // publicKeyRawBuffer = Array.from(publicKeyRawBuffer)
        // publicKeyRawBuffer.unshift(publicKeyRawBuffer.pop());
        // publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer)

        //console.log("publicKeyRawBuffer  F", publicKeyRawBuffer)

        if (false) {
            var $importedPubKey = await crypto.subtle.importKey(
                'raw', orig_publicKeyRawBuffer, {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                true, []
            ).catch(function(err) {
                console.error(err);
            }).then(function(importedPubKey) {
                exportKey(importedPubKey)
            });
        }
        else {
            var x = publicKeyRawBuffer.slice(1, 33);
            var y = publicKeyRawBuffer.slice(33, 66);

            crypto.subtle.importKey(
                'jwk', {
                    kty: "EC",
                    crv: "P-256",
                    x: arrayBufToBase64UrlEncode(x),
                    y: arrayBufToBase64UrlEncode(y)
                }, {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                true, []
            ).catch(function(err) {
                console.error(err);
            }).then(function(importedPubKey) {
                if (importedPubKey)
                    exportKey(importedPubKey)
            });
        }

        function exportKey(importedPubKey) {

            window.crypto.subtle.exportKey(
                    "jwk", //can be "jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
                    importedPubKey //can be a publicKey or privateKey, as long as extractable was true
                )
                .then(function(keydata) {

                    var OK_SEA_epub = keydata.x + '.' + keydata.y;

                    console.log("raw to epub", OK_SEA_epub, orig_publicKeyRawBuffer)

                    if (callback)
                        callback(OK_SEA_epub);

                })
                .catch(function(err) {
                    console.error(err);
                });

        }

    }

    var connected = false;

    this.connect = function(callback /*, _onStatus*/ ) {
        // if (_onStatus)
        //     onStatus = _onStatus;
        onlykey_connect(function(err) {
            if (!err)
                connected = true;
            if (typeof callback === 'function') callback(err);
        });
    }
    this.derive_public_key = function(AdditionalData, keytype, press_required, callback) {
        // if (connected)
        onlykey_derive_public_key(AdditionalData, keytype, press_required, callback);
    };
    this.derive_shared_secret = function(AdditionalData, pubkey, keytype, press_required, callback) {
        // if (connected) {
        if (keytype == KEYTYPE.P256R1) {
            EPUB_TO_ONLYKEY_ECDH_P256(pubkey, function(raw_pub_Key) {
                onlykey_derive_shared_secret(raw_pub_Key, AdditionalData, keytype, press_required, callback);
            });
        }
        else if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) {
            var raw_pub_Key = decode_key(pubkey);
            onlykey_derive_shared_secret(raw_pub_Key, AdditionalData, keytype, press_required, callback);

        }
        // }
    };
    this.build_AESGCM = build_AESGCM;
    this.decode_key = decode_key;
    this.encode_key = encode_key;
    this.sha256 = sha256;

    this.util = {
        sha256: sha256,
        build_AESGCM: build_AESGCM,
        decode_key: decode_key,
        encode_key: encode_key,
        base64_encode: bytes2b64,
        base64_decode: b642bytes,
        hex_encode: hex_encode,
        hex_decode: hex_decode
    }

}
API.prototype = new EventEmitter();


module.exports = new API();
