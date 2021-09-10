module.exports = function(imports, onlykeyApi) {
    /* global TextEncoder */
    // var $ = require("jquery");
    var nacl = require("./nacl.min.js");
    var EventEmitter = require("events").EventEmitter;


    var extras = require("./onlykey.extra.js")(imports);
    var {
        // wait,
        async_sha256,
        hexStrToDec,
        bytes2string,
        // noop,
        // getstringlen,
        // mkchallenge,
        bytes2b64,
        // getOS,
        // ctap_error_codes,
        // getAllUrlParams,
        aesgcm_decrypt,
        // aesgcm_encrypt
        digestBuff,
        digestArray,
        arrayBufToBase64UrlDecode,
        arrayBufToBase64UrlEncode,
    } = extras;

    var window = imports.window;

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

    function build_AESGCM(raw_secret) {
        return new Promise(async resolve => {
            var derivedKey = await window.crypto.subtle.importKey('raw', Uint8Array.from(raw_secret), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
            resolve(await window.crypto.subtle.exportKey('jwk', derivedKey).then(({ k }) => k));
        });
    }

    function EPUB_TO_ONLYKEY_ECDH_P256(ePub, callback) {
        var xdecoded = arrayBufToBase64UrlDecode(ePub.split(".")[0]);
        var ydecoded = arrayBufToBase64UrlDecode(ePub.split(".")[1]);
        
        var publicKeyRawBuffer = Uint8Array.from([].concat(Array.from(xdecoded)).concat(Array.from(ydecoded)).concat([0]));
        
        if (callback)
            callback(publicKeyRawBuffer);
            
        return publicKeyRawBuffer;
        /*
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
        // console.log("epub to raw", ePub, publicKeyRawBuffer)
        if (callback)
            callback(publicKeyRawBuffer)

        return publicKeyRawBuffer;
        */
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
            var $importedPubKey = await imports.window.crypto.subtle.importKey(
                'raw', orig_publicKeyRawBuffer, {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                true, []
            ).catch(function(err) {
                // console.error(err);
            }).then(function(importedPubKey) {
                exportKey(importedPubKey)
            });
        }
        else {
            var x = publicKeyRawBuffer.slice(1, 33);
            var y = publicKeyRawBuffer.slice(33, 66);

            imports.window.crypto.subtle.importKey(
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
                // console.error(err);
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

                    // console.log("raw to epub", OK_SEA_epub, orig_publicKeyRawBuffer)

                    if (callback)
                        callback(OK_SEA_epub);

                })
                .catch(function(err) {
                    // console.error(err);
                });

        }

    }

    function onlykey(keytype) {

        var api = new EventEmitter();

        var appKey;

        api.connect = async function(cb) {
            var delay = 0;


            // console.log("-------------------------------------------");
            // msg("Requesting OnlyKey Secure Connection (" + getOS() + ")");
            // $onStatus("Requesting OnlyKey Secure Connection");

            var cmd = OKCMD.OKCONNECT;

            var message = [255, 255, 255, 255, OKCMD.OKCONNECT]; //Add header and message type
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);
            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);
            var encryptedkeyHandle = Uint8Array.from(message); // Not encrypted as this is the initial key exchange

            var enc_resp = 1;
            await onlykeyApi.ctaphid_via_webauthn(cmd, null, null, null, encryptedkeyHandle, 6000).then(async(response) => {

                if (!response.data) {
                    // msg("Problem setting time on onlykey");
                    // $onStatus("Problem setting time on onlykey");
                    return;
                }
                response = response.data;

                var data = await Promise;

                var okPub = response.slice(0, 32);
                // console.info("Onlykey transit public", okPub);

                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    // console.info("Onlykey transit public", okPub);
                    // console.info("App transit public", appKey.publicKey);
                    // console.info("Transit shared secret", transit_key);
                    transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    // console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    response = await aesgcm_decrypt(encrypted, transit_key);
                }
                
                //   transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                //   console.info("App AES Key", transit_key);
                //   var encrypted  = response.slice(32, response.length);
                //   onlykey_api.FWversion = bytes2string(response.slice(32+8, 32+20));
                //   response = await aesgcm_decrypt(encrypted, transit_key);
                //   onlykey_api.OKversion = response[32+19] == 99 ? 'Color' : 'Go';

                var FWversion = bytes2string(response.slice(32 + 8, 32 + 20));
                var OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';
                var sharedsec = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);

                //msg("message -> " + message)
                // msg("OnlyKey " + OKversion + " " + FWversion + " connection established\n");
                // $onStatus("OnlyKey " + FWversion + " Connection Established");

                async_sha256(sharedsec).then((key) => {
                    // console.log("AES Key", bytes2b64(key));
                    if (typeof cb === 'function') cb(null);
                });
            });


        }

        api.derive_public_key = async function(additional_d, keytype, press_required, cb) {

            // console.log("-------------------------------------------");
            // msg("Requesting OnlyKey Derive Public Key");
            // $onStatus("Requesting OnlyKey Derive Public Key");

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
            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
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
            await onlykeyApi.ctaphid_via_webauthn(cmd, keyAction, keytype, enc_resp, message, 6000).then(async(response) => {

                if (!response.data) {
                    // msg("Problem setting time on onlykey");
                    // $onStatus("Problem setting time on onlykey");
                    return;
                }
                response = response.data;

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                var sharedPub;
                var okPub = response.slice(0, 32);

                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    // console.info("Onlykey transit public", okPub);
                    // console.info("App transit public", appKey.publicKey);
                    // console.info("Transit shared secret", transit_key);
                    transit_key = Uint8Array.from(transit_key); //await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    // console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    response = await aesgcm_decrypt(encrypted, transit_key);
                }

                // OnlyKey version and model info
                var FWversion = bytes2string(response.slice(32 + 8, 32 + 20));
                var OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) {
                    sharedPub = response.slice(response.length - (32), response.length);
                }
                else {
                    sharedPub = response.slice(response.length - (65), response.length);
                }
                // msg("OnlyKey Derive Public Key Complete");

                // $onStatus("OnlyKey Derive Public Key Completed ");
                // console.info("sharedPub", sharedPub);


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


        }

        api.derive_shared_secret = async function(additional_d, pubkey, keytype, press_required, cb) {
            
            if(keytype == KEYTYPE.P256R1 || keytype == KEYTYPE.P256K1)
                pubkey = EPUB_TO_ONLYKEY_ECDH_P256(pubkey);

            // console.log("-------------------------------------------");
            // msg("Requesting OnlyKey Shared Secret");
            // $onStatus("Requesting OnlyKey Shared Secret");

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
            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);

            var dataHash;
            //Add additional data for key derivation
            if (!additional_d) {
                // SHA256 hash of empty buffer
                dataHash = await digestArray(Uint8Array.from(new Uint8Array(32)));
            }
            else {
                // SHA256 hash of input data
                dataHash = await digestArray(Uint8Array.from(additional_d));
            }
            Array.prototype.push.apply(message, dataHash);
            //msg("additional data hash -> " + dataHash)

            //Add input public key for shared secret computation 
            Array.prototype.push.apply(message, pubkey);
            //msg("input pubkey -> " + pubkey)
            //msg("full message -> " + message)

            var keyAction = press_required ? KEYACTION.DERIVE_SHARED_SECRET_REQ_PRESS : KEYACTION.DERIVE_SHARED_SECRET;

            var enc_resp = 1;
            await onlykeyApi.ctaphid_via_webauthn(cmd, keyAction, keytype, enc_resp, message, 6000).then(async(response) => {


                if (!response.data) {
                    // msg("Problem setting time on onlykey");
                    // $onStatus("Problem setting time on onlykey");
                    return;
                }
                response = response.data;

                // var data = await Promise;

                var sharedPub;
                var okPub = response.slice(0, 32);

                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    // console.info("Transit shared secret", transit_key);
                    transit_key = Uint8Array.from(transit_key); //await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    // console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    response = await aesgcm_decrypt(encrypted, transit_key);
                }

                var FWversion = bytes2string(response.slice(32 + 8, 32 + 20));
                var OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                if (keytype == KEYTYPE.NACL || keytype == KEYTYPE.CURVE25519) {
                    sharedPub = response.slice(response.length - (32 + 32), response.length - 32);
                }
                else {
                    sharedPub = response.slice(response.length - (32 + 65), response.length - 32);
                }
                //Private ECC key will be 32 bytes for all supported ECC key types
                var sharedsec = response.slice(response.length - 32, response.length);

                // console.info("sharedPub", sharedPub);
                // console.info("sharedsec", sharedsec);

                // msg("OnlyKey Shared Secret Completed\n");
                // $onStatus("OnlyKey Shared Secret Completed ");

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
        };

        return api;
    }



    return onlykey;
};
