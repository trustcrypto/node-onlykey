define(function(require, exports, module) {
    /* globals $ SEA GUN */

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


    module.exports = {
        start: function(testType) {

            console.log("onlykeyIndex");
            require("/dist/onlykey3rd-party.js")(function(ONLYKEY) {
                

                var onlykey;
                var pageLayout;
                var keyType;

                var press_required = (testType.split("-")[1] ? true : false);

                if (testType.split("-")[0] == "P256R1") {

                    keyType = 1; //P256R1
                    
                    onlykey = ONLYKEY(keyType);
                    
                    pageLayout = $(require("text!./pageLayout_P256R1.html"));

                    pageLayout.find("#connect_onlykey").click(function() {
                        onlykey.connect(async function() {
                            console.log("onlykey has connected");
                            pageLayout.find("#connect_onlykey").hide();
                            pageLayout.find("#connected_onlykey").show();

                            pageLayout.find("#derive_public_key").click();
                        }, async function(status) {
                            pageLayout.find("#connection_status").text(status);
                        });
                    });


                    pageLayout.find("#derive_public_key").click(function() {
                        var AdditionalData = $("#onlykey_additional_data").val();
                        onlykey.derive_public_key(AdditionalData, keyType, press_required, async function(err, key, keyString) {
                            if (err) console.log(err);
                            pageLayout.find("#onlykey_pubkey").val(key);

                            if ($("#encryptKey").val() == "")
                                $("#encryptKey").val(key);

                            if ($("#decryptKey").val() == "")
                                $("#decryptKey").val(key);


                            pageLayout.find("#encryptData").val("test");
                            //$("#encryptBTN").click();

                            (async function() {
                                var sharedSecret = await SEA.secret({
                                    epub: key
                                }, JSON.parse($("#sea_test_key").val()));

                                $("#sea_test_shared_secret").val(sharedSecret);


                                onlykey.derive_shared_secret(AdditionalData, JSON.parse($("#sea_test_key").val()).epub, keyType, press_required, async function(err, sharedSecret) {
                                    if (err) console.log(err);
                                    $("#ok_test_shared_secret").val(sharedSecret);
                                });

                            })();

                        });
                    });


                    pageLayout.find("#connect_onlykey").click();


                    $("#main-container").html(pageLayout);

                    $("#encryptBTN").click(async function() {

                        var encData = pageLayout.find("#encryptData").val();
                        var encryptoToKey = pageLayout.find("#encryptKey").val(); //.split("")
                        //onlykey.b642bytes()

                        var AdditionalData = $("#onlykey_additional_data").val();
                        onlykey.derive_shared_secret(AdditionalData, encryptoToKey, keyType, press_required, async function(err, sharedSecret) {
                            if (err) console.log(err);
                            var enc = await GUN.SEA.encrypt(encData, sharedSecret);

                            //pageLayout.find("#encryptData").val(enc);
                            pageLayout.find("#decryptData").val(enc);
                            pageLayout.find("#pills-decrypt-tab").click();
                        });


                    });

                    $("#decryptBTN").click(async function() {

                        var decData = pageLayout.find("#decryptData").val();
                        var decryptoToKey = pageLayout.find("#decryptKey").val();

                        var AdditionalData = $("#onlykey_additional_data").val();
                        onlykey.derive_shared_secret(AdditionalData, decryptoToKey, keyType, press_required, async function(err, sharedSecret) {
                            if (err) console.log(err);
                            //var enc = await SEA.encrypt('shared data', await SEA.secret(bob.epub, alice));

                            var dec = await GUN.SEA.decrypt(decData, sharedSecret);

                            pageLayout.find("#encryptData").val(dec);
                            pageLayout.find("#pills-encrypt-tab").click();
                        });


                    });

                    // (async function() {
                    //     $("#sea_test_key").text(JSON.stringify(await GUN.SEA.pair()))
                    // })()
                }

                /*  
                if (testType == "NACL.js") {
                    require("./test_nacl.js").start(testType)
                }*/

                if (testType.split("-")[0] == "CURVE25519") {
                    keyType = 3; //CURVE25519
                    
                    onlykey = ONLYKEY(keyType);
                    
                    pageLayout = $(require("text!./pageLayout_CURVE25519.html"));

                    pageLayout.find("#connect_onlykey").click(function() {
                        onlykey.connect(async function() {
                            console.log("onlykey has connected");
                            pageLayout.find("#connect_onlykey").hide();
                            pageLayout.find("#connected_onlykey").show();

                            pageLayout.find("#derive_public_key").click();
                        }, async function(status) {
                            pageLayout.find("#connection_status").text(status);
                        });
                    });


                    pageLayout.find("#derive_public_key").click(function() {
                        var AdditionalData = $("#onlykey_additional_data").val();
                        onlykey.derive_public_key(AdditionalData, keyType, press_required, async function(err, OK_sharedPubKey, keyString) {
                            if (err) console.log(err);
                            pageLayout.find("#onlykey_pubkey").val(OK_sharedPubKey);

                            if ($("#encryptKey").val() == "")
                                $("#encryptKey").val(OK_sharedPubKey);

                            if ($("#decryptKey").val() == "")
                                $("#decryptKey").val(OK_sharedPubKey);


                            pageLayout.find("#encryptData").val("test");
                            //$("#encryptBTN").click();

                            (async function() {
                                var ok_pubkey_decoded = onlykey.decode_key(OK_sharedPubKey);

                                var pair_bob = JSON.parse($("#sea_test_key").val());
                                var bobPubKey = pair_bob.epub; //<-- hex encoded
                                var bobPrivKey = pair_bob.epriv; //<-- hex encoded

                                var bobPubKey_decoded = onlykey.decode_key(bobPubKey); //<-- uint8array
                                var bobPrivKey_decoded = onlykey.decode_key(bobPrivKey); //<-- uint8array

                                console.log("bob1", onlykey.encode_key(bobPubKey_decoded));
                                console.log("bob2", onlykey.encode_key(bobPrivKey_decoded));

                                console.log("bobs_pair", pair_bob);

                                var nacl = require("nacl");
                                //nacl.scalarMult(bob priv key, sharedPub)
                                var ss = nacl.scalarMult(bobPrivKey_decoded, ok_pubkey_decoded);
                                // var ss = nacl.box.before(hex_decode(OK_sharedPubKey), bobPrivKey_decoded);

                                // await onlykey.build_AESGCM(ss)
                                var Bob_generated_sharedSecret = await onlykey.build_AESGCM(ss); //hex_encode(ss);


                                console.log("nacl:x25519 Bob_generated_sharedSecret", Bob_generated_sharedSecret);
                                $("#sea_test_shared_secret").val(Bob_generated_sharedSecret);

                                onlykey.derive_shared_secret(AdditionalData, bobPubKey, keyType, press_required, async function(err, sharedSecret) {
                                    if (err) console.log(err);
                                    $("#ok_test_shared_secret").val(sharedSecret);


                                    console.log("elliptic_curve25519: bobPubKey: ", bobPubKey);
                                    console.log("elliptic_curve25519: Bob_generated_sharedSecret: ", Bob_generated_sharedSecret);
                                });

                            })();

                        });
                    });


                    pageLayout.find("#connect_onlykey").click();


                    $("#main-container").html(pageLayout);

                    $("#encryptBTN").click(async function() {

                        var encData = pageLayout.find("#encryptData").val();
                        var encryptoToKey = pageLayout.find("#encryptKey").val(); //.split("")
                        //onlykey.b642bytes()
                        var AdditionalData = $("#onlykey_additional_data").val();
                        onlykey.derive_shared_secret(AdditionalData, encryptoToKey, keyType, press_required, async function(err, sharedSecret) {
                            if (err) console.log(err);
                            var enc = await GUN.SEA.encrypt(encData, sharedSecret);

                            //pageLayout.find("#encryptData").val(enc);
                            pageLayout.find("#decryptData").val(enc);
                            pageLayout.find("#pills-decrypt-tab").click();
                        });


                    });

                    $("#decryptBTN").click(async function() {

                        var decData = pageLayout.find("#decryptData").val();
                        var decryptoToKey = pageLayout.find("#decryptKey").val();
                        var AdditionalData = $("#onlykey_additional_data").val();
                        onlykey.derive_shared_secret(AdditionalData, decryptoToKey, keyType, press_required, async function(err, sharedSecret) {
                            if (err) console.log(err);
                            //var enc = await SEA.encrypt('shared data', await SEA.secret(bob.epub, alice));

                            var dec = await GUN.SEA.decrypt(decData, sharedSecret);

                            pageLayout.find("#encryptData").val(dec);
                            pageLayout.find("#pills-encrypt-tab").click();
                        });


                    });

                    // (async function() {
                    //     $("#sea_test_key").text(JSON.stringify(await GUN.SEA.pair()))
                    // })()
                }


            });

        }
    };







})
