# node-onlykey

## STATUS: ALPHA

Get an Onlykey: [https://onlykey.io/](https://onlykey.io/)

Live Demo: [https://docs.crp.to/node-onlykey/docs/](https://docs.crp.to/node-onlykey/docs/)

Please Leave Feedback Here [https://github.com/trustcrypto/node-onlykey/issues](https://github.com/trustcrypto/node-onlykey/issues)

Onlykey 3rd Party API
----


Supports
* ECDH and ECDSA (NIST256P1)
* ECDH and EDDSA (ED25519)
* NACL


API
----

```js
require("./dist/onlykey3rd-party.js")(function(ONLYKEY) {

  var ok = ONLYKEY();

})
```


Events
-----

```js
ok.on(event,function() {})
```

List of events

* `"status"`  outputs current operation in english
* `"error"`   emits any errors during operations


Methods
-----

```js
ok.connect(function() {})
```
`connect()` does ECDH for secure session using NACL and informs hardware of current time, OS, and browser.


```js
ok.derive_public_key(AdditionalData, keyType, press_required, function(error, ok_jwk_epub) {})
```

`derive_public_key()` does `connect()` and returns a hardware generated public key from OnlyKey

```js
ok.derive_shared_secret(AdditionalData, input_jwk_epub, keyType, press_required, function(error, shared_secret, ok_jwk_epub) {})
```

`derive_shared_secret()` does `connect()` and returns a hardware generated shared secret from OnlyKey that can be used as private key for encryption/signing

*   `AdditionalData` = `string` or `buffer` to point to a derived key
*   `input_jwk_epub` = input public key in jwk format
*   `ok_jwk_epub` = onlykey output public key in jwk format
*   `keyType` = key generation type
*   `shared_secret`  = shared AES-GCM key

`KEYTYPE`
*   KEYTYPE_NACL = `0`
*   KEYTYPE_P256R1 = `1`
*   KEYTYPE_P256K1 = `2`
*   KEYTYPE_CURVE25519 = `3`

How It Works
-----------

OnlyKey uses the RPID provided from FIDO2 (the origin url), the input public key `jwk_epub`, and any additional data `AdditionalData` such as a username to generate a public/private keypair. OnlyKey returns the public key with `derive_public_key()` and returns the shared secret of "input public/generated private" with `derive_shared_secret()`. 

Single-User Application - This shared secret can be used for encryption and signing purposes. Given the same inputs and the same web site origin the same shared secret can be recreated. 

Multi-User Application - Like a typical ECDH key exchange, both USERA and USERB obtain hardware generated public keys with `derive_public_key()`, these public keys are exchanged and used as input public key for `derive_shared_secret()`. Each user generates the same shared secret which can be used for encryption and signing purposes between USERA and USERB.

Run Demo Locally
-----------
```
$ node node-onlykey/docs/server.js 
```
Browse to http://localhost:3000

CLI
-----------
```
--help,-h,-?               shows this
--keypress,-p              use touch key
--keytype=1,-t=1           1=P256R1,3=CURVE25519
--seed='Onlykey Rocks!'    seed for aditional_data
--secret='pubkey'          pubkey to generate a secret from seed
--domain='localhost'       domain to generate keys for
```

API Authors
-----------
* Tim ~  onlykey.io
* Brad ~  bmatusiak.us
