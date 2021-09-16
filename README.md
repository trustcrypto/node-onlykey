# node-onlykey

Get a Onlykey USB: [https://onlykey.io/sea](https://onlykey.io/sea)

Live Demo for 3rd Party: [https://trustcrypto.github.io/node-onlykey/docs/](https://trustcrypto.github.io/node-onlykey/docs/)

------

3rd Party Support
---

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
* `"debug"`   outpus any debug and status in english, _like `status` but more details_


Methods
-----

```js
ok.connect(function() {})
```
`connect()` does ECDH for secure session using NACL and informs hardware of current time, OS, and browser.


```js
ok.derive_public_key(AdditionalData, keyType, press_required, function(error, jwk_epub) {})
```

`derive_public_key()` does `connect()` and returns a hardware generated public key from OnlyKey

```js
ok.derive_shared_secret(AdditionalData, jwk_epub, keyType, press_required, function(error, shared_secret) {})
```

_derive_shared_secret does _connect and returns a hardware generated shared secret from OnlyKey that can be used as private key for encryption/signing

*   `additional_d` = `string` or `buffer` to point to a derived key
*   `jwk_epub` = input public key in jwk format
*   `keyType` = key generation type
*   `shared_secret`  = shared AES-GCM key

`KEYTYPE`
*   KEYTYPE_NACL = `0`
*   KEYTYPE_P256R1 = `1`
*   KEYTYPE_P256K1 = `2`
*   KEYTYPE_CURVE25519 = `3`

How It Works
-----------

OnlyKey uses the RPID provided from FIDO2 (the origin url), the input public key (jwk_epub), and any additional data (additional_d) such as a username to generate a public/private keypair. OnlyKey returns the public key with _derive_public_key and returns the shared secret of "input public/generated private" with _derive_shared_secret. 

Single-User Application - This shared secret can be used for encryption and signing purposes. Given the same inputs and the same web site origin the same shared secret can be recreated. 

Multi-User Application - Like a typical ECDH key exchange, both USERA and USERB obtain hardware generated public keys with _derive_public_key, these public keys are exchanged and used as input public key for _derive_shared_secret. Each user generates the same shared secret which can be used for encryption and signing purposes between USERA and USERB.

API Authors
-----------
* Tim ~  onlykey.io
* Brad ~  bmatusiak.us
