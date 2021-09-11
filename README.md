# node-onlykey

Get a Onlykey USB: [https://onlykey.io/sea](https://onlykey.io/sea)

Live Demo for 3rd Party: [https://trustcrypto.github.io/node-onlykey/docs/](https://trustcrypto.github.io/node-onlykey/docs/)

------

3rd Party Support
---

Supports
* NACL
* ECDH and ECDSA (p256)
* CURVE25519


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
_connect sets onlykey time_


```js
ok.derive_public_key(AdditionalData, keyType, press_required, function(error, jwk_epub) {})
ok.derive_shared_secret(AdditionalData, jwk_epub, keyType, press_required, function(error, shared_secret) {})
```

*   `additional_d` = `string` or `buffer` to point to a derived key
*   `jwk_epub` = public key in jwk format
*   `keyType` = key generation type
*   `shared_secret`  = shared AES-GCM key

`KEYTYPE`
*   KEYTYPE_NACL = `0`
*   KEYTYPE_P256R1 = `1`
*   KEYTYPE_P256K1 = `2`
*   KEYTYPE_CURVE25519 = `3`



API Authors
-----------
* Tim ~  onlykey.io
* Brad ~  bmatusiak.us
