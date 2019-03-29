e.g. for webhook hashes

---

Example inputs:

| Variable | Value |
| --- | --- |
| key | `the shared secret key here` |
| message | `the message to hash here ` |

Reference outputs for example inputs above:

| Type | Hash |
| --- | --- |
| as hexit | `4643978965ffcec6e6d73b36a39ae43ceb15f7ef8131b8307862ebc560e7f988` |
| as base64 | `RkOXiWX/zsbm1zs2o5rkPOsV9++BMbgweGLrxWDn+Yg=` |

---

## PHP

```php
<?php

$key = 'the shared secret key here';
$message = 'the message to hash here';

// to lowercase hexits
hash_hmac('sha256', $message, $key);

// to base64
base64_encode(hash_hmac('sha256', $message, $key, true));
```

## NodeJS

```js
var crypto = require('crypto');

var key = 'the shared secret key here';
var message = 'the message to hash here';

var hash = crypto.createHmac('sha256', key).update(message);

// to lowercase hexits
hash.digest('hex');

// to base64
hash.digest('base64');
```

## JavaScript ES6

_Using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), available in all modern browsers. <sup>[[1]](https://caniuse.com/#feat=cryptography)</sup>_

```js
const key = 'the shared secret key here';
const message = 'the message to hash here';

const getUtf8Bytes = str =>
  new Uint8Array(
    [...unescape(encodeURIComponent(str))].map(c => c.charCodeAt())
  );

const keyBytes = getUtf8Bytes(key);
const messageBytes = getUtf8Bytes(message);

const cryptoKey = await crypto.subtle.importKey(
  'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' },
  true, ['sign']
);
const sig = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);

// to lowercase hexits
[...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');

// to base64
btoa(String.fromCharCode(...new Uint8Array(sig)));
```

## Ruby

```rb
require 'openssl'
require 'base64'

key = 'the shared secret key here'
message = 'the message to hash here'

# to lowercase hexits
OpenSSL::HMAC.hexdigest('sha256', key, message)

# to base64
Base64.encode64(OpenSSL::HMAC.digest('sha256', key, message))
```

## Elixir

```elixir
key = 'the shared secret key here'
message = 'the message to hash here'

signature = :crypto.hmac(:sha256, key, message)

# to lowercase hexits
Base.encode16(signature, case: :lower)

# to base64
Base.encode64(signature)
```

## Go

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func main() {
	secret := []byte("the shared secret key here")
	message := []byte("the message to hash here")
	
	hash := hmac.New(sha256.New, secret)
	hash.Write(message)
	
	// to lowercase hexits
	hex.EncodeToString(hash.Sum(nil))
	
	// to base64
	base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
```

## Python 2

```py
import hashlib
import hmac
import base64

message = bytes('the message to hash here').encode('utf-8')
secret = bytes('the shared secret key here').encode('utf-8')

hash = hmac.new(secret, message, hashlib.sha256)

# to lowercase hexits
hash.hexdigest()

# to base64
base64.b64encode(hash.digest())
```

## Python 3

```py
import hashlib
import hmac
import base64

message = bytes('the message to hash here', 'utf-8')
secret = bytes('the shared secret key here', 'utf-8')

hash = hmac.new(secret, message, hashlib.sha256)

# to lowercase hexits
hash.hexdigest()

# to base64
base64.b64encode(hash.digest())
```

## C&#35;

```cs
using System;
using System.Security.Cryptography;
using System.Text;

class MainClass {
  public static void Main (string[] args) {
    string key = "the shared secret key here";
    string message = "the message to hash here";
    
    byte[] keyByte = new ASCIIEncoding().GetBytes(key);
    byte[] messageBytes = new ASCIIEncoding().GetBytes(message);
    
    byte[] hashmessage = new HMACSHA256(keyByte).ComputeHash(messageBytes);
    
    // to lowercase hexits
    String.Concat(Array.ConvertAll(hashmessage, x => x.ToString("x2")));
    
    // to base64
    Convert.ToBase64String(hashmessage);
  }
}
```

## Java

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.xml.bind.DatatypeConverter;

class Main {
  public static void main(String[] args) {
  	try {
	    String key = "the shared secret key here";
	    String message = "the message to hash here";
	    
	    Mac hasher = Mac.getInstance("HmacSHA256");
	    hasher.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
	    
	    byte[] hash = hasher.doFinal(message.getBytes());
	    
	    // to lowercase hexits
	    DatatypeConverter.printHexBinary(hash);
	    
	    // to base64
	    DatatypeConverter.printBase64Binary(hash);
  	}
  	catch (NoSuchAlgorithmException e) {}
  	catch (InvalidKeyException e) {}
  }
}
```

---

* https://stackoverflow.com/questions/13109588/base64-encoding-in-java
* http://www.jokecamp.com/blog/examples-of-creating-base64-hashes-using-hmac-sha256-in-different-languages/
