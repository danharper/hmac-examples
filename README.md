e.g. for webhook hashes

---

Example Inputs:

| Variable | Value |
| --- | --- |
| key | `the shared secret key here` |
| message | `the message to hash here ` |

Example Outputs:

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
var cryto = require('crypto');

var key = 'the shared secret key here';
var message = 'the message to hash here';

var hash = crypto.createHmac('sha256', key).update(message);

// to lowercase hexits
hash.digest('hex');

// to base64
hash.digest('base64');
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
