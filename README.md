# go-vault-transit

![Go](https://github.com/alerisolutions/go-vault-transit/workflows/Go/badge.svg?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/alerisolutions/go-vault-transit)](https://goreportcard.com/report/github.com/alerisolutions/go-vault-transit)

Convenience library for accessing vault's transit engine. Allows for using Encryption-as-a-service from go applications, where key material is handled by Vault and not by the application.

## Prerequisites

* Go 1.13+
* Vault 1.3+

## Examples

### Accessing the transit engine

```go
import (
    "github.com/hashicorp/vault/api"
    "github.com/alerisolutions/go-vault-transit/v1"
)

(...)
    // set up vault api client
    cfg := api.DefaultConfig()
    // more config options, e.g. enable tls
    client, err := api.NewClient(cfg)
    if err != nil {
        panic(err)
    }

    engine := transit.NewTransitWithPath(client, "/transit")
```

### Key Management

Supported Operations:
* Create Key 
* List Keys
* Read Key Metadata
* Delete Keys

Create a named Key with a specific type and options:
```go
err := engine.CreateKey("key1", WithType("aes256-gcm96"), WithExportable(),  WithPlaintextBackup())
```

List all keys:
```go
keys, err := engine.ListKeys()
// ...
for _, keyName := range keys {
    // ...
}
```

Read metadata of a named key:
```go
keySpec, err := engine.ReadKey("key1")
// ...
fmt.Printf("%#v", keySpec)
```

Delete a named key:
```go
err = engine.DeleteKey("key1")
```

### Hashing

Compute hash value from byte array with given algorithm and output format:
```go
hash, err := i.Hash([]byte("Something"), WithHashAlgo("sha2-224"), WithHashFormat("base64"))
```

### Hmac computation and verification

```go
input := []byte("Something")
hmac1, err := i.Hmac("key1", input, WithHmacAlgo("sha2-512"))
bOk, err := i.VerifyHmac("key1", input, hmac1, WithHmacAlgo("sha2-512"))
// bOk == true
```

### Encryption and Decryption

```go
plaintext := "Something"
ciphertext, err := i.Encrypt("key1", []byte(plaintext))
decrypted, err := i.Decrypt("key1", ciphertext)
// decrypted == plaintext
```

### Signature and Verify

```go
input := "Something"
signature, err := i.Sign("key1", []byte(input), WithSignAlgo("sha2-256"))
valid, err := i.Verify("key1", []byte(input), signature, WithSignAlgo("sha2-256"))
// valid == true
```


## Testing

Unit tests run against a vault instance, typically a simple `-dev` instance, e.g. by

```
$ vault server -dev -dev-root-token-id=root
$ VAULT_ADDR=http://127.0.0.1:8200/ VAULT_TOKEN=root vault secrets enable transit
```

Then

```
$ go test -v
(...)
```

# License
(C) 2020 Andreas Schmidt, Aleri Solutions GmbH. Licensed under the Apache License, Version 2.0
