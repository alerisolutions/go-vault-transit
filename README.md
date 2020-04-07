# go-vault-transit
Convenience library for accessing vault's transit engine

## Examples

### Accessing the transit engine

```go
import (
    "github.com/hashicorp/vault/api"
    "github.com/alerisolutions/go-vault-transit/v1"
)

(...)
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
err := engine.CreateKey("key1", WithType("aes256-gcm96"), WithConvergentEncryption(), WithDerived())
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
hash, err := i.Hash([]byte("Something"), HashWithAlgo("sha2-224"), HashWithFormat("base64"))
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
