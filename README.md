# go-vault-transit
Convenince library for accessing vault's transit engine

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
