# Hierarchical Deterministic (HD) wallets Plugin
This plugin allows you to derive BIP32 child key pair (xprv, xpub) from BIP32 master key
## Initial setup
import BIP32 master key in SDKMS as secrete object in raw byte format

**Example BIP32 Master Key:** xprv9s21ZrQH143K2yLSxbXemfny4nZroqhpiXEQ1MYx8vo2k7HRXypsWesNr7GkWTuU9CeaW7QeR38NjjaSfZBAAZVkVEpXwEkxLLXP2q1iFUd

## input and output for bitcoin key derivation
Plugin takes master key-id and derivation path as json input and return child private(xprv) and public(xpub) key as response

**Example: Input**
```
{
	"masterKeyId": "fbd70d51-9719-4da8-8f0f-1d304b78df44",
	"path": "m/2"
}
```
**Example: Output**
```
{
  "privateKey": "xprv9vEJzyGyCyy8fWJWmJjFmqVZPk8c5Ha1XuZ1yG2n4zwUf9LAUzsi8PeZEm7PAHBTSQsie6r8pdUm7nkGYUDuJomTNX3mSgbxxvLC9hhfCtM",
  "publicKey": "xpub69DfQUos3MXRszNysLGG8ySHwmy6UkHru8UcmeSPdLUTXwfK2YBxgBy363gdQNv3GWJVbPmFPUhAyWLuECCZgpVAcqLptqXvCNxu6qZHZTw"
}
```

# License

This project is primarily distributed under the terms of the Apache License, Version 2.0 (the "License"), see [LICENSE](./LICENSE) for details.
