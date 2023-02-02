# Age Encryption Engine

Sponsored by [Lendiom](https://lendiom.com)

## Usage

### Setup
```
keys := []string{
    "age1p5eeuhknfm7zemel2k3mth3wmt5qwtl57rhkflpl52gwupe0adkqsy3vgu",
    "age1p5eeuhknfm7zemel2k3mth3wmt5qwtl57rhkflpl52gwupe0adkqsy3vgu",
    "age1qtvvjtg7dh3n3zqk0m0h7qqj2h57s7akqy3dgk8gz4traqnwts9qmk8j7w" # publicKey for our private key
}

privateKey := "AGE-SECRET-KEY-178Q8UQNDPPL24S9K3JPJ3LZTQQ3KGZAJPZVFDUGMG67S99R5JH3QQ8Z64M"

engine := New()

if err := engine.AddEncryptionKeys(keys); err != nil {
    // Handle error
}

if err := engine.AddDecryptionKey(privateKey); err != nil {
    // Handle error
}

engine.RegisterAuditHandler(func(performer, action, key string) error {
    // Logic to write audit log to your audit system

    return nil
})

engine.RegisterSaveHandler(func(perfomer, key, encryptedData string) error {
    // Logic to write your secret to persistant storage

    return nil
})

engine.RegisterReadHandler(func(key string) (string, error) {
    // Logic to read secret from persistant storage

    return value, nil
})

if err := engine.Start(); err != nil {
    // handle - common cases would be not enough keys or no matching public key for your private key
}
```

### EncryptSecret

```
if err := engine.EncryptSecret("func-updateSecret", "organization/{id}/customer/{id}/secret", "super-secret-words-here"); err != nil {
    // Handle your error
}
```

### DecryptSecret

```
decryptedResult, err := engine.DecryptSecret("func-readSecret", "organization/{id}/customer/{id}/secret")
if err != nil {
    // Handle your error
}

// Do something carefully with your secret
```

### GetArmored Secret

Not sure about keeping this one exposed

```
armoredResult, err = engine.GetArmoredSecret("test-armoring", "organization/{id}/customer/{id}/secret")
if err != nil {
    // Handle your error
}

// do with your armored secret as you need
```
