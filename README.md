# Age Encryption Engine

Sponsored by [Lendiom](https://lendiom.com)

## Usage

### Setup
```
package main

import (
	"fmt"

	aee "github.com/geekgonecrazy/age-encryption-engine"
)

func main() {

	keys := []string{
		"age1p5eeuhknfm7zemel2k3mth3wmt5qwtl57rhkflpl52gwupe0adkqsy3vgu",
		"age1p5eeuhknfm7zemel2k3mth3wmt5qwtl57rhkflpl52gwupe0adkqsy3vgu",
		"age1qtvvjtg7dh3n3zqk0m0h7qqj2h57s7akqy3dgk8gz4traqnwts9qmk8j7w",
	}

	privateKey := "AGE-SECRET-KEY-178Q8UQNDPPL24S9K3JPJ3LZTQQ3KGZAJPZVFDUGMG67S99R5JH3QQ8Z64M"

	engine := aee.New()

	if err := engine.AddEncryptionKeys(keys); err != nil {
		// Handle error
	}

	if err := engine.AddDecryptionKey(privateKey); err != nil {
		// Handle error
	}

	engine.RegisterAuditHandler(func(action aee.SecretAuditAction) error {
		// Replace with your own logic to save audit log
		fmt.Printf("performer:%s\naction:%s\nkey:%s", action.Performer, action.Action, action.Key)

		return nil
	})

	engine.RegisterSaveHandler(func(action aee.Secret) error {
		// Logic to write your secret to persistant storage

		return nil
	})

	engine.RegisterReadHandler(func(key string) (aee.Secret, error) {
		// Logic to read secret from persistant storage

		return value, nil
	})

	engine.RegisterAreThereUnDecryptableSecretsHandler(func(publicKey string) (bool, error) {
		// The engine takes the private key and gets its public key.  Then calls this function giving you a chance to find any secrets that won't be able to be decrypted by this key.  See test suite for an example of how this works using in memory db

		return false, nil
	})

	if err := engine.Start(); err != nil {
		// handle - common cases would be not enough keys or no matching public key for your private key
	}
}
```

### StoreSecret

```
if err := engine.StoreSecret("func-updateSecret", "organization/{id}/customer/{id}/secret", "super-secret-words-here"); err != nil {
    // Handle your error
}
```

### RetrieveSecret

```
decryptedResult, err := engine.Retrieve("func-readSecret", "organization/{id}/customer/{id}/secret")
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

### Auditing
Every function that touches a secret takes a performer as the first argument. This could be used maybe to do something like this:

```
func auditPerformerHelper(detail string, userId string, ip string) string {
    return fmt.Sprintf("%s-%s-%s", detail, userId, ip)
}

func retrieveMySecret(secretName string) (string, error) {
    userId := 123 // Pull from your session
    ip := "8.8.8.8" // Pull from your request

    decryptedResult, err := engine.DecryptSecret(auditPerformerHelper(userId, ip, "retrieve-my-secret"), fmt.Sprintf("genericSecret/%s/%s", userId, secretName))
    if err != nil {
        return "", err
    }

    return decryptedResult, nil
}
```

Now in your audit trail you can know what secret was accessed via what method and by who.
