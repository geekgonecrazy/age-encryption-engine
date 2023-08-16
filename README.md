# Age Encryption Engine

Sponsored by [Lendiom](https://lendiom.com)

## Usage

Expects at least 3 age public keys to be provided and 1 private key.  The public key to that private key must be in the list of public keys.

On startup it will call a function to check that all secrets can be decrypted with the provided private key.

### Generating Keys
Visit the [age project](filippo.io/age) and download the age cli.

```
❯ age-keygen
# created: 2023-02-13T14:07:43-06:00
# public key: age1ytvwh068w6qcaflq9cld2ag8rf3482da08xnmgz67nd0vezwwflqeyhwpe
AGE-SECRET-KEY-12YZRS0YPKYGKR0FK859QCU3DKP5CQZUKCK24F62E565WWDQDQ6RSSQLT2Y
```

Do that two more times.  Grab one of the private keys and put the other in a safe place.

### Setup
```
package main

import (
	"fmt"

	aee "github.com/geekgonecrazy/age-encryption-engine"
)

func main() {
	publicKeys := os.Getenv("AEE_PUBLIC_KEYS")
	privateKey := os.Getenv("AEE_PRIVATE_KEY")

	if len(publicKeys) < 1 {
		panic("AEE_PUBLIC_KEYS environment variable containing publicKeys is required to start")
	}

	if len(privateKey) < 1 {
		panic("AEE_PRIVATE_KEY environment variable containing encryption key is required to start")
	}

	engine := aee.New()

	if err := engine.AddEncryptionKeys(strings.Split(publicKeys, ",")); err != nil {
		panic(err)
	}

	if err := engine.AddDecryptionKey(privateKey); err != nil {
		panic(err)
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

This case assumes you'd start up with environment variables something like:
```
AEE_PUBLIC_KEYS=age1ytvwh068w6qcaflq9cld2ag8rf3482da08xnmgz67nd0vezwwflqeyhwpe,age1g5985y3242h3lwsq6f044324a0dgd2ss3w2ymmdq0gwr2359a5qsvd3dm2,age1320sl3g4jhrhs22gd3gy386pss3jxkr97g4sn4pmrtzjkdp8r98q5gxhkn
AEE_PRIVATE_KEY=AGE-SECRET-KEY-1WDLSS8XJD0PSG9GUNUGHASA7TET0PM6RUCQEUEZ0RC95VYH2KJWQD0A46Y
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
