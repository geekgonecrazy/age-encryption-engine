package engine

import (
	"errors"
	"log"
	"testing"

	"filippo.io/age"
)

const publicKey string = "age1qtvvjtg7dh3n3zqk0m0h7qqj2h57s7akqy3dgk8gz4traqnwts9qmk8j7w"
const privateKey string = "AGE-SECRET-KEY-178Q8UQNDPPL24S9K3JPJ3LZTQQ3KGZAJPZVFDUGMG67S99R5JH3QQ8Z64M"

func TestEncryptAndDecrypt(t *testing.T) {

	k1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Error("Error generating k1")
	}

	log.Println(k1.String(), k1.Recipient().String())

	k2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Error("Error generating k2")
	}

	log.Println(k2.String(), k2.Recipient().String())

	keys := []string{
		k1.Recipient().String(),
		k2.Recipient().String(),
		publicKey,
	}

	auditLog := []SecretAuditAction{}
	secretStore := map[string]Secret{}

	engine := New()

	if err := engine.AddEncryptionKeys(keys); err != nil {
		t.Error("Error Adding Encryption Keys", err)
	}

	if err := engine.AddDecryptionKey(privateKey); err != nil {
		t.Error("Error Adding Decryption Key", err)
	}

	engine.RegisterAuditHandler(func(auditAction SecretAuditAction) error {
		auditLog = append(auditLog, auditAction)

		return nil
	})

	engine.RegisterSaveHandler(func(s Secret) error {
		secretStore[s.Key] = s

		return nil
	})

	engine.RegisterReadHandler(func(key string) (Secret, error) {
		value, ok := secretStore[key]
		if !ok {
			return Secret{}, errors.New("not found")
		}

		return value, nil
	})

	engine.RegisterRemoveHandler(func(key string) error {
		delete(secretStore, key)

		return nil
	})

	engine.RegisterAreThereUnDecryptableSecretsHandler(func(publicKey string) (bool, error) {
		numberWithoutKey := 0

		for _, secret := range secretStore {
			hasKey := false
			for _, hash := range secret.PublicKeyIds {
				if publicKey == hash {
					hasKey = true
				}
			}

			if !hasKey {
				numberWithoutKey++
			}
		}

		return numberWithoutKey > 0, nil
	})

	if err := engine.Start(); err != nil {
		t.Error("Error Starting Engine", err)
	}

	t.Run("Encrypting", func(t *testing.T) {
		if err := engine.StoreSecret("func-updateSecret", "organization/{id}/customer/{id}/secret", "super-secret-words"); err != nil {
			t.Error("Should have encrypted secret but got", err)
		}
	})

	t.Run("Audit Log for Encrypt", func(t *testing.T) {
		if !checkAuditLog(auditLog, "encrypt", "func-updateSecret", "organization/{id}/customer/{id}/secret") {
			t.Error("Expected auditLog to contain log of encrypt but was missing")
		}
	})

	t.Run("Decrypting", func(t *testing.T) {
		decryptedResult, err := engine.RetrieveSecret("func-readSecret", "organization/{id}/customer/{id}/secret")
		if err != nil {
			t.Error("Expected to decrypt but got an error", err)
		}

		if decryptedResult != "super-secret-words" {
			t.Error("Expected decrypted result to be super-secret-words but got", decryptedResult)
		}
	})

	t.Run("Audit Log for Decrypt", func(t *testing.T) {
		if !checkAuditLog(auditLog, "decrypt", "func-readSecret", "organization/{id}/customer/{id}/secret") {
			t.Error("Expected auditLog to contain log of decrypt but was missing")
		}
	})

	armoredResult := ""

	t.Run("Request armored secret", func(t *testing.T) {

		armoredResult, err = engine.GetArmoredSecret("test-armoring", "organization/{id}/customer/{id}/secret")
		if err != nil {
			t.Error("Expected to return armored secret but got an error", err)
		}

		log.Println(armoredResult)
	})

	t.Run("Validate returned Armored secret", func(t *testing.T) {

		decryptedResult, err := engine.decryptArmoredSecret(armoredResult)
		if err != nil {
			t.Error("Expected to return decrypted secret but got an error", err)
		}

		log.Println(decryptedResult)

		if decryptedResult != "super-secret-words" {
			t.Error("Expected decrypted result to be super-secret-words but got", decryptedResult)
		}
	})

	//for _, l := range auditLog {
	//	log.Println(fmt.Sprintf("%+v", l))
	//}

	//for _, secret := range secretStore {
	//	log.Println(fmt.Sprintf("%+v", secret))
	//}

}

func checkAuditLog(auditLog []SecretAuditAction, action, performer, key string) bool {
	for _, log := range auditLog {
		if log.Performer == performer && log.Key == key && log.Action == action {
			return true
		}
	}

	return false
}
