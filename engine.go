package engine

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// SecretAuditAction
type SecretAuditAction struct {
	Action      string
	Performer   string
	Key         string
	CreatedDate time.Time
}

type Secret struct {
	Key          string
	Value        string
	Performer    string
	PublicKeyIds []string
	CreatedDate  time.Time
	ModifiedDate time.Time
}

// AgeSecretEncryptionEngine a library for encrypting secrets using age encryption
type AgeSecretEncryptionEngine struct {
	identity                            age.Identity
	identityPubHash                     string
	recipients                          []age.Recipient
	recipientPubHashes                  []string
	auditHandler                        func(audit SecretAuditAction) error
	readHandler                         func(reason, key string) (s Secret, err error)
	areThereUnDecryptableSecretsHandler func(key string) (bool, error)
	saveHandler                         func(secret Secret) error
	removeHandler                       func(key string) error
	initialized                         bool
}

// New initializes a new AgeSecretEncryptionEngine.
func New() *AgeSecretEncryptionEngine {
	return &AgeSecretEncryptionEngine{}
}

// AddDecryptionKey this is your most secret of key.  This is the one that will be used to retrieve the encrypted contents
func (e *AgeSecretEncryptionEngine) AddDecryptionKey(privateKey string) error {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
		return errors.New("failed to parse private key")
	}

	iPublicKey := identity.Recipient().String()
	public_key_hash := md5.Sum([]byte(iPublicKey))

	e.identity = identity
	e.identityPubHash = fmt.Sprintf("%x", public_key_hash)

	return nil
}

// AddEncryptionKeys this is your list of public keys that will be used to encrypt with.  Be sure you provide more than 3 and include the public key for your private key.  Store the private keys not being used somewhere safe in case you need to rotate the key
func (e *AgeSecretEncryptionEngine) AddEncryptionKeys(publicKeys []string) error {
	for _, key := range publicKeys {
		recipient, err := age.ParseX25519Recipient(key)
		if err != nil {
			return err
		}

		recipient_key_hash := md5.Sum([]byte(recipient.String()))

		e.recipientPubHashes = append(e.recipientPubHashes, fmt.Sprintf("%x", recipient_key_hash))
		e.recipients = append(e.recipients, recipient)
	}

	return nil
}

func (e *AgeSecretEncryptionEngine) Start() error {

	// This is to ensure can rotate out privateKeys and recover data
	if len(e.recipients) < 3 {
		return errors.New("at least 3 publicKeys required")
	}

	if e.identityPubHash == "" {
		return errors.New("a private key is required for operation")
	}

	iPublicKeyIncluded := false
	for _, h := range e.recipientPubHashes {
		if h == e.identityPubHash {
			iPublicKeyIncluded = true
		}
	}

	// Ensures the public key for the private key is included
	if !iPublicKeyIncluded {
		return errors.New("must include public key for chosen privatekey")
	}

	if e.saveHandler == nil {
		return errors.New("must register a save handler")
	}

	if e.auditHandler == nil {
		return errors.New("must register an audit handler")
	}

	if e.readHandler == nil {
		return errors.New("must register a read handler")
	}

	if e.removeHandler == nil {
		return errors.New("must register a remove handler")
	}

	if e.areThereUnDecryptableSecretsHandler == nil {
		return errors.New("must register a handler to check for undecryptable secrets")
	}

	unDecryptable, err := e.areThereUnDecryptableSecretsHandler(e.identityPubHash)
	if err != nil {
		return err
	}

	if unDecryptable {
		return errors.New("there are secrets encrypted that your private key can't decrypt")
	}

	e.initialized = true

	return nil
}

// RegisterAuditHandler registers the audit handler which will be executed before every Encrypt / Decrypt so its clear who and what touched data and when
func (e *AgeSecretEncryptionEngine) RegisterAuditHandler(f func(audit SecretAuditAction) error) {
	e.auditHandler = f
}

// RegisterReadHandler registers the read handler which will be used by the engine to retrieve secrets using your logic to talk to your db provider
func (e *AgeSecretEncryptionEngine) RegisterReadHandler(f func(key string) (s Secret, err error)) {
	// Wrap read handler with our own to make sure we log every read we do
	e.readHandler = func(method, key string) (Secret, error) {
		if err := e.auditHandler(SecretAuditAction{Performer: fmt.Sprintf("age-secret-encryption-engine-%s", method), Action: "read", Key: key}); err != nil {
			return Secret{}, err
		}

		return f(key)
	}
}

// RegisterAreThereUnDecryptableSecretsHandler registers a handler to check if there are any secrets that aren't encrypted using the public key for current secret key.
func (e *AgeSecretEncryptionEngine) RegisterAreThereUnDecryptableSecretsHandler(f func(key string) (bool, error)) {
	e.areThereUnDecryptableSecretsHandler = f
}

// RegisterSaveHandler registers the save handler which will be used by the engine to save secrets using your logic to talk to your db provider
func (e *AgeSecretEncryptionEngine) RegisterSaveHandler(f func(s Secret) error) {
	e.saveHandler = f
}

// RegisterRemoveHandler registers the remove handler which will be used by the engine to rmove secrets using your logic to talk to your db provider
func (e *AgeSecretEncryptionEngine) RegisterRemoveHandler(f func(key string) error) {
	e.removeHandler = f
}

// StoreSecret Encrypts the secret using age and saves using your save handler
func (e *AgeSecretEncryptionEngine) StoreSecret(performer, key, body string) error {
	if !e.initialized {
		return errors.New("engine not started")
	}

	// Audit step must always be executed before we even let it encrypt
	if err := e.auditHandler(SecretAuditAction{Performer: performer, Action: "encrypt", Key: key}); err != nil {
		return err
	}

	out := &bytes.Buffer{}

	w, err := age.Encrypt(out, e.recipients...)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(w, body); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	if err := e.saveHandler(Secret{Performer: performer, PublicKeyIds: e.recipientPubHashes, Key: key, Value: out.String()}); err != nil {
		return err
	}

	return nil
}

// RetrieveSecret Fetches the secret using your read handler and decrypts it using age
func (e *AgeSecretEncryptionEngine) RetrieveSecret(performer, key string) (decryptedSecret string, err error) {
	if !e.initialized {
		return "", errors.New("engine not started")
	}

	// Audit step must always be executed before we even let it do anything
	if err := e.auditHandler(SecretAuditAction{Performer: performer, Action: "decrypt", Key: key}); err != nil {
		return "", err
	}

	secret, err := e.readHandler("decrypt-method", key)
	if err != nil {
		return "", err
	}

	r, err := age.Decrypt(strings.NewReader(secret.Value), e.identity)
	if err != nil {
		return "", err
	}

	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		return "", err
	}

	return out.String(), nil
}

// RemoveSecret removes secret using the remove handler
func (e *AgeSecretEncryptionEngine) RemoveSecret(performer, key string) error {
	if !e.initialized {
		return errors.New("engine not started")
	}

	// Audit step must always be executed before we even let it do anything
	if err := e.auditHandler(SecretAuditAction{Performer: performer, Action: "remove", Key: key}); err != nil {
		return err
	}

	if err := e.removeHandler(key); err != nil {
		return err
	}

	return nil
}

// GetArmoredSecret Retrieves secret using read handler and returns an armored copy of it
func (e *AgeSecretEncryptionEngine) GetArmoredSecret(performer, key string) (armoredSecret string, err error) {
	if !e.initialized {
		return "", errors.New("engine not started")
	}

	// Audit step must always be executed before we even let it do anything
	if err := e.auditHandler(SecretAuditAction{Performer: performer, Action: "armoring", Key: key}); err != nil {
		return "", err
	}

	secret, err := e.readHandler("get-armored-secret-method", key)
	if err != nil {
		return "", err
	}

	out := &bytes.Buffer{}
	armorWriter := armor.NewWriter(out)

	if _, err := io.Copy(armorWriter, strings.NewReader(secret.Value)); err != nil {
		return "", err
	}

	if err := armorWriter.Close(); err != nil {
		return "", err
	}

	return out.String(), nil
}

// Unexported for use of validating armoring
func (e *AgeSecretEncryptionEngine) decryptArmoredSecret(body string) (decryptedSecret string, err error) {
	out := &bytes.Buffer{}
	f := strings.NewReader(body)
	armorReader := armor.NewReader(f)

	r, err := age.Decrypt(armorReader, e.identity)
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(out, r); err != nil {
		return "", err
	}

	fmt.Printf("File contents: %q\n", out.Bytes())

	return out.String(), nil
}
