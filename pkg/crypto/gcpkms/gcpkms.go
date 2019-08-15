// Copyright 2019 The Secreter Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package gcpkms encrypts the message using Google Cloud KMS.
//
// Only the recipient can decrypt the message using the corresponding private key.
// While the recipient can verify the integrity of the message, it cannot verify
// the identity of the sender.
//
// Sender anonymously encrypts the message using a randomly generated
// data encryption key(DEK). DEK is encrypted via GCP KMS.
//
// Both symmetric and asymmetric methods can be applied to encrypting DEKs.
//
// XChaCha20-Poly1305 is used for AEAD.
// Additional data (AD) for the AEAD is the keyName used for encrypting the DEK.
// Additional data is used as salt. Key and nonce for XChaCha20-Poly1305 are generated via HKDF.
//
// Additional data is concatenated with the resulting ciphertext. Encrypted DEK(EDEK) is
// stored alongside the encrypted message and concatenated with the ciphertext.
//
// DEK is generated every time the encryption is called.
// Thus, a new DEK will be generated for the same plaintext every time the
// encryption is called.
//
// Resulting message structure:
//   [Header:1||Size(EDEK):2||EDEK||ciphertext]
//   EDEK - Encrypted data encryption key
package gcpkms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/amaizfinance/secreter/pkg/crypto"
	"github.com/amaizfinance/secreter/pkg/crypto/xchacha20poly1305"
)

const (
	// KeySize is the size, in bytes, of data encryption keys
	KeySize = 32

	keyNameTemplate           = "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s"
	asymmetricKeyNameTemplate = "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%d"
	defaultTimeout            = 1 * time.Second
	keySizeOffset             = 2
	headerOffset              = crypto.HeaderSize + keySizeOffset
	cipherTextMinSize         = headerOffset + KeySize + xchacha20poly1305.CiphertextMinSize
)

var (
	errBadCryptoKeyVersionAlgorithm = errors.New("gcpkms: bad algorithm for asymmetric decryption")
	errCipherTextSize               = errors.New("gcpkms: ciphertext too short")
)

type kmsEncryptDecrypter interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
	AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error)
	GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

// Options defines all the parameters needed for encrypting and decrypting via GCP KMS.
type Options struct {
	ProjectID        string
	LocationID       string
	KeyRingID        string
	CryptoKeyID      string
	CryptoKeyVersion int
	Credentials      []byte
	PublicKey        *rsa.PublicKey
}

// keyName converts options into a key resource ID
func (o Options) keyName() string {
	if o.CryptoKeyVersion > 0 {
		return fmt.Sprintf(asymmetricKeyNameTemplate, o.ProjectID, o.LocationID, o.KeyRingID, o.CryptoKeyID, o.CryptoKeyVersion)
	}
	return fmt.Sprintf(keyNameTemplate, o.ProjectID, o.LocationID, o.KeyRingID, o.CryptoKeyID)
}

type encryptDecrypter struct {
	options Options

	keyName string
	client  kmsEncryptDecrypter
	rand    io.Reader
	timeout time.Duration
}

// Encrypt generates an ephemeral data encryption key, encrypts it via KMS,
// encrypts the plaintext and returns the resulting slice
func (e encryptDecrypter) Encrypt(plaintext []byte) ([]byte, error) {
	// generate a data encryption key
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(e.rand, key); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	// encrypt DEK
	var encryptedKey []byte
	if e.options.CryptoKeyVersion > 0 {
		keyVersion, err := e.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: e.keyName})
		if err != nil {
			return nil, fmt.Errorf("error getting crypto key version: %v", err)
		}

		// choose proper hash function
		var shaHash hash.Hash
		switch keyVersion.GetAlgorithm() {
		case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
			kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
			shaHash = sha256.New()
		case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
			shaHash = sha512.New()
		default:
			return nil, errBadCryptoKeyVersionAlgorithm
		}

		ciphertext, err := rsa.EncryptOAEP(shaHash, rand.Reader, e.options.PublicKey, key, nil)
		if err != nil {
			return nil, fmt.Errorf("error encrypting DEK: %v", err)
		}

		encryptedKey = ciphertext
	} else {
		resp, err := e.client.Encrypt(ctx, &kmspb.EncryptRequest{Name: e.keyName, Plaintext: key})
		if err != nil {
			return nil, fmt.Errorf("error encrypting DEK: %v", err)
		}

		encryptedKey = resp.GetCiphertext()
	}

	// encrypt plaintext
	ciphertext, err := xchacha20poly1305.Seal(key, plaintext, []byte(e.keyName))
	if err != nil {
		return nil, err
	}

	// create header
	header := make([]byte, headerOffset)
	header[0] = crypto.GCPKMSXchacha20poly1305
	binary.LittleEndian.PutUint16(header[crypto.HeaderSize:], uint16(len(encryptedKey)))

	return crypto.ConcatByteSlices(header, encryptedKey, ciphertext), nil
}

func (e encryptDecrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < cipherTextMinSize {
		return nil, errCipherTextSize
	}

	encryptedKeyOffset := headerOffset + int(binary.LittleEndian.Uint16(ciphertext[crypto.HeaderSize:]))
	encryptedKey := ciphertext[headerOffset:encryptedKeyOffset]

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	var key []byte
	if e.options.CryptoKeyVersion > 0 {
		resp, err := e.client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{Name: e.keyName, Ciphertext: encryptedKey})
		if err != nil {
			return nil, fmt.Errorf("error decrypting DEK: %v", err)
		}
		key = resp.GetPlaintext()
	} else {
		resp, err := e.client.Decrypt(ctx, &kmspb.DecryptRequest{Name: e.keyName, Ciphertext: encryptedKey})
		if err != nil {
			return nil, fmt.Errorf("error decrypting DEK: %v", err)
		}
		key = resp.GetPlaintext()
	}

	return xchacha20poly1305.Open(key, ciphertext[encryptedKeyOffset:], []byte(e.keyName))
}

// New returns a new instance of the crypto.EncryptDecrypter. If credentials is nil
// application default credentials will be used for authenticating.
func New(ctx context.Context, options Options) (crypto.EncryptDecrypter, error) {
	client, err := newClient(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("error creating gcp kms client: %v", err)
	}

	return &encryptDecrypter{
		options: options,
		keyName: options.keyName(),
		client:  client,
		rand:    rand.Reader,
		timeout: defaultTimeout,
	}, nil
}

// GetPublicKey fetches and returns RSA public key from GCP KMS in both decoded and encoded forms.
func GetPublicKey(ctx context.Context, options Options) (*rsa.PublicKey, string, error) {
	client, err := newClient(ctx, options)
	if err != nil {
		return nil, "", fmt.Errorf("error creating gcp kms client: %v", err)
	}

	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: options.keyName()})
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch public key: %+v", err)
	}

	key, err := ParsePublicKey(response.GetPem())
	if err != nil {
		return nil, "", err
	}

	return key, response.Pem, nil
}

// ParsePublicKey parses PEM formatted string and
func ParsePublicKey(encoded string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	abstractKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	key, ok := abstractKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}

	return key, nil
}

func newClient(ctx context.Context, options Options) (*kms.KeyManagementClient, error) {
	if options.Credentials != nil {
		return kms.NewKeyManagementClient(ctx, option.WithCredentialsJSON(options.Credentials))
	}

	return kms.NewKeyManagementClient(ctx)
}
