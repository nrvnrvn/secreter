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

// Package awskms encrypts the message using AWS KMS.
//
// Only the recipient can decrypt the message using the corresponding private key.
// While the recipient can verify the integrity of the message, it cannot verify
// the identity of the sender.
//
// Sender anonymously encrypts the message using a randomly generated
// data encryption key(DEK). DEK is generated and encrypted via AWS KMS.
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
package awskms

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/amaizfinance/secreter/pkg/crypto"
	"github.com/amaizfinance/secreter/pkg/crypto/xchacha20poly1305"
)

const (
	// KeySize is the size, in bytes, of data encryption keys
	KeySize = 32

	defaultTimeout    = 1 * time.Second
	keySizeOffset     = 2
	headerOffset      = crypto.HeaderSize + keySizeOffset
	cipherTextMinSize = headerOffset + KeySize + xchacha20poly1305.CiphertextMinSize
)

var (
	errCipherTextSize = errors.New("awskms: ciphertext too short")
)

type kmsEncryptDecrypter interface {
	EncryptWithContext(ctx aws.Context, input *kms.EncryptInput, opts ...request.Option) (*kms.EncryptOutput, error)
	DecryptWithContext(ctx aws.Context, input *kms.DecryptInput, opts ...request.Option) (*kms.DecryptOutput, error)
	GenerateDataKeyWithContext(ctx aws.Context, input *kms.GenerateDataKeyInput, opts ...request.Option) (*kms.GenerateDataKeyOutput, error)
}

// Options defines all the parameters needed for encrypting and decrypting via AWS KMS.
type Options struct {
	KeyID           string
	Region          string
	AccessKeyID     string
	SecretAccessKey string

	Timeout time.Duration
}

func (o *Options) applyDefaults() {
	if o.Timeout == 0 {
		o.Timeout = defaultTimeout
	}
}

type encryptDecrypter struct {
	options Options

	client kmsEncryptDecrypter
}

// Encrypt generates an ephemeral data encryption key, encrypts it via KMS,
// encrypts the plaintext and returns the resulting slice
func (e encryptDecrypter) Encrypt(plaintext []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.options.Timeout)
	defer cancel()

	// generate a data encryption key and encrypt it via KMS
	key, err := e.client.GenerateDataKeyWithContext(ctx, &kms.GenerateDataKeyInput{
		KeyId:         aws.String(e.options.KeyID),
		NumberOfBytes: aws.Int64(KeySize),
	})
	if err != nil {
		return nil, fmt.Errorf("error generating data encryption key: %w", err)
	}

	// encrypt plaintext
	ciphertext, err := xchacha20poly1305.Seal(key.Plaintext, plaintext, nil)
	if err != nil {
		return nil, err
	}

	// create header
	header := make([]byte, headerOffset)
	header[0] = crypto.AWSKMSXchacha20poly1305
	binary.LittleEndian.PutUint16(header[crypto.HeaderSize:], uint16(len(key.CiphertextBlob)))

	return crypto.ConcatByteSlices(header, key.CiphertextBlob, ciphertext), nil
}

func (e encryptDecrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < cipherTextMinSize {
		return nil, errCipherTextSize
	}

	encryptedKeyOffset := headerOffset + int(binary.LittleEndian.Uint16(ciphertext[crypto.HeaderSize:]))
	encryptedKey := ciphertext[headerOffset:encryptedKeyOffset]

	ctx, cancel := context.WithTimeout(context.Background(), e.options.Timeout)
	defer cancel()

	key, err := e.client.DecryptWithContext(ctx, &kms.DecryptInput{CiphertextBlob: encryptedKey})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data encryption key: %w", err)
	}

	return xchacha20poly1305.Open(key.Plaintext, ciphertext[encryptedKeyOffset:], nil)
}

// New returns a new instance of the crypto.EncryptDecrypter.
func New(options Options) (crypto.EncryptDecrypter, error) {
	options.applyDefaults()

	client, err := newClient(options)
	if err != nil {
		return nil, fmt.Errorf("error creating aws kms client: %w", err)
	}

	return &encryptDecrypter{
		options: options,
		client:  client,
	}, nil
}

func newClient(options Options) (*kms.KMS, error) {
	config := new(aws.Config)

	if len(options.Region) == 0 {
		parsedARN, err := arn.Parse(options.KeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse KeyID: %w", err)
		}
		options.Region = parsedARN.Region
	}

	if len(options.AccessKeyID) != 0 && len(options.SecretAccessKey) != 0 {
		config.Credentials = credentials.NewStaticCredentials(options.AccessKeyID, options.SecretAccessKey, "")
	}

	config.Region = aws.String(options.Region)
	config.MaxRetries = aws.Int(5)

	s, err := session.NewSession(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session: %w", err)
	}
	return kms.New(s), nil
}
