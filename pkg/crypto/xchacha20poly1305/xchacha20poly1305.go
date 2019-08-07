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

// Package xchacha20poly1305 leverages the extended nonce variant
// XChaCha20-Poly1305 of the ChaCha20-Poly1305 AEAD as specified
// in https://tools.ietf.org/html/draft-arciszewski-xchacha-03.
//
// HKDF-BLAKE2B512 is used for key and nonce derivation.
// The main reason why Blake2b was chosen over ubiquitous sha256 as a hash
// function for HKDF is that it has proven to be at least as secure as sha256
// and faster in software implementations.
// Also it is used internally as a primitive for Argon2 password-based KDF.
//
// The implementation deliberately omits explicit passing of a nonce value.
// Instead it relies on uniqueness of the key and additional data.
// At least one of them should be unique per single encryption operation.
// This will guarantee uniqueness of derived key and nonce that will be used for
// XChaCha20-Poly1305. See https://tools.ietf.org/html/rfc7539#section-4 for details.
package xchacha20poly1305

import (
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
)

// CiphertextMinSize is the minimum size of the encrypted message
const CiphertextMinSize = poly1305.TagSize

// Seal encrypts and authenticates plaintext, authenticates the additional data
// and returns the resulting ciphertext.
//
// key is used as an input key material for HKDF-BLAKE2B512.
// additional data is used as a salt.
//
// As described in https://tools.ietf.org/html/rfc5869#section-2.2
// salt is a non-secret random value.
// It is the caller's responsibility to assure the uniqueness of key and/or additional data.
func Seal(key, plaintext, additionalData []byte) ([]byte, error) {
	derivedKey, nonce, err := deriveKeyAndNonce(key, additionalData)
	if err != nil {
		return nil, err
	}
	aead, _ := chacha20poly1305.NewX(derivedKey) // error is always nil

	return aead.Seal(plaintext[:0], nonce, plaintext, additionalData), nil
}

// Open decrypts and authenticates ciphertext, authenticates the additional data and,
// if successful, returns the resulting plaintext.
func Open(key, ciphertext, additionalData []byte) ([]byte, error) {
	derivedKey, nonce, err := deriveKeyAndNonce(key, additionalData)
	if err != nil {
		return nil, err
	}
	aead, _ := chacha20poly1305.NewX(derivedKey) // error is always nil

	return aead.Open(ciphertext[:0], nonce, ciphertext, additionalData)
}

func deriveKeyAndNonce(inputKeyMaterial, salt []byte) ([]byte, []byte, error) {
	if len(inputKeyMaterial) == 0 {
		return nil, nil, errors.New("xchacha20poly1305: key cannot be empty")
	}

	key := make([]byte, chacha20poly1305.KeySize)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)

	for _, buf := range [][]byte{key, nonce} {
		if _, err := io.ReadFull(hkdf.New(newBlake2b512Hash, inputKeyMaterial, salt, nil), buf); err != nil {
			return nil, nil, err
		}
	}

	return key, nonce, nil
}

func newBlake2b512Hash() hash.Hash {
	h, _ := blake2b.New512(nil)
	return h
}
