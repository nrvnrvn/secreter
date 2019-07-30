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

package curve25519

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/amaizfinance/secreter/pkg/crypto"
)

var (
	testMessage = []byte("lol")
	// empty [32]byte slice
	testPrivateKey = make([]byte, KeySize)
	// curve25519.ScalarBaseMult for empty [32]byte slice
	testPublicKey = []byte{
		47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7,
		48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116,
	}
	// testMessage encrypted using the testPublicKey
	testCipherText = []byte{
		0,
		120, 138, 73, 206, 175, 138, 31, 250, 96, 139, 97, 170, 41, 32, 45, 94,
		162, 78, 136, 4, 89, 53, 10, 68, 182, 108, 152, 80, 55, 189, 89, 92,
		73, 63, 197, 84, 182, 84, 150, 228, 163, 3, 222, 127, 107, 134, 154, 58,
		196, 78, 2,
	}
)

func Test_box_Encrypt(t *testing.T) {
	type fields struct {
		publicKey  []byte
		privateKey []byte
		rand       io.Reader
	}
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{name: "empty", wantErr: true},
		{
			name: "short public key",
			args: args{
				plaintext: testMessage,
			},
			fields: fields{
				publicKey: testPublicKey[:5],
			},
			wantErr: true,
		},
		{
			name: "bad random reader",
			fields: fields{
				publicKey: testPublicKey,
				rand:      errReader{},
			},
			wantErr: true,
		},
		{
			name: "normal",
			fields: fields{
				publicKey: testPublicKey,
				rand:      rand.Reader,
			},
			args: args{
				plaintext: testMessage,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := box{
				publicKey:  tt.fields.publicKey,
				privateKey: tt.fields.privateKey,
				rand:       tt.fields.rand,
			}
			got, err := b.Encrypt(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("box.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if l := len(got); l < cipherTextMinSize {
				if !tt.wantErr {
					t.Errorf("box.Encrypt() bad length= %d, want at least %d", l, cipherTextMinSize)
				}
				return
			}
			if (got[0] != crypto.Curve25519Xchacha20poly1305) != tt.wantErr {
				t.Errorf("box.Encrypt() unexpected ciphersuite = %d, want %d", got[0], crypto.Curve25519Xchacha20poly1305)
			}
		})
	}
}

func Test_box_Decrypt(t *testing.T) {
	badCipherText := make([]byte, len(testCipherText))
	copy(badCipherText, testCipherText)
	badCipherText[len(badCipherText)-1] = byte(255 - badCipherText[len(badCipherText)-1])
	type args struct {
		privateKey, publicKey, ciphertext []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{name: "empty", wantErr: errKeySize},
		{
			name: "short privateKey",
			args: args{
				privateKey: testPrivateKey[:5],
			},
			wantErr: errKeySize,
		},
		{
			name: "short ciphertext",
			args: args{
				privateKey: testPrivateKey,
			},
			wantErr: errCipherTextSize,
		},
		{
			name: "deterministic",
			args: args{
				privateKey: testPrivateKey,
				publicKey:  testPublicKey,
				ciphertext: testCipherText,
			},
			want: testMessage,
		},
		{
			name: "bad ciphertext",
			args: args{
				privateKey: testPrivateKey,
				publicKey:  testPublicKey,
				ciphertext: badCipherText,
			},
			// Apparently this is wrong. needs to be changed, see https://dave.cheney.net/2016/04/07/constant-errors
			// Yet it is not clear how to properly handle external errors...
			wantErr: errors.New("chacha20poly1305: message authentication failed"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.args.publicKey, tt.args.privateKey)
			got, err := c.Decrypt(tt.args.ciphertext)
			if (err != nil) && err.Error() != tt.wantErr.Error() {
				t.Errorf("box.Decrypt()\nerror = %v,\nwantErr %v,\nciphertext %v", err, tt.wantErr, tt.args.ciphertext)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("box.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

type errReader struct{}

func (reader errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("bad reader")
}

type nilReader struct{}

func (reader nilReader) Read(p []byte) (n int, err error) {
	return len(p), nil
}

func TestGenerateKeys(t *testing.T) {
	type args struct {
		rand io.Reader
	}
	tests := []struct {
		name    string
		args    args
		wantPk  []byte
		wantSk  []byte
		wantErr bool
	}{
		{
			name:    "err",
			args:    args{errReader{}},
			wantErr: true,
		},
		{
			name: "normal",
			args: args{nilReader{}},
			wantPk: []byte{
				47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7,
				48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116,
			},
			wantSk: make([]byte, KeySize),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPk, gotSk, err := GenerateKeys(tt.args.rand)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPk, tt.wantPk) {
				t.Errorf("GenerateKeys() Public Key\ngot = %v\nwant  %v", gotPk, tt.wantPk)
			}
			if !reflect.DeepEqual(gotSk, tt.wantSk) {
				t.Errorf("GenerateKeys() Private Key\ngot = %v\nwant  %v", gotSk, tt.wantSk)
			}
		})
	}
}
