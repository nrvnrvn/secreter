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

package xchacha20poly1305

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestSealOpen(t *testing.T) {
	type args struct {
		key, plaintext, ciphertext, additionalData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "empty", wantErr: true},
		{name: "bad ciphertext", args: args{ciphertext: []byte("lol")}, wantErr: true},
		{
			name: "random key",
			args: args{
				key:            generateKey(rand.Reader),
				additionalData: generateKey(rand.Reader),
				plaintext:      []byte("lol"),
			},
			want: []byte("lol"),
		},
		{
			name: "deterministic open",
			args: args{
				key:            []byte("very secret key"),
				additionalData: []byte("such non-secret data"),
				plaintext:      []byte("lol"),
				ciphertext:     []byte{82, 80, 131, 134, 255, 80, 222, 237, 175, 109, 99, 221, 253, 167, 66, 29, 255, 93, 183},
			},
			want: []byte("lol"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.ciphertext == nil {
				ciphertext, err := Seal(tt.args.key, tt.args.plaintext, tt.args.additionalData)
				tt.args.ciphertext = ciphertext
				if (err != nil) != tt.wantErr {
					t.Errorf("Seal() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			got, err := Open(tt.args.key, tt.args.ciphertext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Open() = %v, wantKey %#v", got, tt.want)
			}
		})
	}
}

// test that the cipher works as expected.
func TestSealOpenDeterministic(t *testing.T) {
	type args struct {
		key, plaintext, ciphertext, additionalData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{{
		name: "deterministic",
		args: args{
			key:            []byte("very secret key"),
			additionalData: []byte("such non-secret data"),
			plaintext:      []byte("lol"),
			ciphertext:     []byte{82, 80, 131, 134, 255, 80, 222, 237, 175, 109, 99, 221, 253, 167, 66, 29, 255, 93, 183},
		},
		want: []byte("lol"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(tt.name)
			ciphertext, err := Seal(tt.args.key, tt.args.plaintext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Seal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(ciphertext, tt.args.ciphertext) {
				t.Errorf("\nSeal():\t%v\nwantKey\t%v", ciphertext, tt.args.ciphertext)
				return
			}
			got, err := Open(tt.args.key, tt.args.ciphertext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(tt.args.plaintext)

			if !bytes.Equal(got, tt.want) {
				t.Errorf("Open() = %v, wantKey %#v", got, tt.want)
			}
		})
	}
}

func generateKey(rand io.Reader) []byte {
	key := make([]byte, 1<<6)
	_, _ = io.ReadFull(rand, key)
	return key
}

func BenchmarkDeriveKeyAndNonce(b *testing.B) {
	nonces := make(map[string]struct{}, int(^uint(0)>>1))
	// for those who are adventurous
	// for n := 0; n < int(^uint(0)>>1); n++ {
	for n := 0; n < b.N; n++ {
		_, nonce, err := deriveKeyAndNonce(generateKey(rand.Reader), generateKey(rand.Reader))
		// _, nonce, err := deriveKeyAndNonce(generateKey(rand.Reader), nil)
		if err != nil {
			b.Errorf("deriveKeyAndNonce() error = %v", err)
			return
		}
		h := hex.EncodeToString(nonce)
		if _, ok := nonces[h]; ok {
			b.Error("NONCE REUSE", len(nonces))
			return
		}
		nonces[h] = struct{}{}
		if len(nonces)%1000000 == 0 {
			fmt.Println(len(nonces))
		}
	}
}

func Test_deriveKeyAndNonce(t *testing.T) {
	type args struct {
		inputKeyMaterial []byte
		salt             []byte
	}
	tests := []struct {
		name      string
		args      args
		wantKey   []byte
		wantNonce []byte
		wantErr   bool
	}{
		{name: "empty", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotNonce, err := deriveKeyAndNonce(tt.args.inputKeyMaterial, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("deriveKeyAndNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("deriveKeyAndNonce() gotKey = %v, wantKey %v", gotKey, tt.wantKey)
			}
			if !reflect.DeepEqual(gotNonce, tt.wantNonce) {
				t.Errorf("deriveKeyAndNonce() gotNonce = %v, wantNonce %v", gotNonce, tt.wantNonce)
			}
		})
	}
}
