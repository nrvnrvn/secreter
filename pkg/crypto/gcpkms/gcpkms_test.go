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

package gcpkms

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var dummyCredentials = []byte(`{
	"type": "service_account",
	"project_id": "project_id",
	"private_key_id": "private_key_id",
	"private_key": "-----BEGIN PRIVATE KEY-----\nc3VjaCBrZXk=\n-----END PRIVATE KEY-----\n",
	"client_email": "client_email",
	"client_id": "client_id",
	"auth_uri": "https://accounts.google.com/o/oauth2/auth",
	"token_uri": "https://oauth2.googleapis.com/token",
	"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
	"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/client_email"
}`)

type fakeClient struct{}

func (f fakeClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	return &kmspb.EncryptResponse{
		Ciphertext: req.Plaintext,
	}, nil
}

func (f fakeClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	return &kmspb.DecryptResponse{
		Plaintext: req.Ciphertext,
	}, nil
}

type errClient struct{}

func (e errClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	return nil, errors.New("")
}

func (e errClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	return nil, errors.New("")
}

func Test_encryptDecrypter_Encrypt(t *testing.T) {
	type fields struct {
		options Options
		keyName string
		client  kmsEncryptDecrypter
		rand    io.Reader
	}
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := encryptDecrypter{
				options: tt.fields.options,
				keyName: tt.fields.keyName,
				client:  tt.fields.client,
				rand:    tt.fields.rand,
			}
			got, err := e.Encrypt(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}
