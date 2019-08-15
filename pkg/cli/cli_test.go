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

package cli

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	k8sv1alpha1 "github.com/amaizfinance/secreter/pkg/apis/k8s/v1alpha1"
	"github.com/amaizfinance/secreter/pkg/crypto/curve25519"
)

const (
	testConfig = `
apiVersion: k8s.amaiz.com/v1alpha1
kind: SecretEncryptionConfig
metadata:
  name: test
providers:
- name: test
  curve25519:
    keystore:
      name: test
status:
  publicKey: "0000000000000000000000000000000000000000000000000000000000000000"
`
	testSecret = `
apiVersion: v1
kind: Secret
metadata:
  name: test1
stringData:
  key1: value
  key2: value
---
something weird # should be ignored
---
apiVersion: v1
kind: Secret
metadata:
  name: test2
stringData:
  key1: value
  key2: value
---
{
    "kind": "Secret",
    "apiVersion": "v1",
    "metadata": {
        "name": "test3"
    },
    "data": {
        "test": "d29vdA=="
    }
}
---
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Secret
  metadata:
    name: test4
  stringData:
    key1: value
    key2: value
- apiVersion: v1
  kind: Secret
  metadata:
    name: test5
  stringData:
    key1: value
    key2: value
`
	testEncryptedSecret = `
apiVersion: k8s.amaiz.com/v1alpha1
kind: EncryptedSecret
metadata:
  name: test1
data:
  test: d29vdA==
encryptionConfigRef:
  name: test`
)

var (
	testDir                          string
	testConfigPath                   string
	testSecretPath                   string
	testEncryptedSecretPath          string
	expectedEncryptedSecretFileNames = []string{
		"test1", "test2", "test3", "test4", "test5",
	}
)

func Test_serializer_Read(t *testing.T) {
	type args struct {
		filename  string
		recursive bool
	}
	tests := []struct {
		name        string
		s           serializer
		args        args
		wantObjects [][]byte
		wantErr     bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotObjects, err := tt.s.Read(tt.args.filename, tt.args.recursive)
			if (err != nil) != tt.wantErr {
				t.Errorf("serializer.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotObjects, tt.wantObjects) {
				t.Errorf("serializer.Read() = %v, want %v", gotObjects, tt.wantObjects)
			}
		})
	}
}

func Test_serializer_DecodeSecretEncryptionConfig(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		s       serializer
		args    args
		want    *k8sv1alpha1.SecretEncryptionConfig
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.DecodeSecretEncryptionConfig(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("serializer.DecodeSecretEncryptionConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("serializer.DecodeSecretEncryptionConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_serializer_DecodeSecrets(t *testing.T) {
	type args struct {
		objects [][]byte
	}
	tests := []struct {
		name        string
		s           serializer
		args        args
		wantSecrets []*corev1.Secret
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSecrets := tt.s.DecodeSecrets(tt.args.objects); !reflect.DeepEqual(gotSecrets, tt.wantSecrets) {
				t.Errorf("serializer.DecodeSecrets() = %v, want %v", gotSecrets, tt.wantSecrets)
			}
		})
	}
}

func Test_serializer_DecodeEncryptedSecret(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		s       serializer
		args    args
		want    *k8sv1alpha1.EncryptedSecret
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.DecodeEncryptedSecret(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("serializer.DecodeEncryptedSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("serializer.DecodeEncryptedSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_serializer_Encode(t *testing.T) {
	type args struct {
		objects []*k8sv1alpha1.EncryptedSecret
	}
	tests := []struct {
		name    string
		s       serializer
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.Encode(tt.args.objects); (err != nil) != tt.wantErr {
				t.Errorf("serializer.Encode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_findAllResourceFiles(t *testing.T) {
	type args struct {
		path      string
		recursive bool
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]struct{}
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findAllResourceFiles(tt.args.path, tt.args.recursive)
			if (err != nil) != tt.wantErr {
				t.Errorf("findAllResourceFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findAllResourceFiles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_splitDocuments(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name        string
		args        args
		wantObjects [][]byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotObjects := splitDocuments(tt.args.data); !reflect.DeepEqual(gotObjects, tt.wantObjects) {
				t.Errorf("splitDocuments() = %v, want %v", gotObjects, tt.wantObjects)
			}
		})
	}
}

func Test_encryptUpdater_Encrypt(t *testing.T) {
	type args struct {
		secrets []*corev1.Secret
	}
	tests := []struct {
		name                 string
		e                    encryptUpdater
		args                 args
		wantEncryptedSecrets []*k8sv1alpha1.EncryptedSecret
		wantErr              bool
	}{
		{name: "empty"},
		{
			name: "error encrypting",
			e: encryptUpdater{
				encryptionConfigName: "test",
				encrypter:            curve25519.New(make([]byte, 5), nil),
				// publicKey:            make([]byte, 5), // any number except 32 will work
			},
			args: args{
				secrets: []*corev1.Secret{
					{
						StringData: map[string]string{
							"test": "data",
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEncryptedSecrets, err := tt.e.Encrypt(tt.args.secrets)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptUpdater.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotEncryptedSecrets, tt.wantEncryptedSecrets) {
				t.Errorf("encryptUpdater.Encrypt() = %v, want %v", gotEncryptedSecrets, tt.wantEncryptedSecrets)
			}
		})
	}
}

func Test_encryptUpdater_Update(t *testing.T) {
	type args struct {
		encrypted *k8sv1alpha1.EncryptedSecret
		data      map[string][]byte
	}
	tests := []struct {
		name    string
		e       encryptUpdater
		args    args
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				encrypted: new(k8sv1alpha1.EncryptedSecret),
			},
		},
		{
			name: "error encrypting",
			e: encryptUpdater{
				encryptionConfigName: "test",
				encrypter:            curve25519.New(make([]byte, 5), nil),
				// publicKey:            make([]byte, 5), // any number except 32 will work
			},
			args: args{
				encrypted: new(k8sv1alpha1.EncryptedSecret),
				data: map[string][]byte{
					"test": make([]byte, 5),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.e.Update(tt.args.encrypted, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("encryptUpdater.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	const (
		badPublicKey = `
apiVersion: k8s.amaiz.com/v1alpha1
kind: SecretEncryptionConfig
metadata:
  name: test
providers:
- name: test
status:
  publicKey: "bad"`
		badYaml = `apiVersion: k8s.amaiz.com/v1alpha1
kind: SecretEncryptionConfigERR`
	)

	var badPubKeyConfigPath = filepath.Join(testDir, "test_new_bad_public_key_config.yaml")
	if err := ioutil.WriteFile(badPubKeyConfigPath, []byte(badPublicKey), regularFileMode); err != nil {
		t.Error(err)
		return
	}
	var badYamlConfigPath = filepath.Join(testDir, "test_new_bad_yaml_config.yaml")
	if err := ioutil.WriteFile(badYamlConfigPath, []byte(badYaml), regularFileMode); err != nil {
		t.Error(err)
		return
	}

	type args struct {
		configFilename, outputFormat, outputDir string
	}
	tests := []struct {
		name    string
		args    args
		want    Serializer
		want1   EncryptUpdater
		wantErr bool
	}{
		{
			name: "bad serializer",
			args: args{
				outputFormat: "bad",
			},
			wantErr: true,
		},
		{
			name: "bad config path",
			args: args{
				configFilename: "/non-existent",
				outputFormat:   "yaml",
			},
			wantErr: true,
		},
		{
			name: "stdin empty",
			args: args{
				configFilename: "-",
				outputFormat:   "yaml",
			},
			wantErr: true,
		},
		{
			name: "bad config - public key",
			args: args{
				configFilename: badPubKeyConfigPath,
				outputFormat:   "yaml",
			},
			wantErr: true,
		},
		{
			name: "bad config - decode err",
			args: args{
				configFilename: badYamlConfigPath,
				outputFormat:   "yaml",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := New(tt.args.configFilename, tt.args.outputFormat, tt.args.outputDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("New() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_validateConfig(t *testing.T) {
	type args struct {
		config *k8sv1alpha1.SecretEncryptionConfig
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "no name",
			args: args{
				config: new(k8sv1alpha1.SecretEncryptionConfig),
			},
			wantErr: true,
		},
		{
			name: "no providers",
			args: args{
				config: &k8sv1alpha1.SecretEncryptionConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConfig(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_newSerializer(t *testing.T) {
	type args struct {
		outputDir    string
		outputFormat string
		groupVersion schema.GroupVersion
		scheme       *runtime.Scheme
		adders       []func(s *runtime.Scheme) error
	}
	tests := []struct {
		name    string
		args    args
		want    Serializer
		wantErr bool
	}{
		{
			name: "wrong output outputFormat",
			args: args{
				outputFormat: "err",
			},
			wantErr: true,
		},
		{
			name: "error registering",
			args: args{
				outputFormat: "json",
				adders: []func(s *runtime.Scheme) error{
					func(s *runtime.Scheme) error {
						return errors.New("gotcha")
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newSerializer(tt.args.outputDir, tt.args.outputFormat, tt.args.groupVersion, tt.args.scheme, tt.args.adders...)
			if (err != nil) != tt.wantErr {
				t.Errorf("newSerializer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newSerializer() = %#v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newEncryptUpdater(t *testing.T) {
	type args struct {
		configName string
		provider   k8sv1alpha1.SecretEncryptionProvider
		publicKey  string
	}
	tests := []struct {
		name    string
		args    args
		want    EncryptUpdater
		wantErr bool
	}{
		{
			name: "error decode hex string",
			args: args{
				provider:  k8sv1alpha1.SecretEncryptionProvider{},
				publicKey: "err",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newEncryptUpdater(tt.args.configName, tt.args.provider, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("newEncryptUpdater() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newEncryptUpdater() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDataSources(t *testing.T) {
	type args struct {
		fromFile    []string
		fromLiteral []string
	}
	tests := []struct {
		name     string
		args     args
		wantData map[string][]byte
		wantErr  bool
	}{
		{name: "empty", wantData: make(map[string][]byte)},
		{
			name: "fileSource fail prefix",
			args: args{
				fromFile: []string{
					"=",
				},
			},
			wantErr: true,
		},
		{
			name: "literalSource fail not a key-value pair",
			args: args{
				fromLiteral: []string{
					"err",
				},
			},
			wantData: make(map[string][]byte),
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, err := ParseDataSources(tt.args.fromFile, tt.args.fromLiteral)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDataSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("ParseDataSources() = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}

func Test_parseFileSource(t *testing.T) {
	testFromFilePath := filepath.Join(testDir, "test")
	if err := ioutil.WriteFile(testFromFilePath, []byte("something"), regularFileMode); err != nil {
		t.Error(err)
		return
	}

	type args struct {
		fromFile []string
		into     map[string][]byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "empty"},
		{
			name: "fail prefix",
			args: args{
				fromFile: []string{
					"=",
				},
			},
			wantErr: true,
		},
		{
			name: "fail suffix",
			args: args{
				fromFile: []string{
					"keyName=",
				},
			},
			wantErr: true,
		},
		{
			name: "fail too much equals",
			args: args{
				fromFile: []string{
					"keyName=lol=woot",
				},
			},
			wantErr: true,
		},
		{
			name: "normal file",
			args: args{
				fromFile: []string{
					"keyName=" + testFromFilePath,
					testFromFilePath,
				},
				into: make(map[string][]byte),
			},
		},
		{
			name: "invalid keyName",
			args: args{
				fromFile: []string{
					"*&^&*=" + testFromFilePath,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid file",
			args: args{
				fromFile: []string{
					"/dev/invalid",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseFileSource(tt.args.fromFile, tt.args.into); (err != nil) != tt.wantErr {
				t.Errorf("parseFileSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseLiteralSource(t *testing.T) {
	type args struct {
		literals []string
		into     map[string][]byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "empty"},
		{
			name: "not a key-value pair",
			args: args{
				literals: []string{
					"err",
				},
			},
			wantErr: true,
		},
		{
			name: "empty keyName",
			args: args{
				literals: []string{
					"=errName",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid keyName",
			args: args{
				literals: []string{
					"k*y=errName",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseLiteralSource(tt.args.literals, tt.args.into); (err != nil) != tt.wantErr {
				t.Errorf("parseLiteralSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFullCycleEncrypt(t *testing.T) {
	var testOutputDir = filepath.Join(testDir, "output")
	type args struct {
		configFilename, outputFormat, outputDir string
		secretFilename                          string
		recursive                               bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "yaml output to dir",
			args: args{
				configFilename: testConfigPath,
				outputFormat:   "yaml",
				outputDir:      testOutputDir,
				secretFilename: testSecretPath,
			},
		},
		{
			name: "json output to dir",
			args: args{
				configFilename: testConfigPath,
				outputFormat:   "json",
				outputDir:      testOutputDir,
				secretFilename: testSecretPath,
			},
		},
		{
			name: "json output to dir read recursive",
			args: args{
				configFilename: testConfigPath,
				outputFormat:   "json",
				outputDir:      testOutputDir,
				secretFilename: testDir,
				recursive:      true,
			},
		},
		{
			name: "json output to stdout read recursive",
			args: args{
				configFilename: testConfigPath,
				outputFormat:   "json",
				// outputDir:      testOutputDir,
				secretFilename: testDir,
				recursive:      true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, e, err := New(tt.args.configFilename, tt.args.outputFormat, tt.args.outputDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			rawSecrets, err := s.Read(tt.args.secretFilename, tt.args.recursive)
			if (err != nil) != tt.wantErr {
				t.Errorf("Serializer.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			encryptedSecrets, err := e.Encrypt(s.DecodeSecrets(rawSecrets))
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptUpdater.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// var objects []runtime.Object
			// for i := range encryptedSecrets {
			// 	objects = append(objects, encryptedSecrets[i])
			// }

			if err := s.Encode(encryptedSecrets); (err != nil) != tt.wantErr {
				t.Errorf("Serializer.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			files, _ := ioutil.ReadDir(testOutputDir)
			var got, want []string
			for _, file := range files {
				if strings.TrimLeft(filepath.Ext(file.Name()), ".") == tt.args.outputFormat {
					got = append(got, file.Name())
				}
			}
			sort.Strings(got)
			for _, name := range expectedEncryptedSecretFileNames {
				want = append(want, fmt.Sprintf("%s.%s", name, tt.args.outputFormat))
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("not all secrets were encrypted %s %v, want = %v", tt.args.outputDir, got, want)
				return
			}
		})
	}
}

func TestFullCycleUpdate(t *testing.T) {
	type args struct {
		configFilename, outputFormat, outputDir string
		encryptedSecretFilename                 string
		recursive                               bool
		fromFile, fromLiteral                   []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "yaml output",
			args: args{
				configFilename:          testConfigPath,
				outputFormat:            "yaml",
				encryptedSecretFilename: testEncryptedSecretPath,
				fromLiteral: []string{
					"lol=woot",
					"test=value",
				},
			},
		},
		{
			name: "json output",
			args: args{
				configFilename:          testConfigPath,
				outputFormat:            "json",
				encryptedSecretFilename: testEncryptedSecretPath,
				fromLiteral: []string{
					"lol=woot",
					"test=value",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, e, err := New(tt.args.configFilename, tt.args.outputFormat, tt.args.outputDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			rawEncryptedSecrets, err := s.Read(tt.args.encryptedSecretFilename, tt.args.recursive)
			if (err != nil) != tt.wantErr {
				t.Errorf("Serializer.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			encryptedSecret, err := s.DecodeEncryptedSecret(rawEncryptedSecrets[0])
			if (err != nil) != tt.wantErr {
				t.Errorf("Serializer.DecodeEncryptedSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			data, err := ParseDataSources(tt.args.fromFile, tt.args.fromLiteral)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDataSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := e.Update(encryptedSecret, data); (err != nil) != tt.wantErr {
				t.Errorf("EncryptUpdater.Update() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := s.Encode([]*k8sv1alpha1.EncryptedSecret{encryptedSecret}); err != nil {
				t.Errorf("Serializer.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestMain(m *testing.M) {
	td, err := ioutil.TempDir("", "encrypt_test")
	if err != nil {
		log.Fatal(err)
	}
	testDir = td
	defer os.RemoveAll(testDir)

	testConfigPath = filepath.Join(testDir, "config.yaml")
	if err := ioutil.WriteFile(testConfigPath, []byte(testConfig), regularFileMode); err != nil {
		log.Fatal(err)
	}

	testSecretPath = filepath.Join(testDir, "secret.yaml")
	if err := ioutil.WriteFile(testSecretPath, []byte(testSecret), regularFileMode); err != nil {
		log.Fatal(err)
	}

	testEncryptedSecretPath = filepath.Join(testDir, "encryptedSecret.yaml")
	if err := ioutil.WriteFile(testEncryptedSecretPath, []byte(testEncryptedSecret), regularFileMode); err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}
