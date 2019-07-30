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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	runtimeSerializer "k8s.io/apimachinery/pkg/runtime/serializer"

	k8sv1alpha1 "github.com/amaizfinance/secreter/pkg/apis/k8s/v1alpha1"

	"github.com/amaizfinance/secreter/pkg/apis"
	"github.com/amaizfinance/secreter/pkg/crypto"
	"github.com/amaizfinance/secreter/pkg/crypto/curve25519"
)

const (
	dirFileMode     os.FileMode = 0755
	regularFileMode os.FileMode = 0644
)

// interfaces
type (
	reader interface {
		Read(filename string, recursive bool) ([][]byte, error)
	}

	decoder interface {
		DecodeSecretEncryptionConfig(data []byte) (*k8sv1alpha1.SecretEncryptionConfig, error)
		DecodeEncryptedSecret(data []byte) (*k8sv1alpha1.EncryptedSecret, error)
		DecodeSecrets(objects [][]byte) []*corev1.Secret
	}

	encoder interface {
		Encode(objects []*k8sv1alpha1.EncryptedSecret) error
	}

	// Serializer reads and transforms objects into a serialized outputFormat and back.
	Serializer interface {
		reader
		decoder
		encoder
	}

	encrypter interface {
		Encrypt(secrets []*corev1.Secret) ([]*k8sv1alpha1.EncryptedSecret, error)
	}

	updater interface {
		Update(secret *k8sv1alpha1.EncryptedSecret, data map[string][]byte) error
	}

	// EncryptUpdater encrypts raw secrets and updates encrypted secrets
	EncryptUpdater interface {
		encrypter
		updater
	}
)

type serializer struct {
	outputFormat string
	outputDir    string
	decoder      runtime.Decoder
	encoder      runtime.Encoder
}

// Read reads file input into slice of raw objects.
// If filename is "-" then Read reads from stdin
// If recursive is true Read assumes that filename is a directory.
// Objects
func (s serializer) Read(filename string, recursive bool) (objects [][]byte, err error) {
	switch filename {
	case "-":
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("could not read from Stdin: %s", err)
		}
		objects = append(objects, splitDocuments(data)...)
	default:
		files, err := findAllResourceFiles(filename, recursive)
		if err != nil {
			return nil, fmt.Errorf("find all resources in %s: %s", filename, err)
		}

		for file := range files {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("error reading %s: %s", file, err)
			}
			objects = append(objects, splitDocuments(data)...)
		}
	}

	return objects, nil
}

// DecodeSecretEncryptionConfig decodes byte slice into the DecodeSecretEncryptionConfig instance
func (s serializer) DecodeSecretEncryptionConfig(data []byte) (*k8sv1alpha1.SecretEncryptionConfig, error) {
	config := new(k8sv1alpha1.SecretEncryptionConfig)
	return config, runtime.DecodeInto(s.decoder, data, config)
}

func (s serializer) DecodeEncryptedSecret(data []byte) (*k8sv1alpha1.EncryptedSecret, error) {
	encrypted := new(k8sv1alpha1.EncryptedSecret)
	return encrypted, runtime.DecodeInto(s.decoder, data, encrypted)
}

// DecodeSecrets decodes slice of byte slices into a slice of secrets on the best effort basis.
// In the worst case the result will be an empty slice.
func (s serializer) DecodeSecrets(objects [][]byte) (secrets []*corev1.Secret) {
	for _, raw := range objects {
		obj, err := runtime.Decode(s.decoder, raw)
		if err != nil {
			continue
		}

		switch o := obj.(type) {
		case *corev1.Secret:
			secrets = append(secrets, o)
		case *corev1.List:
			for _, sec := range o.Items {
				secret := new(corev1.Secret)
				if err := runtime.DecodeInto(s.decoder, sec.Raw, secret); err == nil {
					secrets = append(secrets, secret)
				}
			}
		}
	}

	return secrets
}

// Encode encodes the objects and writes them to the specified output
func (s serializer) Encode(objects []*k8sv1alpha1.EncryptedSecret) error {
	if len(objects) == 0 {
		return nil
	}

	// print to stdout if output directory is not present
	if len(s.outputDir) == 0 {
		if len(objects) == 1 {
			encoded, err := runtime.Encode(s.encoder, objects[0])
			if err != nil {
				return fmt.Errorf("encrypt secrets: error encoding EncryptedSecret: %s", err)
			}

			fmt.Println(string(encoded))
			return nil
		}

		// encode objects as a list if the number of objects is more than 1
		list := new(k8sv1alpha1.EncryptedSecretList)
		for _, object := range objects {
			list.Items = append(list.Items, *object)
		}

		encoded, err := runtime.Encode(s.encoder, list)
		if err != nil {
			return fmt.Errorf("encrypt secrets: error encoding Objects: %s", err)
		}

		fmt.Println(string(encoded))
		return nil
	}

	logger := log.New(os.Stderr, "", 0)
	// create a directory tree and write to files appropriately
	for _, object := range objects {
		fullOutputPath := filepath.Join(
			s.outputDir,
			object.GetNamespace(),
			fmt.Sprintf("%s.%s", object.GetName(), s.outputFormat),
		)

		encoded, err := runtime.Encode(s.encoder, object)
		if err != nil {
			return fmt.Errorf("error encoding EncryptedSecret: %s", err)
		}

		if err := os.MkdirAll(filepath.Dir(fullOutputPath), dirFileMode); err != nil {
			return fmt.Errorf("error writing to %s: %s", fullOutputPath, err)
		}

		if err := ioutil.WriteFile(fullOutputPath, encoded, regularFileMode); err != nil {
			return fmt.Errorf("error writing secret to file %s: %s", fullOutputPath, err)
		}
		logger.Printf("wrote %s\n", fullOutputPath)
	}

	return nil
}

func findAllResourceFiles(path string, recursive bool) (map[string]struct{}, error) {
	files := make(map[string]struct{})

	root, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	if !recursive {
		files[path] = struct{}{}
		return files, nil
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		files[path] = struct{}{}
		return nil
	}
	return files, filepath.Walk(root, walkFn)
}

func splitDocuments(data []byte) (objects [][]byte) {
	var (
		jsonPrefix    = []byte("{")
		yamlSeparator = []byte("\n---")
	)

	// check if the byte stream is JSON or not.
	if bytes.HasPrefix(bytes.TrimSpace(data), jsonPrefix) {
		return [][]byte{data}
	}

	// assume the input is YAML
	return bytes.Split(data, yamlSeparator)
}

type encryptUpdater struct {
	encryptionConfigName string
	encrypter            crypto.Encrypter
}

// Encrypt encrypts secrets
func (e encryptUpdater) Encrypt(secrets []*corev1.Secret) (encryptedSecrets []*k8sv1alpha1.EncryptedSecret, err error) {
	for _, secret := range secrets {
		encrypted, err := e.encryptSecret(secret)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt %s/%s: %s", secret.GetNamespace(), secret.GetName(), err)
		}
		encryptedSecrets = append(encryptedSecrets, encrypted)
	}

	return
}

// Update encrypts the data and updates the encrypted secret with the new data
func (e encryptUpdater) Update(encrypted *k8sv1alpha1.EncryptedSecret, data map[string][]byte) (err error) {
	if encrypted.EncryptionConfigRef.Name != e.encryptionConfigName {
		return fmt.Errorf("cannot update encrypted secret %s using config %s", encrypted.GetName(), e.encryptionConfigName)
	}
	if err = e.encryptData(data); err != nil {
		return err
	}
	for key := range data {
		encrypted.Data[key] = data[key]
	}

	return
}

func (e encryptUpdater) encryptSecret(secret *corev1.Secret) (*k8sv1alpha1.EncryptedSecret, error) {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	for key, value := range secret.StringData {
		secret.Data[key] = []byte(value)
	}

	encrypted := &k8sv1alpha1.EncryptedSecret{
		Data: secret.Data,
		Type: secret.Type,
		EncryptionConfigRef: k8sv1alpha1.EncryptionConfigRef{
			Name: e.encryptionConfigName,
		},
	}

	encrypted.SetGroupVersionKind(k8sv1alpha1.SchemeGroupVersion.WithKind("EncryptedSecret"))
	encrypted.SetName(secret.GetName())
	encrypted.SetNamespace(secret.GetNamespace())
	encrypted.SetLabels(secret.GetLabels())

	return encrypted, e.encryptData(secret.Data)
}

// encryptData mutates the data map by encrypting its values
func (e encryptUpdater) encryptData(data map[string][]byte) error {
	for key, plaintext := range data {
		ciphertext, err := e.encrypter.Encrypt(plaintext)
		if err != nil {
			return err
		}
		data[key] = ciphertext
	}
	return nil
}

// New creates an instance of Serializer and EncryptUpdater
func New(configFilename, outputFormat, outputDir string) (Serializer, EncryptUpdater, error) {
	serializer, err := newSerializer(
		outputDir,
		outputFormat,
		k8sv1alpha1.SchemeGroupVersion,
		runtime.NewScheme(),
		// types to register go below
		corev1.AddToScheme,
		apis.AddToScheme,
	)
	if err != nil {
		return nil, nil, err
	}

	objects, err := serializer.Read(configFilename, false)
	if err != nil {
		return nil, nil, err
	}

	config, err := serializer.DecodeSecretEncryptionConfig(objects[0])
	if err != nil {
		return nil, nil, err
	}

	if err := validateConfig(config); err != nil {
		return nil, nil, err
	}

	encryptUpdater, err := newEncryptUpdater(config.GetName(), config.Providers[0], config.Status.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return serializer, encryptUpdater, nil
}

func validateConfig(config *k8sv1alpha1.SecretEncryptionConfig) error {
	if config.GetName() == "" {
		return errors.New("config name cannot be empty")
	}
	if len(config.Providers) < 1 {
		return fmt.Errorf("list of providers is empty %s", config.GetName())
	}
	return nil
}

// newSerializer initializes encoder and decoder for the selected output outputFormat and schema
// Types are registered in schema using their corresponding adder functions.
func newSerializer(
	outputDir string,
	outputFormat string,
	groupVersion schema.GroupVersion,
	scheme *runtime.Scheme,
	adders ...func(s *runtime.Scheme) error,
) (Serializer, error) {
	var (
		s                   = serializer{outputFormat: outputFormat}
		supportedMediaTypes = map[string]string{
			// replace it with runtime.ContentTypeYAML once it lands in operator-sdk dependencies.
			// As of time of writing this comment the first apimachinery release to support it is 1.14.0:
			// https://github.com/kubernetes/apimachinery/blob/kubernetes-1.14.0/pkg/runtime/types.go#L45
			// keep an eye on it.
			"yaml": "application/yaml",
			"json": runtime.ContentTypeJSON,
		}
	)

	if _, ok := supportedMediaTypes[outputFormat]; !ok {
		return nil, fmt.Errorf("wrong output outputFormat \"%s\"", outputFormat)
	}

	// get the absolute representation of outputDir
	if outputDir != "" {
		outputDir, err := filepath.Abs(outputDir)
		if err != nil {
			return nil, fmt.Errorf("error reading output-dir: %s", err)
		}
		s.outputDir = outputDir
	}

	// register all APIs
	for _, adder := range adders {
		if err := adder(scheme); err != nil {
			return nil, fmt.Errorf("failed to add apis to scheme: %s", err)
		}
	}

	// retrieve decoder and encoder for requested scheme and output outputFormat
	codecs := runtimeSerializer.NewCodecFactory(scheme)
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), supportedMediaTypes[outputFormat])
	if !ok {
		return nil, fmt.Errorf("initialize encoders: unsupported mediatype %s", supportedMediaTypes[outputFormat])
	}

	s.decoder = codecs.UniversalDeserializer()

	if info.PrettySerializer != nil {
		s.encoder = codecs.EncoderForVersion(info.PrettySerializer, groupVersion)
	} else {
		s.encoder = codecs.EncoderForVersion(info.Serializer, groupVersion)
	}

	return s, nil
}

// newEncryptUpdater creates an instance of EncryptUpdater using the provider.
func newEncryptUpdater(configName string, provider k8sv1alpha1.SecretEncryptionProvider, publicKey string) (EncryptUpdater, error) {
	switch {
	case provider.GCPKMS != nil && len(provider.GCPKMS.CryptoKeyVersion) > 0:
		// RSA public key here
		// config.Status.PublicKey = "some key"
		// should be something like
		// return gcpkms.New(params go here ...), nil
	case provider.GCPKMS != nil && len(provider.GCPKMS.CryptoKeyVersion) == 0:
		// config.Status.PublicKey=projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID
	default:
	}

	// curve25519
	decodedKey, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	return &encryptUpdater{
		encryptionConfigName: configName,
		encrypter:            curve25519.New(decodedKey, nil),
	}, nil
}

func ParseDataSources(fromFile, fromLiteral []string) (data map[string][]byte, err error) {
	// merge all input data sources into one
	data = make(map[string][]byte)

	if err := parseFileSource(fromFile, data); err != nil {
		return nil, err
	}

	return data, parseLiteralSource(fromLiteral, data)
}

func parseFileSource(fromFile []string, into map[string][]byte) error {
	parsed := make(map[string]string)

	// parse arguments
	for _, source := range fromFile {
		switch numSeparators := strings.Count(source, "="); {
		case numSeparators == 0:
			parsed[filepath.Base(source)] = source
		case numSeparators == 1 && strings.HasPrefix(source, "="):
			return fmt.Errorf("key name for file path %v missing", strings.TrimPrefix(source, "="))
		case numSeparators == 1 && strings.HasSuffix(source, "="):
			return fmt.Errorf("file path for key name %v missing", strings.TrimSuffix(source, "="))
		case numSeparators > 1:
			return errors.New("key names or file paths cannot contain '='")
		default:
			components := strings.Split(source, "=")
			parsed[components[0]] = components[1]
		}
	}

	// read files
	for keyName, source := range parsed {
		if errs := validation.IsConfigMapKey(keyName); len(errs) != 0 {
			return fmt.Errorf("%q is not a valid key name for a Secret: %s", keyName, strings.Join(errs, ";"))
		}
		contents, err := ioutil.ReadFile(source)
		if err != nil {
			return fmt.Errorf("could not read %s: %s", source, err)
		}
		into[keyName] = contents
	}

	return nil
}

func parseLiteralSource(literals []string, into map[string][]byte) error {
	for _, literal := range literals {
		kv := strings.SplitN(literal, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid literal source %s, expected key=value", literal)
		}

		if errs := validation.IsConfigMapKey(kv[0]); len(errs) != 0 {
			return fmt.Errorf("%q is not a valid key name for a Secret: %s", kv[0], strings.Join(errs, ";"))
		}

		into[kv[0]] = []byte(kv[1])
	}

	return nil
}
