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

package encryptedsecret

import (
	"bytes"
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	// _ "github.com/evanphx/json-patch"

	k8sv1alpha1 "github.com/amaizfinance/secreter/pkg/apis/k8s/v1alpha1"

	"github.com/amaizfinance/secreter/pkg/apis"
	"github.com/amaizfinance/secreter/pkg/crypto/curve25519"
)

func TestReconcileEncryptedSecret_Reconcile(t *testing.T) {
	// = "test-secreter"
	names := struct {
		operatorNamespace      string
		namespace              string
		secretEncryptionConfig string
		encryptedSecret        string
		secret                 string
		keyStore               string
	}{
		"test-secreter",
		"test-namespace",
		"test-config",
		"test-secret",
		"test-secret",
		"test-keystore",
	}
	// nameForEverythingElse := "test"
	testPublicKey := []byte{47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7, 48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116}
	testPrivateKey := make([]byte, 32)
	testKeyStoreCheckSum := "322bad6450e2f12f5c398d1e19e44a23846c6e4a1d5f76ead5b36d4fe6457f9a35c13c4a8fd240bc005c79c590cbc092efcb939de08deb7caab0464fd4d5bede"
	testPlaintextName, testPlaintext := "test-message", []byte("test-plaintext")
	c := curve25519.New(testPublicKey, testPrivateKey)
	testCipherText, err := c.Encrypt(testPlaintext)
	if err != nil {
		t.Errorf("curve25519.Encrypt error = %v", err)
		return
	}

	// initialize encrypted secret with curve25519 provider, config and keystore
	objs := []runtime.Object{
		&k8sv1alpha1.EncryptedSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      names.encryptedSecret,
				Namespace: names.namespace,
			},
			Data: map[string][]byte{
				"errDecrypt":      {0, 1, 2},
				"errLength":       {},
				testPlaintextName: testCipherText,
			},
			EncryptionConfigRef: k8sv1alpha1.EncryptionConfigRef{
				Name: names.secretEncryptionConfig,
			},
		},

		&k8sv1alpha1.SecretEncryptionConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      names.secretEncryptionConfig,
				Namespace: names.operatorNamespace,
			},
			Providers: []k8sv1alpha1.SecretEncryptionProvider{
				{
					Name: names.keyStore,
					Curve25519: &k8sv1alpha1.Curve25519{
						KeyStore: corev1.LocalObjectReference{
							Name: names.keyStore,
						},
					},
				},
			},
		},

		// keystore
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      names.keyStore,
				Namespace: operatorNamespace,
				Annotations: map[string]string{
					k8sv1alpha1.Curve25519keyStoreCheckSumAnnotationKey: testKeyStoreCheckSum,
				},
			},
			Data: map[string][]byte{
				k8sv1alpha1.Curve25519keyStorePublicKeysMapKey:  testPublicKey,
				k8sv1alpha1.Curve25519keyStorePrivateKeysMapKey: testPrivateKey,
			},
		},
	}

	// Register operator types with the runtime scheme.
	s := scheme.Scheme
	if err := corev1.AddToScheme(s); err != nil {
		t.Errorf("failed to register core types: %v", err)
		return
	}
	if err := apis.AddToScheme(s); err != nil {
		t.Errorf("failed to register amaiz types: %v", err)
		return
	}

	t.Run("normal creation", func(t *testing.T) {
		client := fake.NewFakeClient(objs...)
		r := &ReconcileEncryptedSecret{client: client, scheme: s}

		// Create a ReconcileEncryptedSecret object with the scheme and fake client.
		// Mock request to simulate Reconcile() being called on an event for a
		// watched resource .
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      names.encryptedSecret,
				Namespace: names.namespace,
			},
		}

		result, err := r.Reconcile(req)
		if err != nil {
			t.Fatalf("reconcile: (%v)", err)
		}
		if !result.Requeue {
			t.Error("reconcile did not requeue request as expected")
		}

		secret := new(corev1.Secret)
		if err := client.Get(context.TODO(), req.NamespacedName, secret); err != nil {
			t.Fatalf("get secret: (%v)", err)
		}
		if len(secret.Data) != 1 {
			t.Fatalf("unexpected number of decrypted data = %v", secret.Data)
		}
		plaintext, ok := secret.Data[testPlaintextName]
		if !ok {
			t.Fatalf("get secret data key: (%v)", ok)
		}
		if !bytes.Equal(plaintext, testPlaintext) {
			t.Fatalf("secret data want = %v, got = %v", string(testPlaintext), string(plaintext))
		}

		encrypted := new(k8sv1alpha1.EncryptedSecret)
		if err := client.Get(context.TODO(), req.NamespacedName, encrypted); err != nil {
			t.Fatalf("get EncryptedSecret: (%v)", err)
		}

		// check failed secrets
		if encrypted.Status.Decrypted {
			t.Fatalf("decrypted should be false %#v", encrypted.Status)
		}
	})
}

func Test_secretUpdateNeeded(t *testing.T) {
	type args struct {
		got  *corev1.Secret
		want *corev1.Secret
	}
	tests := []struct {
		name       string
		args       args
		wantNeeded bool
	}{
		{
			name: "empty",
			args: args{
				got:  new(corev1.Secret),
				want: new(corev1.Secret),
			},
		},
		{
			name: "type mismatch",
			args: args{
				got:  &corev1.Secret{Type: "got"},
				want: &corev1.Secret{Type: "want"},
			},
			wantNeeded: true,
		},
		{
			name: "labels mismatch",
			args: args{
				got:  &corev1.Secret{},
				want: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"some": "thing"}}},
			},
			wantNeeded: true,
		},
		{
			name: "data mismatch",
			args: args{
				got:  &corev1.Secret{},
				want: &corev1.Secret{Data: map[string][]byte{"some": []byte("data")}},
			},
			wantNeeded: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotNeeded := secretUpdateNeeded(tt.args.got, tt.args.want); gotNeeded != tt.wantNeeded {
				t.Errorf("secretUpdateNeeded() = %v, want %v", gotNeeded, tt.wantNeeded)
			}
		})
	}
}

func Test_mapStringsEqual(t *testing.T) {
	type args struct {
		got  map[string]string
		want map[string]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "empty", want: true},
		{
			name: "length differ",
			args: args{
				map[string]string{"one": "one", "two": "two"},
				map[string]string{"one": "one"},
			},
			want: false,
		},
		{
			name: "strings differ",
			args: args{
				map[string]string{"one": "two"},
				map[string]string{"one": "one"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapStringsEqual(tt.args.got, tt.args.want); got != tt.want {
				t.Errorf("mapStringsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mapBytesEqual(t *testing.T) {
	type args struct {
		got  map[string][]byte
		want map[string][]byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "empty", want: true},
		{
			name: "length differ",
			args: args{
				map[string][]byte{"one": {}, "two": {}},
				map[string][]byte{"one": {}},
			},
			want: false,
		},
		{
			name: "bytes differ",
			args: args{
				map[string][]byte{"one": {1}},
				map[string][]byte{"one": {2}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapBytesEqual(tt.args.got, tt.args.want); got != tt.want {
				t.Errorf("mapBytesEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
