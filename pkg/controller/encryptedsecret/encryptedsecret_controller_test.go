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
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	// _ "github.com/evanphx/json-patch"

	k8sv1alpha1 "github.com/amaizfinance/secreter/pkg/apis/k8s/v1alpha1"

	"github.com/amaizfinance/secreter/pkg/apis"
	"github.com/amaizfinance/secreter/pkg/crypto"
	"github.com/amaizfinance/secreter/pkg/crypto/curve25519"
)

func TestReconcileEncryptedSecret_Reconcile(t *testing.T) {
	operatorNamespace = "test-secreter"

	nameForEverythingElse := "test"
	testPublicKey := []byte{47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7, 48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116}
	testPrivateKey := make([]byte, 32)
	testKeyStoreCheckSum := "322bad6450e2f12f5c398d1e19e44a23846c6e4a1d5f76ead5b36d4fe6457f9a35c13c4a8fd240bc005c79c590cbc092efcb939de08deb7caab0464fd4d5bede"
	c := curve25519.New(testPublicKey, testPrivateKey)
	testCipherText, err := c.Encrypt([]byte(nameForEverythingElse))
	if err != nil {
		t.Errorf("curve25519.Encrypt error = %v", err)
		return
	}

	// initialize encrypted secret with curve25519 provider, config and keystore
	objs := []runtime.Object{
		&k8sv1alpha1.EncryptedSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameForEverythingElse,
				Namespace: nameForEverythingElse,
			},
			Data: map[string][]byte{
				"errDecrypt":          {0, 1, 2},
				"errLength":           {},
				nameForEverythingElse: testCipherText,
			},
			EncryptionConfigRef: k8sv1alpha1.EncryptionConfigRef{
				Name: nameForEverythingElse,
			},
		},
		&k8sv1alpha1.SecretEncryptionConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameForEverythingElse,
				Namespace: operatorNamespace,
			},
			Providers: []k8sv1alpha1.SecretEncryptionProvider{
				{
					Name: nameForEverythingElse,
					Curve25519: &k8sv1alpha1.Curve25519{
						KeyStore: corev1.LocalObjectReference{
							Name: nameForEverythingElse,
						},
					},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameForEverythingElse,
				Namespace: operatorNamespace,
				Annotations: map[string]string{
					"keyStoreCheckSum": testKeyStoreCheckSum,
				},
			},
			Data: map[string][]byte{
				k8sv1alpha1.Curve25519keyStorePublicKeysMapKey:  testPublicKey,
				k8sv1alpha1.Curve25519keyStorePrivateKeysMapKey: testPrivateKey,
			},
		},
	}

	// Register operator types with the runtime scheme.
	scheme := scheme.Scheme
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Errorf("failed to register core types: %v", err)
		return
	}
	if err := apis.AddToScheme(scheme); err != nil {
		t.Errorf("failed to register amaiz types: %v", err)
		return
	}

	t.Run("normal creation", func(t *testing.T) {
		client := fake.NewFakeClient(objs...)
		r := &ReconcileEncryptedSecret{client: client, scheme: scheme}

		// Create a ReconcileEncryptedSecret object with the scheme and fake client.
		// Mock request to simulate Reconcile() being called on an event for a
		// watched resource .
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      nameForEverythingElse,
				Namespace: nameForEverythingElse,
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
		plaintext, ok := secret.Data[nameForEverythingElse]
		if !ok {
			t.Fatalf("get secret data key: (%v)", ok)
		}
		if !bytes.Equal(plaintext, []byte(nameForEverythingElse)) {
			t.Fatalf("secret data want = %v, got = %v", nameForEverythingElse, string(plaintext))
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

	// /////////////////////////////////////////
	// /////////////////////////////////////////
	// /////////////////////////////////////////
	// /////////////////////////////////////////
	// /////////////////////////////////////////
	// type fields struct {
	// 	client client.Client
	// 	scheme *runtime.Scheme
	// }
	// type args struct {
	// 	request reconcile.Request
	// }
	// tests := []struct {
	// 	name    string
	// 	fields  fields
	// 	args    args
	// 	want    reconcile.Result
	// 	wantErr bool
	// }{
	// 	{
	// 		name:   "not exist",
	// 		fields: fields{client: fake.NewFakeClient(objs...), scheme: scheme},
	// 		args: args{
	// 			request: reconcile.Request{
	// 				NamespacedName: types.NamespacedName{
	// 					Name:      "dummy",
	// 					Namespace: nameForEverythingElse,
	// 				},
	// 			},
	// 		},
	// 		want: reconcile.Result{},
	// 	},
	// 	{
	// 		name:   "normal",
	// 		fields: fields{client: fake.NewFakeClient(objs...), scheme: scheme},
	// 		args: args{
	// 			request: reconcile.Request{
	// 				NamespacedName: types.NamespacedName{
	// 					Name:      nameForEverythingElse,
	// 					Namespace: nameForEverythingElse,
	// 				},
	// 			},
	// 		},
	// 		want: reconcile.Result{Requeue: true},
	// 	},
	// }
	// for _, tt := range tests {
	// 	t.Run(tt.name, func(t *testing.T) {
	// 		r := &ReconcileEncryptedSecret{
	// 			client: tt.fields.client,
	// 			scheme: tt.fields.scheme,
	// 		}
	// 		got, err := r.Reconcile(tt.args.request)
	// 		if (err != nil) != tt.wantErr {
	// 			t.Errorf("ReconcileEncryptedSecret.Reconcile() error = %v, wantErr %v", err, tt.wantErr)
	// 			return
	// 		}
	// 		if !reflect.DeepEqual(got, tt.want) {
	// 			t.Errorf("ReconcileEncryptedSecret.Reconcile() = %v, want %v", got, tt.want)
	// 		}
	// 	})
	// }
}

func TestReconcileEncryptedSecret_initDecrypters(t *testing.T) {
	type fields struct {
		client client.Client
		scheme *runtime.Scheme
	}
	type args struct {
		config *k8sv1alpha1.SecretEncryptionConfig
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[byte][]crypto.Decrypter
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReconcileEncryptedSecret{
				client: tt.fields.client,
				scheme: tt.fields.scheme,
			}
			got, err := r.initDecrypters(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReconcileEncryptedSecret.initDecrypters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReconcileEncryptedSecret.initDecrypters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconcileEncryptedSecret_createOrUpdateSecret(t *testing.T) {
	type fields struct {
		client client.Client
		scheme *runtime.Scheme
	}
	type args struct {
		decrypted *corev1.Secret
		encrypted *k8sv1alpha1.EncryptedSecret
	}
	tests := []struct {
		name             string
		fields           fields
		args             args
		wantStateChanged bool
		wantErr          bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReconcileEncryptedSecret{
				client: tt.fields.client,
				scheme: tt.fields.scheme,
			}
			gotStateChanged, err := r.createOrUpdateSecret(tt.args.decrypted, tt.args.encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReconcileEncryptedSecret.createOrUpdateSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotStateChanged != tt.wantStateChanged {
				t.Errorf("ReconcileEncryptedSecret.createOrUpdateSecret() = %v, want %v", gotStateChanged, tt.wantStateChanged)
			}
		})
	}
}

func TestReconcileEncryptedSecret_updateStatus(t *testing.T) {
	type fields struct {
		client client.Client
		scheme *runtime.Scheme
	}
	type args struct {
		encrypted       *k8sv1alpha1.EncryptedSecret
		failedToDecrypt map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    reconcile.Result
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ReconcileEncryptedSecret{
				client: tt.fields.client,
				scheme: tt.fields.scheme,
			}
			got, err := r.updateStatus(tt.args.encrypted, tt.args.failedToDecrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReconcileEncryptedSecret.updateStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReconcileEncryptedSecret.updateStatus() = %v, want %v", got, tt.want)
			}
		})
	}
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
