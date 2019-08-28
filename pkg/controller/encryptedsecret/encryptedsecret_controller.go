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
	"errors"
	"fmt"

	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	k8sv1alpha1 "github.com/amaizfinance/secreter/pkg/apis/k8s/v1alpha1"
	"github.com/amaizfinance/secreter/pkg/crypto"
	"github.com/amaizfinance/secreter/pkg/crypto/curve25519"
	"github.com/amaizfinance/secreter/pkg/crypto/gcpkms"
)

const encryptionConfigRefLabel = "encryptionConfigRef"

var (
	errEmptyCipherText = errors.New("ciphertext cannot be empty")
	log                = logf.Log.WithName("controller_encryptedsecret")
	operatorNamespace  string
)

// Add creates a new EncryptedSecret Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileEncryptedSecret{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(
		"encryptedsecret-controller", mgr,
		controller.Options{MaxConcurrentReconciles: 4, Reconciler: r},
	)
	if err != nil {
		return err
	}

	// store the namespace name operator resides in. This will be the namespace
	// where all SecretEncryptionConfig and corresponding Secrets will reside as well.
	if operatorNamespace, err = k8sutil.GetOperatorNamespace(); err != nil {
		return err
	}

	// Watch for changes to primary resource EncryptedSecret
	if err := c.Watch(
		&source.Kind{Type: new(k8sv1alpha1.EncryptedSecret)},
		new(handler.EnqueueRequestForObject),
	); err != nil {
		return err
	}

	return c.Watch(
		&source.Kind{Type: new(corev1.Secret)},
		&handler.EnqueueRequestForOwner{OwnerType: new(k8sv1alpha1.EncryptedSecret), IsController: true},
	)
}

// ReconcileEncryptedSecret reconciles a EncryptedSecret object
type ReconcileEncryptedSecret struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// strict implementation check
var _ reconcile.Reconciler = (*ReconcileEncryptedSecret)(nil)

// Reconcile reads that state of the cluster for a EncryptedSecret object and makes changes based on the state read
// and what is in the EncryptedSecret.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileEncryptedSecret) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	logger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	logger.V(1).Info("Reconciling EncryptedSecret")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Fetch the EncryptedSecret instance
	encrypted := new(k8sv1alpha1.EncryptedSecret)
	if err := r.client.Get(ctx, request.NamespacedName, encrypted); err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to fetch EncryptedSecret: %s", err)
	}

	// read config referenced in the EncryptedSecret
	config := new(k8sv1alpha1.SecretEncryptionConfig)
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: operatorNamespace,
		Name:      encrypted.EncryptionConfigRef.Name,
	}, config); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to fetch SecretEncryptionConfig: %s", err)
	}

	// set proper label referencing a SecretEncryptionConfig.
	if encrypted.GetLabels() == nil {
		encrypted.SetLabels(make(map[string]string))
	}
	encrypted.Labels[encryptionConfigRefLabel] = config.GetName()

	// parse config and compile a suite of decrypters
	decrypterSuite, err := r.initDecrypters(ctx, config)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to initialize decrypters: %s", err)
	}

	// initialize Secret with name, namespace and .metadata.Labels matching those of the Encrypted Secret
	decrypted := &corev1.Secret{Data: make(map[string][]byte), Type: encrypted.Type}
	decrypted.SetName(encrypted.GetName())
	decrypted.SetNamespace(encrypted.GetNamespace())
	decrypted.SetLabels(encrypted.GetLabels())

	failedToDecrypt := make(map[string]string)

	for key, ciphertext := range encrypted.Data {
		if len(ciphertext) < crypto.HeaderSize {
			failedToDecrypt[key] = errEmptyCipherText.Error()
			continue
		}

		for _, decrypter := range decrypterSuite[ciphertext[0]] {
			plaintext, err := decrypter.Decrypt(ciphertext)
			if err != nil {
				failedToDecrypt[key] = err.Error()
				continue
			}
			decrypted.Data[key] = plaintext
			delete(failedToDecrypt, key)
			break
		}
	}

	stateChanged, err := r.createOrUpdateSecret(ctx, decrypted, encrypted)
	if err != nil {
		logger.V(1).Info("state did not change")
		return reconcile.Result{}, err
	}
	if stateChanged {
		logger.Info("Updated Secret")
	}

	return r.updateStatus(ctx, encrypted, failedToDecrypt)
}

// initDecrypters creates a map of Decrypters which can be addressed
// by using the corresponding cipher suite ID and publicKey representation
func (r *ReconcileEncryptedSecret) initDecrypters(
	ctx context.Context, config *k8sv1alpha1.SecretEncryptionConfig,
) (map[byte][]crypto.Decrypter, error) {
	decrypterSuite := make(map[byte][]crypto.Decrypter)

	for _, provider := range config.Providers {
		if provider.Curve25519 != nil && provider.GCPKMS != nil {
			return nil, crypto.ErrMultipleCipherSuites
		}

		switch {
		case provider.GCPKMS != nil:
			for _, selector := range provider.GCPKMS.Credentials {
				credStore := new(corev1.Secret)
				if err := r.client.Get(ctx, types.NamespacedName{
					Namespace: operatorNamespace,
					Name:      selector.SecretKeyRef.Name,
				}, credStore); err != nil {
					return nil, err
				}

				decrypter, err := gcpkms.New(ctx, gcpkms.Options{
					ProjectID:        provider.GCPKMS.ProjectID,
					LocationID:       provider.GCPKMS.LocationID,
					KeyRingID:        provider.GCPKMS.KeyRingID,
					CryptoKeyID:      provider.GCPKMS.CryptoKeyID,
					CryptoKeyVersion: provider.GCPKMS.CryptoKeyVersion,
					Credentials:      credStore.Data[selector.SecretKeyRef.Key],
				})
				if err != nil {
					return nil, err
				}

				decrypterSuite[crypto.GCPKMSXchacha20poly1305] = append(
					decrypterSuite[crypto.GCPKMSXchacha20poly1305], decrypter,
				)
			}
		case provider.Curve25519 != nil:
			// fetch the keystore
			keystore := new(corev1.Secret)
			if err := r.client.Get(ctx, types.NamespacedName{
				Namespace: operatorNamespace,
				Name:      provider.Curve25519.KeyStore.Name,
			}, keystore); err != nil {
				return nil, err
			}

			// TODO: validate keystore before proceeding

			for i := 0; i < len(keystore.Data[k8sv1alpha1.Curve25519keyStorePublicKeysMapKey]); i += curve25519.KeySize {
				decrypterSuite[crypto.Curve25519Xchacha20poly1305] = append(
					decrypterSuite[crypto.Curve25519Xchacha20poly1305],
					curve25519.New(
						keystore.Data[k8sv1alpha1.Curve25519keyStorePublicKeysMapKey][i:i+curve25519.KeySize],
						keystore.Data[k8sv1alpha1.Curve25519keyStorePrivateKeysMapKey][i:i+curve25519.KeySize],
					),
				)
			}
		default:
			return nil, crypto.ErrNoCipherSuites
		}
	}

	return decrypterSuite, nil
}

func (r *ReconcileEncryptedSecret) createOrUpdateSecret(
	ctx context.Context, decrypted *corev1.Secret, encrypted *k8sv1alpha1.EncryptedSecret,
) (stateChanged bool, err error) {
	// get or create the secret
	secret := new(corev1.Secret)
	if err = r.client.Get(ctx, types.NamespacedName{
		Namespace: encrypted.GetNamespace(),
		Name:      encrypted.GetName(),
	}, secret); err != nil {
		// create if not found
		if apierrors.IsNotFound(err) {
			// Set EncryptedSecret instance as the owner and controller
			if err = controllerutil.SetControllerReference(encrypted, decrypted, r.scheme); err != nil {
				return false, fmt.Errorf("failed to set owner for Secret: %s", err)
			}

			if err = r.client.Create(ctx, decrypted); err != nil && !apierrors.IsAlreadyExists(err) {
				return false, fmt.Errorf("failed to create Secret: %s", err)
			}

			return true, nil
		}
		return false, fmt.Errorf("failed to fetch Secret: %s", err)
	}

	if secretUpdateNeeded(secret, decrypted) {
		if err = controllerutil.SetControllerReference(encrypted, secret, r.scheme); err != nil {
			return false, fmt.Errorf("failed to set owner for Secret: %s", err)
		}

		if err = r.client.Update(ctx, secret); err != nil {
			if apierrors.IsConflict(err) {
				// conflicts can be common, consider it part of normal operation
				return true, nil
			}
			return false, fmt.Errorf("failed to update Secret: %s", err)
		}
	}

	return false, nil
}

// updateStatus will requeue request if decrypted is false
func (r *ReconcileEncryptedSecret) updateStatus(ctx context.Context, encrypted *k8sv1alpha1.EncryptedSecret, failedToDecrypt map[string]string) (reconcile.Result, error) {
	decrypted := len(failedToDecrypt) == 0

	if encrypted.Status != nil &&
		encrypted.Status.Decrypted == decrypted &&
		mapStringsEqual(encrypted.Status.FailedToDecrypt, failedToDecrypt) {
		return reconcile.Result{Requeue: !decrypted}, nil
	}

	encrypted.Status = &k8sv1alpha1.EncryptedSecretStatus{
		Decrypted:       decrypted,
		FailedToDecrypt: failedToDecrypt,
	}

	if err := r.client.Status().Update(ctx, encrypted); err != nil {
		if apierrors.IsConflict(err) {
			return reconcile.Result{Requeue: true}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to update Status: %s", err)
	}

	return reconcile.Result{Requeue: !decrypted}, nil
}

func secretUpdateNeeded(got, want *corev1.Secret) (needed bool) {
	if got.Type != want.Type {
		got.Type = want.Type
		needed = true
	}

	if !mapStringsEqual(got.Labels, want.Labels) {
		got.Labels = want.Labels
		needed = true
	}

	if !mapBytesEqual(got.Data, want.Data) {
		got.Data = want.Data
		needed = true
	}

	return
}

func mapStringsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}

	for k, stringWant := range want {
		stringGot, ok := got[k]
		if !(ok && stringGot == stringWant) {
			return false
		}
	}
	return true
}

func mapBytesEqual(got, want map[string][]byte) bool {
	if len(got) != len(want) {
		return false
	}

	for k, bytesWant := range want {
		bytesGot, ok := got[k]
		if !(ok && bytes.Equal(bytesGot, bytesWant)) {
			return false
		}
	}
	return true
}
