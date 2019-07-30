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

package secretencryptionconfig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	"golang.org/x/crypto/blake2b"
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
	"github.com/amaizfinance/secreter/pkg/crypto/curve25519"
)

var (
	errMultipleProviders          = errors.New("more than one provider configured in a section")
	errCurve25519KeyStoreCheckSum = errors.New("curve25519 keystore is broken")
	log                           = logf.Log.WithName("controller_secretencryptionconfig")
	operatorNamespace             string
)

// Add creates a new SecretEncryptionConfig Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSecretEncryptionConfig{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("secretencryptionconfig-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// store the namespace name operator resides in. This will be the namespace
	// where all SecretEncryptionConfig and corresponding Secrets will reside as well.
	if operatorNamespace, err = k8sutil.GetOperatorNamespace(); err != nil {
		return err
	}

	// Watch for changes to primary resource SecretEncryptionConfig
	if err := c.Watch(
		&source.Kind{Type: new(k8sv1alpha1.SecretEncryptionConfig)},
		new(handler.EnqueueRequestForObject),
	); err != nil {
		return err
	}

	// Watch for changes to secondary resource *v1.Secret
	return c.Watch(
		&source.Kind{Type: new(corev1.Secret)},
		&handler.EnqueueRequestForOwner{OwnerType: new(k8sv1alpha1.SecretEncryptionConfig), IsController: true},
	)
}

// ReconcileSecretEncryptionConfig reconciles a SecretEncryptionConfig object
type ReconcileSecretEncryptionConfig struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// strict implementation check
var _ reconcile.Reconciler = (*ReconcileSecretEncryptionConfig)(nil)

// Reconcile reads that state of the cluster for a SecretEncryptionConfig object and makes changes based on the state read
// and what is in the SecretEncryptionConfig.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSecretEncryptionConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	logger := log.WithValues("Request.Name", request.Name)
	logger.V(1).Info("Reconciling SecretEncryptionConfig")

	// ignore external encryption configs
	if request.Namespace != operatorNamespace {
		return reconcile.Result{}, nil
	}

	// Fetch the SecretEncryptionConfig instance
	config := new(k8sv1alpha1.SecretEncryptionConfig)
	if err := r.client.Get(context.TODO(), types.NamespacedName{Namespace: operatorNamespace, Name: request.Name}, config); err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	logger.V(1).Info("assert that only one provider is set up")
	for _, provider := range config.Providers {
		// assert that only one provider is set up per element
		if provider.Curve25519 != nil && provider.GCPKMS != nil {
			logger.Error(errMultipleProviders, "")
			return reconcile.Result{}, nil
		}
	}

	logger.V(1).Info("check GCP is set up")

	primaryProvider := config.Providers[0]
	if primaryProvider.GCPKMS != nil {
		// TODO: retrieve public asymmetric keys and write to .status.providers[i].gcpkms.publicKey
		return reconcile.Result{}, nil
	}

	// deal with Curve25519
	secret := new(corev1.Secret)
	secretName := primaryProvider.Curve25519.KeyStore.Name

	logger.V(1).Info("fetch secret")
	if err := r.client.Get(context.TODO(), types.NamespacedName{Namespace: operatorNamespace, Name: secretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			publicKey, privateKey, err := curve25519.GenerateKeys(rand.Reader)
			if err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to generate curve25519 keypair: %s", err)
			}

			// store the newly created private and public key-pair
			secret.Data = map[string][]byte{
				k8sv1alpha1.Curve25519keyStorePublicKeysMapKey:  publicKey,
				k8sv1alpha1.Curve25519keyStorePrivateKeysMapKey: privateKey,
			}

			secret.SetName(secretName)
			secret.SetNamespace(operatorNamespace)
			secret.SetLabels(config.GetLabels())
			secret.SetAnnotations(
				map[string]string{
					k8sv1alpha1.Curve25519keyStoreCheckSumAnnotationKey: hashMapStringBytes(secret.Data),
				},
			)

			if err = controllerutil.SetControllerReference(config, secret, r.scheme); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to set owner for Secret: %s", err)
			}

			if err = r.client.Create(context.TODO(), secret); err != nil && !apierrors.IsAlreadyExists(err) {
				return reconcile.Result{}, fmt.Errorf("failed to create Secret: %s", err)
			}
			logger.V(1).Info("created new secret")
			return reconcile.Result{Requeue: true}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to fetch Secret: %s", err)
	}

	// check the integrity of the keystore
	if len(secret.Data[k8sv1alpha1.Curve25519keyStorePublicKeysMapKey])%curve25519.KeySize != 0 ||
		len(secret.Data[k8sv1alpha1.Curve25519keyStorePrivateKeysMapKey])%curve25519.KeySize != 0 ||
		hashMapStringBytes(secret.Data) != secret.Annotations[k8sv1alpha1.Curve25519keyStoreCheckSumAnnotationKey] {
		logger.Error(
			errCurve25519KeyStoreCheckSum, hashMapStringBytes(secret.Data),
			k8sv1alpha1.Curve25519keyStoreCheckSumAnnotationKey,
			secret.Annotations[k8sv1alpha1.Curve25519keyStoreCheckSumAnnotationKey],
		)
		return reconcile.Result{}, nil
	}

	// TODO: create a CronJob for rotating keys

	// write current public key to the configuration status
	switch {
	case primaryProvider.GCPKMS != nil && len(primaryProvider.GCPKMS.CryptoKeyVersion) > 0:
		// RSA public key here
		// config.Status.PublicKey = "--- x509 formatted cert ---"
	case primaryProvider.GCPKMS != nil && len(primaryProvider.GCPKMS.CryptoKeyVersion) == 0:
		// config.Status.PublicKey="projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID"
	case primaryProvider.Curve25519 != nil:
		config.Status.PublicKey = hex.EncodeToString(secret.Data[k8sv1alpha1.Curve25519keyStorePublicKeysMapKey][:curve25519.KeySize])
	}

	if err := r.client.Status().Update(context.TODO(), config); err != nil {
		if apierrors.IsConflict(err) {
			logger.Info("Conflict updating Status, requeue")
			return reconcile.Result{Requeue: true}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to update Status: %s", err)
	}
	logger.Info("Updated Status")
	return reconcile.Result{}, nil
}

// hashMapStringBytes returns the base16-encoded BLAKE2b-512 checksum.
func hashMapStringBytes(m map[string][]byte) string {
	// sort keys before proceeding
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// err will always be nil for nil key
	hash, _ := blake2b.New512(nil)
	for _, key := range keys {
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write(m[key])
	}
	return hex.EncodeToString(hash.Sum(nil))
}
