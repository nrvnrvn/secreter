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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretEncryptionConfig is the Schema for the secretencryptionconfigs API
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status
type SecretEncryptionConfig struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Providers is the list of encryption providers to be used.
	// The first one is the primary provider that will be used for encryption.
	// +kubebuilder:validation:Minimum=1
	Providers []SecretEncryptionProvider `json:"providers"`
	// Status contains the information about public keys of the primary encryption
	// provider (if applicable), observed state of the configuration, etc.
	Status SecretEncryptionStatus `json:"status,omitempty"`
}

// SecretEncryptionProvider defines the desired state of SecretEncryptionConfig.
type SecretEncryptionProvider struct {
	// Name is the name of the provider to be used.
	// +kubebuilder:validation:Pattern=^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
	Name string `json:"name"`
	// Curve25519 defines the configuration of the local Curve25519 provider
	Curve25519 *Curve25519 `json:"curve25519,omitempty"`
	// GCPKMS defines the configuration of the GCP KMS provider
	GCPKMS *GCPKMS `json:"gcpkms,omitempty"`
}

const (
	// Curve25519MaxKeyCount is a maximum number of Curve25519 key pairs.
	// It is limited to the maximum size of the Kubernetes Secret.
	Curve25519MaxKeyCount = corev1.MaxSecretSize / 32

	// Curve25519keyStorePublicKeysMapKey is used to store the public keys in the keystore map
	Curve25519keyStorePublicKeysMapKey = "publicKeys"

	// Curve25519keyStorePrivateKeysMapKey is used to store the primary public key in the keystore map
	Curve25519keyStorePrivateKeysMapKey = "privateKeys"

	// Curve25519keyStoreCheckSumAnnotationKey is the annotation key to store the hash of the keystore
	Curve25519keyStoreCheckSumAnnotationKey = "keyStoreCheckSum"
)

// Curve25519 represents a Curve25519 keyring.
type Curve25519 struct {
	// Reference to a secret containing a key store with Curve25519 key pairs
	KeyStore corev1.LocalObjectReference `json:"keyStore"`
	// Key rotation schedule in Cron format, see https://en.wikipedia.org/wiki/Cron.
	RotationSchedule string `json:"rotationSchedule,omitempty"`
}

// GCPKMS defines all the parameters needed for encryption via GCP KMS.
type GCPKMS struct {
	// GCP project ID, see https://cloud.google.com/kms/docs/object-hierarchy#project
	// +kubebuilder:validation:Pattern=^[a-z]([a-z0-9-]+)?[a-z0-9]?$
	ProjectID string `json:"projectID"`
	// KMS location ID, see https://cloud.google.com/kms/docs/object-hierarchy#location
	// +kubebuilder:validation:Pattern=^[\w-]{1,63}$
	LocationID string `json:"locationID"`
	// Key ring resource ID, see https://cloud.google.com/kms/docs/object-hierarchy#key_ring
	// +kubebuilder:validation:Pattern=^[\w-]{1,63}$
	KeyRingID string `json:"keyRingID"`
	// Key resource ID, see https://cloud.google.com/kms/docs/object-hierarchy#key
	// +kubebuilder:validation:Pattern=^[\w-]{1,63}$
	CryptoKeyID string `json:"cryptoKeyID"`
	// Key version resource ID (needed for asymmetric decryption), see https://cloud.google.com/kms/docs/object-hierarchy#key_version
	// +kubebuilder:validation:Minimum=1
	CryptoKeyVersion int `json:"cryptoKeyVersion,omitempty"`
	// List of references to keys of Secrets containing GCP credential files, see https://cloud.google.com/iam/docs/creating-managing-service-account-keys
	Credentials []SecretKeySelector `json:"credentials"`
}

// SecretKeySelector defines a reference to the specific key in a Secret collocated in the same namespace
type SecretKeySelector struct {
	// Selects a key of a Secret in the same namespace
	SecretKeyRef *corev1.SecretKeySelector `json:"secretKeyRef"`
}

// SecretEncryptionStatus defines the observed state of SecretEncryptionConfig.
type SecretEncryptionStatus struct {
	// PublicKey is the current primary PublicKey used for encryption
	PublicKey string `json:"publicKey,omitempty"`
}

// SecretEncryptionConfigList contains a list of SecretEncryptionConfigs
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SecretEncryptionConfigList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretEncryptionConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretEncryptionConfig{}, &SecretEncryptionConfigList{})
}
