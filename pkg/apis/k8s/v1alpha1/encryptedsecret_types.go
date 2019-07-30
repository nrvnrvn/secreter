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

// EncryptedSecret is the Schema for the encryptedsecrets API
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Decrypted",type="boolean",JSONPath=".status.decrypted",description="Indicates whether the secret has been successfully decrypted and created"
type EncryptedSecret struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Data contains the secret data. Each key must consist of alphanumeric
	// characters, '-', '_' or '.'. The serialized form of the secret data is a
	// base64 encoded string, representing the arbitrary (possibly non-string)
	// data value here. Described in https://tools.ietf.org/html/rfc4648#section-4
	Data map[string][]byte `json:"data,omitempty"`

	// Used to facilitate programmatic handling of secret data.
	Type corev1.SecretType `json:"type,omitempty"`

	// EncryptionConfigRef holds a reference to the SecretEncryptionConfig
	EncryptionConfigRef EncryptionConfigRef `json:"encryptionConfigRef"`

	Status *EncryptedSecretStatus `json:"status,omitempty"`
}

// EncryptionConfigRef contains information that points to the
// SecretEncryptionConfig being used for encryption/decryption
type EncryptionConfigRef struct {
	// Name is the name of SecretEncryptionConfig being referenced
	Name string `json:"name"`
}

// EncryptedSecretStatus defines the observed state of EncryptedSecret
type EncryptedSecretStatus struct {
	// Decrypted is set to true once the Secret is fully decrypted and created.
	Decrypted bool `json:"decrypted,omitempty"`
	// FailedToDecrypt holds the map of Secret.Data keys which could not be decrypted.
	// Since different keys can be encrypted using different providers,
	// failing to decrypt a single value should not block creating the decrypted
	// Secret resource. Thus every EncryptedSecret is decrypted and created on
	// the best effort basis.
	FailedToDecrypt map[string]string `json:"failedToDecrypt,omitempty"`
}

// EncryptedSecretList contains a list of EncryptedSecrets
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EncryptedSecretList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EncryptedSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EncryptedSecret{}, &EncryptedSecretList{})
}
