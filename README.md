# Secreter

[![Build Status](https://cloud.drone.io/api/badges/amaizfinance/secreter/status.svg)](https://cloud.drone.io/amaizfinance/secreter)
[![Go Report Card](https://goreportcard.com/badge/github.com/amaizfinance/secreter)](https://goreportcard.com/report/github.com/amaizfinance/secreter)
[![GolangCI](https://golangci.com/badges/github.com/amaizfinance/secreter.svg)](https://golangci.com/r/github.com/amaizfinance/secreter)
[![LICENSE](https://img.shields.io/github/license/amaizfinance/secreter.svg)](https://github.com/amaizfinance/secreter/blob/master/LICENSE)
[![GoDoc](https://godoc.org/github.com/amaizfinance/secreter?status.svg)](https://godoc.org/github.com/amaizfinance/secreter)
[![Releases](https://img.shields.io/github/release/amaizfinance/secreter.svg)](https://github.com/amaizfinance/secreter/releases)

## Project status: alpha

### Cryptography API

Core cryptography API is freezed and is unlikely to be changed. It is open for extension and adding more providers. Thorough independent security audit is badly needed and welcome!

### Kubernetes API and CLI

The basic features have been completed, and while no breaking API changes are currently planned, the API can change in a backwards incompatible way before the project is declared stable.

## Overview

Secreter consists of two components:

* CLI tool that allows to encrypt Kubernetes secrets and store them safely outside of the cluster (VCS, artifacts repository, CI/CD keystore, etc.).
* and Kubernetes operator that decrypts encrypted secrets and creates Kubernetes Secrets.

Secrets encrypted with the Secreter CLI can only be decrypted by the Encrypted Secrets Controller. Controller watches for new and changed `EncryptedSecret` objects and decrypts them on the fly creating `Secret` objects accordingly.

When used in conjunction with [encrypting Secret Data at Rest][encrypting-secret-data-at-rest] it will create a perfect solution where the actual secrets are known in their raw format only to the workloads they are explicitly bound to inside the cluster. Outside of it, `kube-apiserver` would store the secrets encrypted in etcd, `secreter` allows storing encrypted secrets in VCS, CI/CD, et al.

## Features

* Envelope (hybrid) encryption. Every value of the `data` map of a Secret is encrypted using a unique 256-bit key and the key is encrypted with any of the implemented providers. Please refer to the "[Cryptography overview](#cryptography-overview)" for details.
* Diff-friendly. `EncryptedSecret` objects mimic `Secret` objects. Only values of the `data` map get encrypted making it easy to compare two versions of the same encrypted secret or an encrypted secret to the corresponding decrypted secret.
* Separation of concerns. Every encrypted secret is explicitly bound to the secret encryption config. Thus you may group secrets based on their shared access, usage and protection needs and use different secret encryption configs for different groups of secrets. Please refer to the "[Configuring Secreter](#configuring-secreter)" section for details.
* Separation of duties. Secreter CLI is used **only** for encrypting secrets and updating existing encrypted secrets. Operator is used **only** for decrypting secrets. Secret encryption config contains **only** public data required for encryption. Thus `SecretEncryptionConfig` objects can be left visible using RBAC for users involved in encryption of secrets.
* Non-interactive CLI. End user can encrypt a secret or update existing encrypted secret but cannot edit an encrypted secret interactively.
* Multiple providers. You can choose between the built-in curve25519 provider and GCP KMS (more cloud KMS options to be announced soon), define multiple providers and switch between them.
* Multi namespace. By default the controller operates in the entire cluster. But it is possible to run namespaced controllers bound to specific namespaces.
* Separation of duties. Secret encryption config contains only public data required for encryption. Thus using RBAC it can be made available for read access to those who should be able to create or update encrypted secrets.
* Key rotation. Keys can be rotated manually or automatically. Please refer to "[Key rotation](#key-rotation)" for details.

## Getting Started

### Deploying the Secreter operator

1. Create all the necessary resources and deploy the operator:

    ```bash
    kubectl apply -Rf deploy
    ```

2. Verify that the operator is running:

    ```bash
    $ kubectl -n secreter get deployment
    NAME       READY   UP-TO-DATE   AVAILABLE   AGE
    secreter   1/1     1            1           5m
    ```

3. Apply an example Secret Encryption Config:

    ```bash
    kubectl apply -f example/k8s_v1alpha1_secretencryptionconfig_cr.yaml
    ```

### Getting CLI

Official Secreter CLI binaries can be found on the [Releases][releases] page.

### Configuring Secreter

The `SecretEncryptionConfig` CRD is used for configuring Secreter.

#### Important considerations

* Secret Encryption Config must reside in the same namespace as the operator. Configs created in other namespaces will be ignored.
* Secret Encryption Config contains only public data needed for encryption. It is safe to be stored outside of the cluster. You can either store it as a file or fetch dynamically upon encrypting the Secret or updating an Encrypted Secret.
* Config's `.status.publicKey` is used for encryption. Depending on the provider used it will keep either public key or some other form of public data required for encryption.
* Multiple secret encryption configs may be created for better segregation of secrets.

#### Configuration overview

Let's go through the sample `SecretEncryptionConfig`:

```yaml
apiVersion: k8s.amaiz.com/v1alpha1
kind: SecretEncryptionConfig
metadata:
  name: example
  namespace: secreter
providers:
- name: primary
  curve25519:
    keyStore:
      name: my-curve25519-keystore
- name: secondary
  gcpkms:
    projectID: my-kms-project
    locationID: global
    keyRingID: my-keyring
    cryptoKeyID: my-key
    credentials:
    - secretKeyRef:
        name: my-kms-project-creds
        key: creds.json
status:
  publicKey: 2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74
```

`namespace: secreter` matches the namespace where the `secreter` operator has been deployed.

`providers` is an ordered list. Only one provider may be specified per entry.

`status.publicKey` contains public key (or any other public data required for encryption).

In the above config there are two providers configured , named `primary` and `secondary` for simplicity. The first element is a primary provider that is supposed to be used for encryption. `primary` provider's section configures the built-in `curve25519` provider. Name of the `keyStore` is the name of the Kubernetes secret containing public and primary keys. Operator will create the key store if it does not find one. The `secondary` provider contains the `gcpkms` configuration with the reference to the secret with the the service account `credentials`. `credentials` is an ordered list allowing you to seamlessly rotate the credentials when needed.

#### Configuring providers

##### Curve25519

```yaml
<...>
providers:
- name: primary
  curve25519:
    keyStore:
      name: my-curve25519-keystore
```

Operator will create a Kubernetes Secret `my-curve25519-keystore` with the keystore if it does not exist. No configuration other than that is needed.

##### GCP KMS

To add a GCP KMS provider you will need to pass `projectID`, `locationID`, `keyRingID` and `cryptoKeyID`. Those are required for symmetric encryption. In order to use asymmetric encryption be sure to pass `cryptoKeyVersion` as well. Please refer to the [GCP KMS Object hierarchy] for details.

`credentials` hold the [GCP service account credentials]. Once you've created and obtained the credentials json create a Kubernetes Secret in the operator namespace:

```bash
$ kubectl -n secreter create secret generic my-kms-project-creds --from-file creds.json
secret/my-kms-project-creds created
```

Once created you can refer to this secret within the secret encryption config.
`credentials` is a list so that you can refer to multiple service account credentials.

```yaml
<...>
providers:
- name: my-gcp
  gcpkms:
    projectID: my-kms-project
    locationID: global
    keyRingID: my-keyring
    cryptoKeyID: my-key
    cryptoKeyVersion: 1 # optional field, use with asymmetric encryption only.
    credentials:
    - secretKeyRef:
        name: my-kms-project-creds
        key: creds.json
<...>
```

To be able to encrypt secrets using GCP KMS you will need to:

1. install the [Google Cloud SDK].

2. acquire new [Application Default Credentials]:

    ```bash
    gcloud auth application-default login
    ```

#### Planned providers

* `awskms` - support for [AWS KMS] will be added in the nearest future.

#### Key rotation

Regularly rotating keys is a security best practice and there is a number of ways keys can be rotated for the selected Secret encryption config.

Important note: rotating keys will not re-encrypt existing encrypted secrets. Please refer to the "[Encrypting Secrets](#encrypting-secrets)" section for details about how to re-encrypt a secret.

##### Provider rotation

The easiest way to rotate keys is to add a new primary provider:

```yaml
apiVersion: k8s.amaiz.com/v1alpha1
kind: SecretEncryptionConfig
metadata:
  name: example
  namespace: secreter
providers:
- name: new-primary # <- add as the first element to make primary
  curve25519:
    keyStore:
      name: my-new-curve25519-keystore
- name: my-previous-primary-provider
  curve25519:
    keyStore:
      name: my-curve25519-keystore
<...>
```

This will create a new `curve25519` provider named `new-primary`. It will be used for encrypting new data and updating existing encrypted secrets. The second provider, named `my-previous-primary-provider`, will still be used for decryption. This is the recommended way to manually rotate keys for the `curve25519` provider.

##### Curve25519 automatic key rotation

Not implemented. To be announced soon.

##### KMS providers

Some KMS providers (like [Google Cloud KMS][google-cloud-kms-key-rotation]) support automatic key rotation.

Regularly rotating credentials for KMS providers is important as well.

Below is an example flow for rotating GCP KMS credentials.

1. Create a secret in the `secreter` namespace with the newly created credentials file:

    ```bash
    $ kubectl -n secreter create secret generic my-new-creds --from-file creds.json
    secret/my-new-creds created
    ```

2. Add a reference to the newly created secret in your kms provider configuration section and comment out the previous key:

    ```yaml
    apiVersion: k8s.amaiz.com/v1alpha1
    kind: SecretEncryptionConfig
    metadata:
      name: example
      namespace: secreter
    providers:
    - name: primary
      curve25519:
        keyStore:
          name: my-curve25519-keystore
    - name: secondary
      gcpkms:
        projectID: my-kms-project
        locationID: global
        keyRingID: my-keyring
        cryptoKeyID: my-key
        credentials:
        - secretKeyRef:
            name: my-new-creds
            key: creds.json
        # - secretKeyRef:
        #     name: my-kms-project-creds
        #     key: creds.json
    ```

3. Apply the new config and check everything is working as expected.
4. Once you are happy with the new credentials feel free to delete the commented section and the _old_ `my-kms-project-creds` secret:

    ```bash
    $ kubectl delete secret my-kms-project-creds
    secret "my-kms-project-creds" deleted
    ```

### Encrypting Secrets

Secrets can be encrypted in a number of ways. Below you will find a couple of examples.

* Create and encrypt a secret in place and print to stdout. Note that the config is fetched dynamically here:

    ```bash
    $ kubectl create secret generic test --dry-run -o yaml --from-literal lol=woot | secreter encrypt -f- -c <(kubectl -n secreter get secretencryptionconfig example -o yaml)
    apiVersion: k8s.amaiz.com/v1alpha1
    kind: EncryptedSecret
    data:
      lol: <base64-encoded-ciphertext>
    encryptionConfigRef:
      name: example
    metadata:
      creationTimestamp: null
      name: test
    ```

    Note that the name of the encryption config appears as the `encryptionConfigRef`. This reference is used by the operator to find the appropriate config during decryption.

* Encrypt all secrets in the namespace with a single config and apply it back to the cluster:

    ```bash
    kubectl get secret -o yaml -n test | secreter encrypt -f- -c <(kubectl -n secreter get secretencryptionconfig example -o yaml) | kubectl apply -f-
    ```

* Encrypt secrets in bulk from different namespaces using label selector and output to local directory:

    ```bash
    $ kubectl get secret -o yaml --all-namespaces -l some=label | secreter encrypt -f- -c <(kubectl -n secreter get secretencryptionconfig example -o yaml) --output-dir /tmp/encrypted-secrets
    wrote /tmp/encrypted-secrets/first-namespace/some-secret.yaml
    wrote /tmp/encrypted-secrets/another-namespace/some-secret.yaml
    ```

    Note that when encrypted secrets are written to `--output-dir` instead of stdout all namespaced secrets will be written to the directory named after the name of the namespace they belong to. All leading directories will be created on the fly including the `output-dir` itself.

The same techniques can be applied to re-encrypt secrets in case the primary provider has changed or the primary key has been rotated.

Please run `secreter help encrypt` for detailed description and examples.

#### Encrypted secrets decryption

Encrypted secrets have a one-to-one mapping with the corresponding secrets. Treat an `EncryptedSecret` resource as the encrypted form of the `Secret` with the same `name`, `namespace`, `.metadata.labels`, `data` map and `type`.

`EncryptedSecret` does not have a `stringData` map though. If the `Secret` to be encrypted contains this `stringData` map the data it consists of will be encrypted and put into the `data` map.

The `data` map of an `EncryptedSecret` will become the `data` map of the corresponding `Secret`. Encrypted Secret resource will be set as the owner for the decrypted Secret. Values of this map are decrypted on the best effort basis. In case any value fails to get decrypted it will appear in the encrypted secret's `status.failedToDecrypt` map with the reason for failure. Once all the values of the encrypted secret are decrypted its status will reflect this state:

```bash
$ kubectl get encryptedsecrets.k8s.amaiz.com
NAME   DECRYPTED
test   true
```

### Updating Encrypted Secrets

Updating encrypted secrets is similar to the encryption operation but the config passed should match the config used during initial encryption.

Please run `secreter help update` for detailed description and examples.

If it is needed to use different secret encryption config then the recommended way is to encrypt the secret using the desired config and to replace the encrypted secret.

## Uninstalling Secreter operator

The most important thing to bear in mind before deletion is that all of the decrypted secrets are owned by their corresponding `EncryptedSecret` objects. It is recommended to make a backup of the essentially important secrets before proceeding.

1. Scale down the operator:

    ```bash
    kubectl -n secreter scale deployment secreter --replicas 0
    ```

2. Remove the owner references for each secret, e.g.:

    ```bash
    $ kubectl patch secret test --type json -p '[{"op": "remove", "path": "/metadata/ownerReferences"}]'
    secret/test patched
    ```

3. Delete the namespace with the operator:

    ```bash
    $ kubectl delete namespace secreter
    namespace "secreter" deleted
    ```

4. Delete CRDs. Kubernetes will garbage collect all operator-managed resources:

    ```bash
    $ kubectl delete crd secretencryptionconfigs.k8s.amaiz.com encryptedsecrets.k8s.amaiz.com
    customresourcedefinition.apiextensions.k8s.io "secretencryptionconfigs.k8s.amaiz.com" deleted
    customresourcedefinition.apiextensions.k8s.io "encryptedsecrets.k8s.amaiz.com" deleted
    ```

## Design and goals

The main rationale behind starting this project was to create a Kubernetes-native set of tools for managing secrets in a secure and protected fashion. Kubernetes secrets contain base64-encoded byte arrays which makes it impossible to store them along with other resources and manage them in a declarative way. Some investigation showed that there are various approaches to managing secrets in Kubernetes world but all of them are complex multi-step systems implying a lot of manual preparatory work hence prone to introducing fragility and human errors. Many approaches suggest encrypting whole files whereas all is needed is encrypting the `data` map values.

After inspecting the already implemented feature of [encrypting data at rest][encrypting-secret-data-at-rest] it became clear that encrypting secrets on client side together with proper RBAC and encrypting data at rest would create a complete straightforward solution for securing and managing Kubernetes secrets where secrets in their decrypted way are known only to certain workloads (via explicit referencing) or to certain people/service accounts via RBAC.

> TODO: add a diagram showing relations and workflow for better understanding of the concept.

## Cryptography overview

One of the major goals was to avoid _legacy_ crypto algorithms as well as _new shiny_ but lacking good track record and assessment approaches and to keep the number of options to a minimum to make things simple and clear.

All secret data is encrypted using hybrid (or envelope) encryption.

[AEAD] is used for encrypting the data itself. Currently only [XChaCha20-Poly1305][xchacha20-poly1305] is used for AEAD. It is designed to avoid key and nonce reuse. Key and nonce are derived for input key material using HKDF. Please refer to the package documentation for detailed description.

All providers are supposed to use XChaCha20-Poly1305 for encrypting raw secret data.

Providers:

* [Curve25519] is the built-in provider. Curve25519 together with XChaCha20-Poly1305 is designed to generate unique cryptographically strong key and nonce for encrypting secret values. Every value is encrypted with its own unique key. This provider is inspired by Libsodium's [sealed box][libsodium-sealed-box] and NaCl [box][nacl-box]. Please refer to the package documentation for detailed description.
* [GCP KMS symmetric encryption]. 256-bit DEK is randomly generated per value and encrypted using KMS. Ciphertext is concatenated with the enciphered DEK.
* [GCP KMS asymmetric encryption]. 256-bit DEK is randomly generated per value and encrypted using RSA OAEP, public RSA key is stored in `.status.PublicKey` of the secret encryption config. Ciphertext is concatenated with the enciphered DEK.
* [AWS KMS] (planned: PRs are welcome).

[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)
[AWS KMS]: https://aws.amazon.com/kms/
[Application Default Credentials]: https://cloud.google.com/docs/authentication/production
[Curve25519]: https://godoc.org/github.com/amaizfinance/secreter/pkg/crypto/curve25519
[GCP KMS Object hierarchy]: https://cloud.google.com/kms/docs/object-hierarchy
[GCP KMS asymmetric encryption]: https://cloud.google.com/kms/docs/asymmetric-encryption
[GCP KMS symmetric encryption]: https://cloud.google.com/kms/docs/encrypt-decrypt
[GCP service account credentials]: https://cloud.google.com/docs/authentication/production#obtaining_and_providing_service_account_credentials_manually
[Google Cloud SDK]: https://cloud.google.com/sdk/install
[encrypting-secret-data-at-rest]: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data
[google-cloud-kms-key-rotation]: https://cloud.google.com/kms/docs/key-rotation#automatic_rotation
[google-cloud-kms]: https://cloud.google.com/kms/
[libsodium-sealed-box]: https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes
[nacl-box]: https://nacl.cr.yp.to/box.html
[releases]: https://github.com/amaizfinance/secreter/releases
[xchacha20-poly1305]: https://godoc.org/github.com/amaizfinance/secreter/pkg/crypto/xchacha20poly1305
