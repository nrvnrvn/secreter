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

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	k8sv1alpha1 "github.com/amaizfinance/secreter/pkg/apis/k8s/v1alpha1"
	"github.com/amaizfinance/secreter/pkg/cli"
	"github.com/amaizfinance/secreter/version"
)

const (
	encryptCmdDesc = `Encrypt secrets from a file or from stdin using the encryption configuration file.

It is possible to encrypt secrets in bulk using the same configuration.

The first(primary) provider will be used for encryption. Public key from the config's status will be used for encrypting
the data. Format of the public key should match the primary provider.

Examples:
  # Create a secret in place, encrypt it and print to stdout.
  kubectl create secret generic my-secret --from-file=path/to/bar --dry-run -o yaml | secreter encrypt -c config.yaml -f-

  # Read all secrets from specific namespace, encrypt them with a config and save to the output directory.
  # Output directory will be created, along with any necessary parents, if it does not exist.
  kubectl get secret -n default -o yaml | secreter encrypt -c config.yaml -f- --output-dir /path/to/encrypted/secrets`

	updateCmdDesc = `Update encrypted secret from a file or from stdin using the encryption configuration file.

Name of the config should match the name referenced in the encrypted secret. If keys are already present in the encrypted
secret they will be overridden.

When creating a secret based on a file, the key will default to the basename of the file, and the value will default to
the file content. If the basename is an invalid key or you wish to chose your own, you may specify an alternate key.

Examples:
  # Update encrypted secret by passing the literal key-value pair
  secreter update -f my-encrypted-secret.yaml -c config.yaml --from-literal key=super-secret

  # Update encrypted secret by passing the file.
  secreter update -f my-encrypted-secret.yaml -c config.yaml --from-file=ssh-privatekey=~/.ssh/id_rsa

  # Update encrypted secret by passing both file and literal options. Literal key-value pair will take precedence in this case.
  secreter update -f my-encrypted-secret.yaml -c config.yaml --from-file=somekey=~/.ssh/id_rsa --from-literal somekey=super-secret`
)

func rootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "secreter",
		Short: "Encrypt Kubernetes secrets and store them securely them outside of the cluster",

		// SuggestionsMinimumDistance defines minimum levenshtein distance to display suggestions.
		SuggestionsMinimumDistance: 2,
	}
}

func encryptCommand() *cobra.Command {
	var (
		configFilename string
		outputDir      string
		outputFormat   string
		secretFilename string

		recursive bool
	)

	command := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt secrets from a file or from stdin.",
		Long:  encryptCmdDesc,
		Run: func(_ *cobra.Command, _ []string) {
			logger := log.New(os.Stderr, "", 0)
			serializer, encryptUpdater, err := cli.New(configFilename, outputFormat, outputDir)
			if err != nil {
				logger.Fatal(err)
			}

			rawSecrets, err := serializer.Read(secretFilename, recursive)
			if err != nil {
				logger.Fatalf("error reading secrets: %v", err)
			}

			encryptedSecrets, err := encryptUpdater.Encrypt(serializer.DecodeSecrets(rawSecrets))
			if err != nil {
				logger.Fatalf("error encrypting secrets: %v", err)
			}

			if err := serializer.Encode(encryptedSecrets); err != nil {
				logger.Fatalf("error encoding secrets: %v", err)
			}
		},
	}

	flags := command.Flags()

	flags.StringVarP(&configFilename, "config", "c", "",
		"Path to the secret encryption configuration file")
	_ = command.MarkFlagRequired("config")
	flags.StringVarP(&secretFilename, "filename", "f", "",
		"Path to secrets. Pass '-' to use stdin")
	_ = command.MarkFlagRequired("file")

	flags.StringVarP(&outputFormat, "output", "o", "yaml",
		"Output format. One of: yaml or json")
	flags.StringVar(&outputDir, "output-dir", "",
		"Path to directory to write secrets into")

	flags.BoolVarP(&recursive, "recursive", "R", false,
		"Process the directory used in -f, --filename recursively")

	return command
}

func updateCommand() *cobra.Command {
	var (
		configFilename          string
		encryptedSecretFilename string
		outputDir               string
		outputFormat            string

		fromLiteral []string
		fromFile    []string
	)

	command := &cobra.Command{
		Use:   "update",
		Short: "Update encrypted secret based on a file or specified literal value.",
		Long:  updateCmdDesc,
		Run: func(_ *cobra.Command, _ []string) {
			logger := log.New(os.Stderr, "", 0)
			serializer, encryptUpdater, err := cli.New(configFilename, outputFormat, outputDir)
			if err != nil {
				logger.Fatal(err)
			}

			rawEncryptedSecret, err := serializer.Read(encryptedSecretFilename, false)
			if err != nil {
				logger.Fatalf("error reading encrypted secret: %v", err)
			}

			encryptedSecret, err := serializer.DecodeEncryptedSecret(rawEncryptedSecret[0])
			if err != nil {
				logger.Fatalf("error decoding encrypted secret: %v", err)
			}

			data, err := cli.ParseDataSources(fromFile, fromLiteral)
			if err != nil {
				logger.Fatalf("error parsing secret data: %v", err)
			}

			if err := encryptUpdater.Update(encryptedSecret, data); err != nil {
				logger.Fatalf("error updating encrypted secret: %v", err)
			}

			if err := serializer.Encode([]*k8sv1alpha1.EncryptedSecret{encryptedSecret}); err != nil {
				logger.Fatalf("error encoding encrypted secret: %v", err)
			}
		},
	}

	flags := command.Flags()

	flags.StringVarP(&configFilename, "config", "c", "",
		"Path to the secret encryption configuration file. Pass '-' to use stdin")
	_ = command.MarkFlagRequired("config")
	flags.StringVarP(&encryptedSecretFilename, "filename", "f", "",
		"Path to the encrypted secret. Pass '-' to use stdin")
	_ = command.MarkFlagRequired("file")
	flags.StringVarP(&outputFormat, "output", "o", "yaml",
		"Output format. One of: yaml or json")
	flags.StringSliceVar(&fromLiteral, "from-literal", nil,
		"Specify a key and literal value to insert in secret (i.e. mykey=somevalue)")
	flags.StringSliceVar(&fromFile, "from-file", nil,
		`Key files can be specified using their file path, in which case a default name will be given to
them, or optionally with a name and file path, in which case the given name will be used.`)

	return command
}

func versionCmd() *cobra.Command {
	var showFullVersion bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print secreter version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("Version: %s\n", version.Version)
			if showFullVersion {
				fmt.Printf(
					"Build date: %s\nGit commit: %s\nGo version: %s\n",
					version.BuildDate, version.GitCommit, version.GoVersion,
				)
			}
		},
	}

	cmd.Flags().BoolVarP(&showFullVersion, "full", "f", false,
		"If true, prints git commit sha1 and build date in rfc3339 format")
	return cmd
}

func main() {
	root := rootCommand()

	root.AddCommand(
		encryptCommand(),
		updateCommand(),
		versionCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
