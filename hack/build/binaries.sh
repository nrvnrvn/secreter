#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# copied from https://github.com/kubernetes/kubernetes/blob/v1.15.1/hack/lib/golang.sh#L42-L53
readonly KUBE_SUPPORTED_CLIENT_PLATFORMS=(
  linux_amd64
  linux_386
  linux_arm
  linux_arm64
  linux_s390x
  linux_ppc64le
  darwin_amd64
  darwin_386
  windows_amd64
  windows_386
)

# build secreter cli binaries for multiple platforms
for platform in "${KUBE_SUPPORTED_CLIENT_PLATFORMS[@]}"; do
  echo "Building secreter cli for ${platform}"
  bazel build --platforms "@io_bazel_rules_go//go/toolchain:${platform}" //cmd/cli:secreter_pkg
  mv -f bazel-bin/cmd/cli/secreter_{pkg,"${platform}"}.tgz
done
