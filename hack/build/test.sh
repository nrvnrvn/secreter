#!/usr/bin/env bash
# run tests and build all
set -o errexit
set -o nounset
set -o pipefail
set -x

bazel test //...
bazel build //...
