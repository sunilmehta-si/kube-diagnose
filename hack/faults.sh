#!/usr/bin/env bash
# Runs the fault suite: a fresh kind cluster, every scenario in faults/ applied to it, kube-diagnose and k8sgpt (and
# HolmesGPT when HOLMES_MODEL is set) run on each broken namespace, and the outputs scored.
#
# It never uses your kubeconfig: kind writes the cluster's credentials to .faults/kubeconfig, and faultsuite refuses
# any context that is not kind-*. Needs Docker and Go. On linux/amd64 it downloads kind, k8sgpt and HolmesGPT and
# checks each against the checksum in faults/versions.env; elsewhere it uses kind and k8sgpt from PATH.
#
#   hack/faults.sh                          # run and score
#   HOLMES_MODEL=<litellm model> hack/faults.sh   # also HolmesGPT; needs that provider's API key in the environment
#   KEEP_CLUSTER=1 hack/faults.sh           # leave the cluster up afterwards (kind delete cluster --name kd-faults)
set -euo pipefail
cd "$(dirname "$0")/.."
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  [ -n "${!key:-}" ] || export "$key=$value"
done < faults/versions.env

work=.faults
mkdir -p "$work/bin"
platform="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"

fetch() { # url sha256 dest
  curl -fsSL --retry 3 -o "$3" "$1"
  if command -v sha256sum >/dev/null; then
    echo "$2  $3" | sha256sum -c --quiet -
  else
    echo "$2  $3" | shasum -a 256 -c --quiet -
  fi
}

if [ "$platform" = "linux-x86_64" ]; then
  [ -x "$work/bin/kind" ] || { fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" "$KIND_SHA256_LINUX_AMD64" "$work/bin/kind"; chmod +x "$work/bin/kind"; }
  if [ ! -x "$work/bin/k8sgpt" ]; then
    fetch "https://github.com/k8sgpt-ai/k8sgpt/releases/download/$K8SGPT_VERSION/k8sgpt_Linux_x86_64.tar.gz" "$K8SGPT_SHA256_LINUX_AMD64" "$work/k8sgpt.tar.gz"
    tar -xzf "$work/k8sgpt.tar.gz" -C "$work/bin" k8sgpt
  fi
  kind="$work/bin/kind"; k8sgpt="$work/bin/k8sgpt"
else
  echo "faults.sh: $platform has no pinned downloads; using kind and k8sgpt from PATH, unverified" >&2
  kind="$(command -v kind)"; k8sgpt="$(command -v k8sgpt || true)"
fi

holmes_args=()
if [ -n "${HOLMES_MODEL:-}" ]; then
  [ "$platform" = "linux-x86_64" ] || { echo "faults.sh: HolmesGPT is pinned for linux/amd64 only" >&2; exit 1; }
  if [ ! -d "$work/holmes" ]; then
    fetch "https://github.com/HolmesGPT/holmesgpt/releases/download/$HOLMES_VERSION/holmes-linux-amd64-$HOLMES_VERSION.zip" "$HOLMES_SHA256_LINUX_AMD64" "$work/holmes.zip"
    mkdir -p "$work/holmes" && unzip -q "$work/holmes.zip" -d "$work/holmes"
  fi
  holmes_bin="$(find "$work/holmes" -type f -name holmes -perm -u+x | head -n 1)"
  [ -n "$holmes_bin" ] || { echo "faults.sh: no holmes executable in the release zip" >&2; exit 1; }
  holmes_args=(--holmes "$holmes_bin" --holmes-model "$HOLMES_MODEL")
fi

if ! "$kind" get clusters 2>/dev/null | grep -qx kd-faults; then
  "$kind" create cluster --name kd-faults --image "$KIND_NODE_IMAGE" --config hack/kind-faults.yaml --kubeconfig "$work/kubeconfig" --wait 180s
else
  "$kind" get kubeconfig --name kd-faults > "$work/kubeconfig"
fi

# The Gateway API's CRDs go in before the scenarios, some of which create Gateways and routes.
[ -f "$work/gateway-api-$GATEWAY_API_VERSION.yaml" ] || fetch "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml" "$GATEWAY_API_SHA256" "$work/gateway-api-$GATEWAY_API_VERSION.yaml"
kubectl --kubeconfig "$work/kubeconfig" apply --server-side -f "$work/gateway-api-$GATEWAY_API_VERSION.yaml" >/dev/null
kubectl --kubeconfig "$work/kubeconfig" wait --for condition=Established --timeout 120s \
  crd/gatewayclasses.gateway.networking.k8s.io crd/gateways.gateway.networking.k8s.io crd/httproutes.gateway.networking.k8s.io crd/grpcroutes.gateway.networking.k8s.io

make build
gpt_args=()
[ -n "$k8sgpt" ] && gpt_args=(--k8sgpt "$k8sgpt")
# The ${a[@]+"${a[@]}"} form expands an empty array under set -u on every bash, including macOS's 3.2.
go run ./cmd/faultsuite run --kubeconfig "$work/kubeconfig" --out "$work" ${gpt_args[@]+"${gpt_args[@]}"} ${holmes_args[@]+"${holmes_args[@]}"}
go run ./cmd/faultsuite score --results "$work/results" --markdown "$work/results.md" --json "$work/results.json"

if [ -z "${KEEP_CLUSTER:-}" ]; then
  "$kind" delete cluster --name kd-faults
fi
