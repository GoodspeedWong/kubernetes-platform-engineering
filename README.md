# kubernetes-platform-engineering

A local-first Kubernetes platform engineering workspace built around a four-node [KinD](https://kind.sigs.k8s.io/) cluster and a composable platform baseline for traffic management, observability, storage, GitOps, and performance testing. Contributor workflow and coding standards live in [`AGENTS.md`](AGENTS.md).

This README documents the `kubernetes-platform-engineering` repository against the live cluster context `kind-goodnotes-k8s-demo` as checked on 2026-03-30, so it distinguishes between:

- manifest-backed stacks that are defined in this repository
- additional workloads currently running in the cluster but not fully sourced from this repo

## Platform characteristics

- **Composable platform roots**: the repo is organized so namespaces, traffic, observability, storage, and workload layers can be applied independently with `kubectl apply -k`.
- **Multi-path traffic management**: both NGINX Ingress and Gateway API / Envoy Gateway assets are present, which makes the repo useful for comparing or evolving ingress patterns.
- **Full telemetry baseline**: Prometheus, Grafana, OTEL Collector, Loki, Mimir, and Tempo are all represented as first-class platform components.
- **Local-first, operations-oriented**: the platform runs on KinD, but the repo structure, manifests, and validation commands are aimed at realistic platform operations rather than a throwaway sample.
- **Workload onboarding surface**: the `apps/` layer and supporting scripts provide a baseline path for exposing and testing services on top of the shared platform.

## Platform scope

- **Cluster bootstrap**: `goodnotes-k8s-demo/cluster-config.yaml` defines a KinD control plane plus three workers with host ports `8080 -> 80` and `8443 -> 443`.
- **Workload baselines**: `foo`, `bar`, and `iris-sklearn-api` are deployed in the `apps` namespace and currently route through Gateway API `HTTPRoute` objects.
- **Traffic layers**: the repo contains both an NGINX Ingress controller stack and Envoy Gateway assets (`gateway/` CRDs plus `gateway-controller/` controller manifests).
- **Observability**: Prometheus/Grafana, OTEL Collector, Loki, Mimir, and Tempo all have manifests under `kind-goodnotes-k8s-demo/`.
- **Storage and GitOps**: MinIO operator and tenant resources are present, along with Argo CD manifests.
- **Performance engineering**: a Python ingress load generator lives in `scripts/load-test.py`, and the k6 operator manifests live in `kind-goodnotes-k8s-demo/k6/`.
- **Profiling and diagnosis**: `go-apps/main.go` starts several intentionally hot code paths plus `pprof` on `localhost:6060`.

## Repository layout

```text
.
├── README.md
├── AGENTS.md
├── docs/                        # Issue logs and supporting notes
├── go-apps/                     # Go profiling / stress tooling
├── goodnotes-k8s-demo/          # KinD cluster config
├── iris-sklearn-api/            # Baseline sklearn inference service
├── kind-goodnotes-k8s-demo/
│   ├── apps/                    # baseline workloads
│   ├── argocd/                  # Argo CD manifests
│   ├── coredns/                 # Supporting CoreDNS config snippets
│   ├── crd/                     # Supporting CRDs
│   ├── gateway/                 # Gateway API install assets (not a kustomize root)
│   ├── gateway-controller/      # Envoy Gateway controller manifests
│   ├── ingress-controller/      # NGINX ingress controller manifests
│   ├── k6/                      # k6 operator manifests
│   ├── loki/                    # Loki stack
│   ├── mimir/                   # Mimir stack
│   ├── minio/                   # MinIO resources
│   ├── minio-operator/          # MinIO operator install
│   ├── minio-tenant/            # MinIO tenant config
│   ├── namespaces/              # Shared namespaces
│   ├── otel-collector/          # OTEL agent + gateway
│   ├── prometheus/              # Prometheus Operator + Grafana
│   └── tempo/                   # Tempo distributed tracing
└── scripts/
    └── load-test.py             # Async Host-header load generator
```

## Platform bootstrap

1. Create the KinD cluster.

   ```sh
   kind create cluster --name goodnotes-k8s-demo --config goodnotes-k8s-demo/cluster-config.yaml
   ```

2. Create the shared namespaces.

   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/namespaces
   ```

3. Install Gateway API CRDs and the Envoy Gateway controller if you want north-south routing through `HTTPRoute`.

   ```sh
   kubectl apply -f kind-goodnotes-k8s-demo/gateway/standard-install.yaml
   kubectl apply -f kind-goodnotes-k8s-demo/gateway-controller/manifest.yaml
   ```

4. Install the NGINX ingress controller if you want ingress-backed platform endpoints.

   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/ingress-controller
   ```

5. Install the optional platform stacks you need.

   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/argocd
   kubectl apply -k kind-goodnotes-k8s-demo/k6
   kubectl apply -k kind-goodnotes-k8s-demo/minio-operator
   kubectl apply -k kind-goodnotes-k8s-demo/minio
   kubectl apply -k kind-goodnotes-k8s-demo/mimir
   kubectl apply -k kind-goodnotes-k8s-demo/loki
   kubectl apply -k kind-goodnotes-k8s-demo/tempo
   kubectl apply -k kind-goodnotes-k8s-demo/otel-collector
   kubectl apply -k kind-goodnotes-k8s-demo/prometheus
   ```

6. Deploy the baseline workloads.

   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/apps/foo
   kubectl apply -k kind-goodnotes-k8s-demo/apps/bar
   kubectl apply -k kind-goodnotes-k8s-demo/apps/iris-sklearn-api
   ```

## Current live cluster snapshot

Verified on 2026-03-30 against `kubectl config current-context = kind-goodnotes-k8s-demo`.

- **Nodes**: `goodnotes-k8s-demo-control-plane` plus `worker`, `worker2`, `worker3`, all `Ready`.
- **Namespaces from this repo are present**: `addons`, `apps`, `argocd`, `gateway`, `ingress-nginx`, `k6`, and `monitoring`.
- **Gateway API is active**: `gateway/public-gateway` is `Programmed=True`.
- **Application routes are Gateway API based**:
  - `apps/foo` for `foo.localhost`
  - `apps/bar` for `bar.localhost`
  - `apps/iris-sklearn-api` for `iris.localhost`
- **Monitoring routes are still modeled as Ingress objects**:
  - `monitoring/grafana` for `grafana.localhost`
  - `monitoring/promethues` for `prometheus.localhost`
- **Observed running stacks**:
  - baseline workloads: `foo`, `bar`, `iris-sklearn-api`
  - platform: Argo CD, k6 operator, Envoy Gateway, MinIO operator, Prometheus/Grafana, Loki, Mimir, OTEL, Tempo
  - additional runtime-only workloads in `apps`: `agent-coordinator`, `execution-agent`, `market-data-adapter`, `notification-gateway`, `openclaw-discord-gateway`, `portfolio-watcher`, `trading-console`, `trading-core`, `postgres`, `postgres-exporter`, plus several CronJob-created completed Jobs

The important boundary is that the live cluster has moved beyond the repository's baseline platform definition. This repo still provides the core platform and workload manifests, while the running cluster currently hosts extra OpenClaw/trading services that are only partially reflected here through Grafana dashboards and observability config.

## Access and validation

To inspect the current routing objects:

```sh
kubectl get gateway,httproute,ingress -A
kubectl get pods -A
kubectl get deploy -A
```

If host-based routing is healthy on your machine, the intended local entrypoints are:

- `http://foo.localhost:8080/`
- `http://bar.localhost:8080/`
- `http://iris.localhost:8080/`
- `http://grafana.localhost:8080/`
- `http://prometheus.localhost:8080/`

For direct verification without relying on browser or host DNS, use port-forward:

```sh
kubectl -n monitoring port-forward svc/grafana 3000:80
kubectl -n monitoring port-forward svc/prometheus-k8s 9090:9090
kubectl -n argocd port-forward svc/argocd-server 8081:80
```

On 2026-03-30, `kubectl` confirmed the cluster state above, but `curl -H 'Host: foo.localhost' http://127.0.0.1:8080/healthz` from this shell could not connect and `kubectl get deploy -n ingress-nginx` showed `ingress-nginx-controller` at `0/0`. Treat localhost host-routing as something to re-verify on the host after reconciling the ingress or gateway path.

## Platform validation commands

- Run the async ingress smoke/load test:

  ```sh
  python scripts/load-test.py 20000 50
  ```

- Build and load the iris image into KinD:

  ```sh
  docker build -t iris-sklearn-api:local iris-sklearn-api
  kind load docker-image iris-sklearn-api:local --name goodnotes-k8s-demo
  ```

- Exercise the iris prediction endpoint when host routing is available:

  ```sh
  curl -X POST \
    -H "Host: iris.localhost" \
    -H "Content-Type: application/json" \
    -d '{"features":[5.1,3.5,1.4,0.2]}' \
    http://127.0.0.1:8080/predict
  ```

- Run the Go profiling lab:

  ```sh
  go test ./...
  go run go-apps/main.go
  ```

## Notes

- Not every directory under `kind-goodnotes-k8s-demo/` is a standalone kustomize root. The confirmed roots are `argocd`, `ingress-controller`, `k6`, `loki`, `mimir`, `minio-operator`, `minio`, `namespaces`, `otel-collector`, and `tempo`, plus the three app directories.
- `kind-goodnotes-k8s-demo/gateway/` currently holds install assets such as `standard-install.yaml`; `kind-goodnotes-k8s-demo/gateway-controller/` is applied from the rendered `manifest.yaml`.
- Several repo files are clearly operational scratchpads or generated artifacts. This README intentionally documents the maintained platform surfaces rather than every untracked local file in the worktree.
