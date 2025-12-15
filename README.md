# DevOps Kubernetes Playground

A local-first Kubernetes sandbox that provisions a multi-node [KinD](https://kind.sigs.k8s.io/) cluster, deploys sample services, and wires up observability, storage, and load testing. The manifests and scripts here mirror the layouts used in CI so you can iterate locally with the same structure as automation.

## Features

- **KinD topology** – 1 control plane + 3 workers with HTTP/HTTPS ports mapped to the host for ingress testing.
- **Ingress routing** – NGINX Ingress Controller exposes hostname-based routing for demo services (`foo.localhost`, `bar.localhost`, `iris.localhost`).
- **Demo applications** – simple `foo`/`bar` echo deployments and an `iris-sklearn-api` model-serving example with Dockerfile and training script.
- **GitOps ready** – Argo CD manifests and values are included for templating and GitOps rollout trials.
- **Observability** – Prometheus stack (with Grafana dashboards), Mimir, Loki, and an OTEL collector for metrics and logs.
- **Load testing** – k6 configuration and a Python script to generate randomized traffic across ingress hosts.
- **Object storage** – MinIO operator + tenant definitions for S3-compatible buckets inside the cluster.

## Repository layout

```text
.
├── README.md                     # This guide
├── goodnotes-k8s-demo            # KinD cluster configuration (port mappings, node layout)
├── iris-sklearn-api              # Sample ML API (Dockerfile, training + app code)
├── kind-goodnotes-k8s-demo       # Kubernetes manifests and kustomize roots
│   ├── apps/                     # Foo/Bar echo services and iris-sklearn ingress/service/deployment
│   ├── argocd/                   # Argo CD Helm-rendered manifests and kustomization
│   ├── gateway/                  # Example HTTP gateway definition
│   ├── gateway-controller/       # Controller setup for gateway resources
│   ├── ingress-controller/       # NGINX Ingress Controller manifests + ServiceMonitor
│   ├── k6/                       # k6 load testing config
│   ├── loki/                     # Loki manifests for log aggregation
│   ├── mimir/                    # Mimir manifests for long-term metrics storage
│   ├── minio/                    # MinIO buckets and policies
│   ├── minio-operator/           # MinIO operator installation
│   ├── minio-tenant/             # MinIO tenant configuration
│   ├── namespaces/               # Namespace definitions used across the stack
│   ├── otel-collector/           # OpenTelemetry collector deployment
│   └── prometheus/               # Prometheus Operator stack (Grafana, Alertmanager, etc.)
└── scripts
    └── load-test.py              # Async HTTP load generator for foo/bar ingress paths
```

## Getting started locally

1. **Create the KinD cluster**
   ```sh
   kind create cluster --name goodnotes --config goodnotes-k8s-demo/cluster-config.yaml
   ```

2. **Bootstrap namespaces and ingress**
   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/namespaces
   kubectl apply -k kind-goodnotes-k8s-demo/ingress-controller
   ```

3. **Deploy core platform services** (pick and choose based on what you need)
   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/prometheus
   kubectl apply -k kind-goodnotes-k8s-demo/mimir
   kubectl apply -k kind-goodnotes-k8s-demo/loki
   kubectl apply -k kind-goodnotes-k8s-demo/otel-collector
   kubectl apply -k kind-goodnotes-k8s-demo/minio-operator
   kubectl apply -k kind-goodnotes-k8s-demo/minio-tenant
   ```

4. **Deploy sample workloads**
   ```sh
   kubectl apply -k kind-goodnotes-k8s-demo/apps/bar
   kubectl apply -k kind-goodnotes-k8s-demo/apps/foo
   kubectl apply -k kind-goodnotes-k8s-demo/apps/iris-sklearn-api
   ```

5. **Run load testing against ingress**
   ```sh
   python scripts/load-test.py 20000 50
   ```
   The script generates randomized traffic to `foo.localhost` and `bar.localhost` through the ingress controller and prints latency percentiles and error rates.

6. **Access dashboards and services**
   - Prometheus: http://prometheus.localhost:8080
   - Grafana: http://grafana.localhost:8080
   - Iris API: http://iris.localhost/
   - Echo services: http://foo.localhost/ and http://bar.localhost/

## Additional notes

- Every manifest set under `kind-goodnotes-k8s-demo/` is organized as a kustomize root so you can `kubectl apply -k` individual stacks during experimentation.
- The `iris-sklearn-api` directory contains a standalone Docker build path (`docker build -t iris-sklearn-api:local .`) that you can push to a registry referenced by the Kubernetes deployment manifests.
- Example CI artifacts and load-testing PRs from the original demo remain linked for reference in case you want to replicate the automated pipeline locally.
