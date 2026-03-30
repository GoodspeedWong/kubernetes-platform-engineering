
## 1st time installation


update `values.yaml` then

```sh

helm template mimir grafana/mimir-distributed \
--namespace monitoring \
--values ./kind-goodnotes-k8s-demo/mimir/values.yaml \
> ./kind-goodnotes-k8s-demo/mimir/manifest.yaml

```

```sh
kustomize build kind-goodnotes-k8s-demo/mimir | kubectl diff -f -

k apply -k kind-goodnotes-k8s-demo/mimir --dry-run=server

```

## OpenClaw governance note

This stack now carries an explicit Mimir block-retention override for the local playground.
Retaining blocks indefinitely on local-path storage is not acceptable because it can exhaust the KinD worker filesystem and cascade into `apps/postgres` outages.
