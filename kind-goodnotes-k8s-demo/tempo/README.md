
## 1st time installation


update `values.yaml` then

```sh

helm template tempo grafana/tempo-distributed \
--namespace monitoring \
--values ./kind-goodnotes-k8s-demo/tempo/values.yaml \
> ./kind-goodnotes-k8s-demo/tempo/manifest.yaml

```

```sh
kustomize build kind-goodnotes-k8s-demo/tempo | kubectl diff -f -

k apply -k kind-goodnotes-k8s-demo/tempo --dry-run=server


k apply -k kind-goodnotes-k8s-demo/tempo
```