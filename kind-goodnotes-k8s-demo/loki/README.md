
```sh
helm template loki grafana/loki \
--namespace monitoring \
--values ./kind-goodnotes-k8s-demo/loki/values.yaml \
> ./kind-goodnotes-k8s-demo/loki/manifest.yaml
```