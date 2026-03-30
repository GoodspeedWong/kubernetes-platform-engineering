
```sh
helm template loki grafana/loki \
--namespace monitoring \
--version 6.46.0 \
--values ./kind-goodnotes-k8s-demo/loki/values.yaml \
--values ./kind-goodnotes-k8s-demo/loki/loki-values.override.yaml \
> ./kind-goodnotes-k8s-demo/loki/manifest.yaml
```

## OpenClaw governance note

Loki now carries an explicit retention configuration for the local playground.
The goal is to bound object-store growth in `loki-data` and prevent monitoring storage from exhausting worker-node disks.
