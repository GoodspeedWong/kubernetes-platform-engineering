
## Installation
```sh
helm template minio-tenant \
  minio-operator/tenant \
  --namespace monitoring \
  --values kind-goodnotes-k8s-demo/minio-tenant/values.yaml \
  > kind-goodnotes-k8s-demo/minio-tenant/manifest.yaml
```