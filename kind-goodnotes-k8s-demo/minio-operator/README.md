

```sh
helm template minio-operator minio-operator/operator \
--namespace monitoring \
--values ./kind-goodnotes-k8s-demo/minio-operator/values.yaml \
> ./kind-goodnotes-k8s-demo/minio-operator/manifest.yaml

kustomize build kind-goodnotes-k8s-demo/minio-operator | kubectl diff -f -

```