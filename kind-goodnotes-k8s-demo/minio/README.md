## Installation

```sh

helm repo add minio https://charts.min.io/
helm repo update


export MINIO_ROOT_USER=""
export MINIO_ROOT_PASSWORD=""

kubectl -n monitoring create secret generic minio-creds \
  --from-literal=rootUser=$MINIO_ROOT_USER \
  --from-literal=rootPassword=$MINIO_ROOT_PASSWORD


helm template minio bitnami/minio \
--namespace monitoring \
--values ./kind-goodnotes-k8s-demo/minio/values.yaml \
> ./kind-goodnotes-k8s-demo/minio/manifest.yaml


kustomize build kind-goodnotes-k8s-demo/minio | kubectl diff -f -

```