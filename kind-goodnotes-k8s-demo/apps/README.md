

## Manual Deployments for CI unavailable

1. Checkout from `main` branch and create yaml by requirements

2. Run `kustomize build` and `kubectl diff` to see output
```sh
kustomize build kind-goodnotes-k8s-demo/apps/<app_name> | kubectl diff -f -

```

3. Raise a PR and paste diff output with comment for review

4. Apply it once approved and without code confliction.

```sh
kubectl apply -k kind-goodnotes-k8s-demo/apps/<app_name>
```

## loading image to cluster
```sh
kind load docker-image iris-sklearn-api:local --name goodnotes-k8s-demo
```



## Test example
```sh
curl -X POST \
  -H "Host: iris.localhost" \
  -H "Content-Type: application/json" \
  -d '{"features":[5.1,3.5,1.4,0.2]}' \
  http://iris.localhost:8080/predict
  ```
