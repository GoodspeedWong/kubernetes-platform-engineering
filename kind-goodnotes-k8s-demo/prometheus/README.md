
## Quickstart

This project is intended to be used as a library (i.e. the intent is not for you to create your own modified copy of this repository).

Though for a quickstart a compiled version of the Kubernetes [manifests](manifests) generated with this library (specifically with `example.jsonnet`) is checked into this repository in order to try the content out quickly. To try out the stack un-customized run:
* Create the monitoring stack using the config in the `manifests` directory:

```shell
# Create the namespace and CRDs, and then wait for them to be available before creating the remaining resources
# Note that due to some CRD size we are using kubectl server-side apply feature which is generally available since kubernetes 1.22.
# If you are using previous kubernetes versions this feature may not be available and you would need to use kubectl create instead.
kubectl apply --server-side -f manifests/setup
kubectl wait \
	--for condition=Established \
	--all CustomResourceDefinition \
	--namespace=monitoring
kubectl apply -f manifests/
```

We create the namespace and CustomResourceDefinitions first to avoid race conditions when deploying the monitoring components.
Alternatively, the resources in both folders can be applied with a single command
`kubectl apply --server-side -f manifests/setup -f manifests`, but it may be necessary to run the command multiple times for all components to
be created successfully.

* And to teardown the stack:

```shell
kubectl delete --ignore-not-found=true -f manifests/ -f manifests/setup
```


## Access

[Prometheus Query UI](http://prometheus.localhost:8080)

[Grafana UI](http://grafana.localhost:8080)

## OpenClaw dashboards

This stack also carries two OpenClaw business dashboards:
- `openclaw-trading-overview`
- `openclaw-data-core-pipeline`

They are sourced from the `trading-openclaw` repository and copied in as concrete ConfigMap manifests.

## OpenClaw dashboards

This stack also carries three OpenClaw dashboards:
- `openclaw-trading-overview`
- `openclaw-data-core-pipeline`
- `openclaw-trace-operations`

They are sourced from the `trading-openclaw` repository and copied in as concrete ConfigMap manifests.

## OpenClaw dashboards

This stack also carries four OpenClaw dashboards:
- `openclaw-trading-overview`
- `openclaw-data-core-pipeline`
- `openclaw-trace-operations`
- `openclaw-tempo-drilldowns`

They are sourced from the `trading-openclaw` repository and copied in as concrete ConfigMap manifests.

## OpenClaw tracing datasource

The Grafana datasources definition now includes a `tempo` datasource so OpenClaw trace dashboards can use Tempo as source-of-truth instead of relying on manual UI-only datasource setup.

## OpenClaw dashboards

This stack also carries five OpenClaw dashboards:
- `openclaw-trading-overview`
- `openclaw-postgres-overview`
- `openclaw-data-core-pipeline`
- `openclaw-trace-operations`
- `openclaw-tempo-drilldowns`

They are sourced from the `trading-openclaw` repository and copied in as concrete ConfigMap manifests.

## OpenClaw dashboards

This stack also carries five OpenClaw dashboards:
- `openclaw-trading-overview`
- `openclaw-postgres-overview`
- `openclaw-postgres-statement-drilldown`
- `openclaw-data-core-pipeline`
- `openclaw-trace-operations`
- `openclaw-tempo-drilldowns`

They are sourced from the `trading-openclaw` repository and copied in as concrete ConfigMap manifests.

## OpenClaw Postgres datasource

Grafana also provisions an `openclaw-postgres` datasource that connects directly to `postgres.apps.svc.cluster.local:5432` for SQL drilldown dashboards backed by `pg_stat_statements`.

## OpenClaw dashboards

This stack also carries five OpenClaw dashboards:
- `openclaw-trading-overview`
- `openclaw-monitoring-storage-risk`
- `openclaw-postgres-overview`
- `openclaw-postgres-statement-drilldown`
- `openclaw-data-core-pipeline`
- `openclaw-trace-operations`
- `openclaw-tempo-drilldowns`

They are sourced from the `trading-openclaw` repository and copied in as concrete ConfigMap manifests.
