# Kubernetes manifests

Applied in filename order:

| File | Contents |
|---|---|
| `00-namespace.yaml` | Namespace with `restricted` pod-security enforcement |
| `10-configmap.yaml` | Non-secret configuration |
| `20-secret.yaml` | **Template** -- signing key + database URL. Create it out of band. |
| `30-api.yaml` | API Deployment (2 replicas) + Service, probes, limits, read-only root FS |
| `40-worker.yaml` | Scan worker Deployment, separate from the API |
| `50-hpa.yaml` | Autoscaling for both, with a slow scale-down so scans finish |
| `60-ingress.yaml` | TLS-terminating ingress example |
| `70-pvc.yaml` | Read-only volume holding the repositories to scan |

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
kubectl -n ironclad create secret generic ironclad-secrets \
  --from-literal=IRONCLAD_SIGNING_KEY="$(openssl rand -hex 32)" \
  --from-literal=IRONCLAD_DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/ironclad"
kubectl apply -f deploy/k8s/
kubectl -n ironclad run ironclad-migrate --rm -it --restart=Never \
  --image=ghcr.io/daniyalofficial/ironclad-sentinel:1.1.0 \
  --env-from=configmap/ironclad-config --env-from=secret/ironclad-secrets \
  -- migrate
```

The API and worker are separate Deployments on purpose: a large scan is
CPU-bound and must not starve API requests.

`20-secret.yaml` is a template with placeholder values. Real credentials
belong in your secret manager, not in git.
