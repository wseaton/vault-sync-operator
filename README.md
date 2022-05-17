# vault-sync-operator

This is a WIP implementation of a K8s Operator that can sync secrets from Vault -> K8s `Secret` Objects.

## Why?

The [External Secrets Operator](https://external-secrets.io/) requires too many permissions to operate well in a multi-tenant environment. This implementation attempts to solve the problem in a least-privileges way, without giving the Operator default ** Secrets access to the entire cluster.

With this approach the Operator can be 'opted-in' to management of a select set of namespaces, each independently syncing secrets via their own team keys.

### `VaultSecret` CR

```yaml

apiVersion: vault-sync.io/v1
kind: VaultSecret
metadata:
  name: example-vault-sync
spec:
  refreshInterval: 30
  target:
    name: my-secret-target
  vault:
    creds:
      name: vault-login
      namespace: my-cool-namespace
    source:
      key: path/to/my/teams/vault
      mount: apps/ # custom mount mount if required
status: {}
```

### Secret Specification

```yaml
kind: Secret
apiVersion: v1
metadata:
  name: vault-login
stringData:
  ALLOWED_TARGET_NAMESPACES: my-ns1,my-ns2
  VAULT_ADDR: https://my.vault.host.my.company.com:8200
  VAULT_APPROLE_ID: {your_approle}
  VAULT_SECRET_ID: {your_secret}
type: Opaque

```




## TODOs

- Liveness/readiness probes
- Expose vault config to CLI
  - eg. Private CA support
- Parameterize some of the OTEL stuff
- Add more login methods for vault
