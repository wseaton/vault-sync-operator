# vault-sync-operator

This is a WIP implementation of a K8s Operator that can sync secrets from Vault -> K8s `Secret` Objects.

## Why?

The [External Secrets Operator](https://external-secrets.io/) requires too many permissions to operate well in a multi-tenant environment. This implementation attempts to solve the problem in a least-privileges way, without giving the Operator default ** Secrets access to the entire cluster.

With this approach the Operator can be 'opted-in' to management of a select set of namespaces, each independently syncing secrets via their own team keys.
