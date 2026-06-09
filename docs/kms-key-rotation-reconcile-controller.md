# PoC: Etcd Encryption Key Version Sync Controller

## What this PoC validates

This PoC proves that the ARO-HCP backend can detect when a customer rotates their Azure KeyVault encryption key and persist the new version in Cosmos DB. The detection runs as a standard backend controller that periodically polls the customer's KeyVault using the data plane API and compares the latest key version against what is stored in the `ServiceProviderCluster` document. When a rotation is detected, the controller records the new version and preserves the previous one for audit.

This is the first step in the full key rotation flow. A separate trigger controller (not part of this PoC) would read the persisted version change and call Cluster Service to update the HostedCluster's KMS configuration.

## Why the data plane API

We evaluated three credential and API strategies before settling on the data plane approach.

**ARM management plane with KMS managed identity** was the first attempt. The ARM API (`armkeyvault`) lists key versions via the standard resource manager endpoint, which works for both public and private KeyVaults. However, the KMS managed identity is assigned the "Key Vault Crypto User" role, which only grants data plane `DataActions` — it lacks the ARM `Actions` like `Microsoft.KeyVault/vaults/keys/read`. Deploying the controller to the dev environment confirmed this with a `ForbiddenByRbac` error.

**ARM management plane with FPA credentials** was the second attempt. The First Party Application has broader ARM access. We added a `KeyVaultKeysClient` method to `FirstPartyApplicationClientBuilder` and tested it in the dev environment. It also returned `ForbiddenByRbac` because the FPA did not have a role assignment granting `Microsoft.KeyVault/vaults/keys/read` on the customer's KeyVault. While this could be fixed by adding a "Key Vault Reader" role assignment for the FPA on every customer vault, that introduces an operational burden — every customer onboarding would require an additional RBAC grant.

**Data plane API with KMS managed identity** is what we landed on. The `azkeys` package talks directly to the KeyVault data plane (`https://{vault}.vault.azure.net`). The KMS identity already has "Key Vault Crypto User", which grants the data plane `keys/read` permission needed to list key versions. No additional role assignments are required. The credential is retrieved through the MI Data Plane service using the cluster's identity URL, following the same pattern as `ServiceManagedIdentityClientBuilder`. The tradeoff is that the backend needs network access to the vault endpoint, which may not be reachable for private KeyVaults from the service cluster — but this is acceptable for the PoC scope and can be addressed later.

## What was implemented

### Cosmos DB schema extension

A new `EtcdEncryption` field was added to `ServiceProviderClusterSpec` in `internal/api/types_serviceprovider_cluster.go`. It holds `CurrentKeyVersion` (the latest detected version) and `PreviousKeyVersion` (what was active before the rotation). Using a pointer type means the field is omitted entirely for clusters without customer-managed encryption, keeping existing documents untouched.

### KeyVault data plane client interface

A `KeyVaultKeysClient` interface in `backend/pkg/azure/client/keyvault_keys_client.go` wraps the single method we need from `azkeys.Client`: `NewListKeyPropertiesVersionsPager`. The `azkeys.Client` struct satisfies this interface directly. Tests inject a mock implementation that returns canned key lists without touching Azure.

### The controller

The controller lives in `backend/pkg/controllers/etcdencryption/key_version_sync_controller.go` and follows the `ClusterSyncer` pattern used by the upgrade controllers. It is wrapped by `NewClusterWatchingController` with a 5-minute sync interval (this is just for testing, it can be syncrhonized in a longer period in AKS this is done every [6 hours](https://learn.microsoft.com/en-us/azure/aks/kms-data-encryption?pivots=cmk-private) ).

The `SyncOnce` method runs for each cluster and does the following:

1. Reads the cluster from Cosmos and skips if there is no customer-managed KMS configuration.
2. Looks up the KMS managed identity resource ID from `ControlPlaneOperators["kms"]` and the cluster's MI Data Plane identity URL. Skips if either is missing.
3. Constructs the vault URL using the vault name and the cloud-specific DNS suffix (e.g. `https://myvault.vault.azure.net`).
4. Calls the `KeyVaultKeysClientFactory` — in production this retrieves the KMS MI credential via the MI Data Plane service and creates an `azkeys.Client` scoped to the vault.
5. Iterates all key versions, filtering for enabled and non-expired, and selects the one with the most recent `Updated` (or `Created`) timestamp. The version string is extracted using `azkeys.ID.Version()`.
6. Compares against the stored `CurrentKeyVersion` in the `ServiceProviderCluster` document. If unchanged, returns early. If different, writes the new version as `CurrentKeyVersion` and moves the old one to `PreviousKeyVersion`.

The factory function `NewMIDataplaneKeysClientFactory` encapsulates the MI Data Plane credential flow: it creates an MI DP client from the cluster's identity URL, retrieves credentials for the KMS identity, converts them to an `azidentity` credential, and constructs the `azkeys.Client`. This follows the same three-step pattern as `ServiceManagedIdentityClientBuilder.UserAssignedIdentitiesClient`.

### KeyVault DNS suffix

Rather than hardcoding `vault.azure.net`, a `KeyVaultDNSSuffix()` method was added to `AzureCloudEnvironment` in `backend/pkg/azure/config/azure_cloud_environment.go`. It returns the correct suffix for each cloud: `vault.azure.net` for Azure Public, `vault.azure.cn` for Azure China, and `vault.usgovcloudapi.net` for Azure US Government. This follows the same approach as HyperShift's `GetKeyVaultDNSSuffixFromCloudType`. The suffix flows from the cloud environment config through `BackendOptions` into the controller constructor.

### Wiring

The controller is instantiated in `backend/pkg/app/backend.go` alongside the other cluster-watching controllers. The factory receives the `FPAMIDataplaneClientBuilder` and `AZCoreClientOptions` from `BackendOptions`. The `KeyVaultDNSSuffix` is passed from `root.go` where the cloud environment is initialized.

### Tests

Unit tests in `key_version_sync_controller_test.go` cover: cluster not found, no KMS config, no KMS managed identity, version match (no-op), version differs (update), rotation (sets previous version), multiple versions (selects latest enabled), all disabled, latest expired, KeyVault API error, factory error, and empty versions. All tests use mock implementations of the `KeyVaultKeysClient` interface and a mock resources DB client.

## Dev environment validation

The controller was deployed to a personal dev environment with a customer-managed encryption cluster. On the first sync it detected the current key version and persisted it in Cosmos:

```
"msg":"Etcd encryption key version changed","oldVersion":"","newVersion":"40c1f75160a3431386f0aee6b70ff0b9"
```

After rotating the key in KeyVault (`az keyvault key rotate`), the next sync cycle detected the change:

```
"msg":"Etcd encryption key version changed","oldVersion":"40c1f75160a3431386f0aee6b70ff0b9","newVersion":"da8d96a668414abe85b7bb4c04cb1d7c"
```

The controller status in the data dump showed `Degraded: False`, `reason: NoErrors`.

## Files changed

| File | What |
|------|------|
| `internal/api/types_serviceprovider_cluster.go` | Added `EtcdEncryption` field and `ServiceProviderClusterEtcdEncryptionSpec` type |
| `internal/api/zz_generated.deepcopy.go` | Regenerated via `make deepcopy` |
| `backend/pkg/azure/client/keyvault_keys_client.go` | New — `KeyVaultKeysClient` interface wrapping `azkeys.Client` |
| `backend/pkg/azure/config/azure_cloud_environment.go` | Added `keyVaultDNSSuffix` field and `KeyVaultDNSSuffix()` method |
| `backend/pkg/controllers/etcdencryption/key_version_sync_controller.go` | New — the controller |
| `backend/pkg/controllers/etcdencryption/key_version_sync_controller_test.go` | New — unit tests |
| `backend/pkg/app/backend.go` | Wired the controller, added `AZCoreClientOptions` and `KeyVaultDNSSuffix` to `BackendOptions` |
| `backend/cmd/root.go` | Passes `AZCoreClientOptions` and `KeyVaultDNSSuffix` from cloud environment |
| `backend/go.mod` | Added `azkeys` dependency |

## Assumptions and known limitations

The vault URL is constructed from the vault name and cloud-specific DNS suffix. This assumes the vault name alone is sufficient to form the FQDN, which holds for all Azure public clouds. If a customer uses a custom domain for their vault, this would break.

The controller assumes the KeyVault is network-reachable from the service cluster. For private KeyVaults with no public endpoint, the data plane call will fail. In production this would need a solution — either routing through the management cluster (which already has connectivity for the KMS plugin) or falling back to ARM with appropriate RBAC.

The resource group used in the ARM-era code was the cluster's resource group, under the assumption the vault lives there. With the data plane switch this is no longer relevant — the `azkeys` client addresses the vault by URL, not by resource group.

## What comes next

A trigger controller that watches `ServiceProviderCluster.Spec.EtcdEncryption.CurrentKeyVersion` against the cluster's stored KMS version and calls Cluster Service to update the cluster when they diverge. This follows the `TriggerControlPlaneUpgradeController` pattern. Metrics for rotation events (detected, applied, failed) should also be added.

