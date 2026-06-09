// Copyright 2026 Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package etcdencryption

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/msi-dataplane/pkg/dataplane"

	azureclient "github.com/Azure/ARO-HCP/backend/pkg/azure/client"
	"github.com/Azure/ARO-HCP/backend/pkg/controllers/controllerutils"
	"github.com/Azure/ARO-HCP/backend/pkg/informers"
	"github.com/Azure/ARO-HCP/backend/pkg/listers"
	"github.com/Azure/ARO-HCP/internal/api"
	"github.com/Azure/ARO-HCP/internal/azure"
	controllerutil "github.com/Azure/ARO-HCP/internal/controllerutils"
	"github.com/Azure/ARO-HCP/internal/database"
	unionkubeapplierinformers "github.com/Azure/ARO-HCP/internal/database/unioninformers/kubeapplier"
	"github.com/Azure/ARO-HCP/internal/utils"
)

// KeyVaultKeysClientFactory creates a KeyVaultKeysClient for a given vault.
// In production, it retrieves KMS MI credentials via the MI Data Plane and
// constructs an azkeys data plane client. Tests replace this with a mock.
type KeyVaultKeysClientFactory func(ctx context.Context, clusterIdentityURL string, kmsIdentityResourceID *azcorearm.ResourceID, vaultURL string) (azureclient.KeyVaultKeysClient, error)

// NewMIDataplaneKeysClientFactory returns a KeyVaultKeysClientFactory that
// uses the MI Data Plane to retrieve KMS managed identity credentials, then
// creates an azkeys data plane client scoped to the vault URL.
func NewMIDataplaneKeysClientFactory(fpaMIDPClientBuilder azureclient.FPAMIDataplaneClientBuilder, clientOptions *azcore.ClientOptions) KeyVaultKeysClientFactory {
	return func(ctx context.Context, clusterIdentityURL string, kmsIdentityResourceID *azcorearm.ResourceID, vaultURL string) (azureclient.KeyVaultKeysClient, error) {
		miDPClient, err := fpaMIDPClientBuilder.ManagedIdentitiesDataplane(clusterIdentityURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create MI dataplane client: %w", err)
		}

		resp, err := miDPClient.GetUserAssignedIdentitiesCredentials(ctx, dataplane.UserAssignedIdentitiesRequest{
			IdentityIDs: []string{kmsIdentityResourceID.String()},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get KMS MI credentials: %w", err)
		}
		if len(resp.ExplicitIdentities) == 0 {
			return nil, fmt.Errorf("MI dataplane returned no credentials for KMS identity %s", kmsIdentityResourceID.String())
		}

		cred, err := dataplane.GetCredential(*clientOptions, resp.ExplicitIdentities[0])
		if err != nil {
			return nil, fmt.Errorf("failed to get credential from MI dataplane response: %w", err)
		}

		return azkeys.NewClient(vaultURL, cred, &azkeys.ClientOptions{ClientOptions: *clientOptions})
	}
}

type etcdEncryptionKeyVersionSyncer struct {
	cooldownChecker           controllerutil.CooldownChecker
	resourcesDBClient         database.ResourcesDBClient
	keyVaultDNSSuffix         string
	keyvaultKeysClientFactory KeyVaultKeysClientFactory
}

var _ controllerutils.ClusterSyncer = (*etcdEncryptionKeyVersionSyncer)(nil)

func NewEtcdEncryptionKeyVersionSyncController(
	resourcesDBClient database.ResourcesDBClient,
	activeOperationLister listers.ActiveOperationLister,
	backendInformers informers.BackendInformers,
	kubeApplierInformers *unionkubeapplierinformers.UnionKubeApplierInformers,
	keyVaultDNSSuffix string,
	keyvaultKeysClientFactory KeyVaultKeysClientFactory,
) controllerutils.Controller {
	syncer := &etcdEncryptionKeyVersionSyncer{
		cooldownChecker:           controllerutils.DefaultActiveOperationPrioritizingCooldown(activeOperationLister),
		resourcesDBClient:         resourcesDBClient,
		keyVaultDNSSuffix:         keyVaultDNSSuffix,
		keyvaultKeysClientFactory: keyvaultKeysClientFactory,
	}

	return controllerutils.NewClusterWatchingController(
		"EtcdEncryptionKeyVersionSync",
		resourcesDBClient,
		backendInformers,
		kubeApplierInformers,
		5*time.Minute,
		syncer,
	)
}

func (c *etcdEncryptionKeyVersionSyncer) CooldownChecker() controllerutil.CooldownChecker {
	return c.cooldownChecker
}

func (c *etcdEncryptionKeyVersionSyncer) SyncOnce(ctx context.Context, key controllerutils.HCPClusterKey) error {
	logger := utils.LoggerFromContext(ctx)

	cluster, err := c.resourcesDBClient.HCPClusters(key.SubscriptionID, key.ResourceGroupName).Get(ctx, key.HCPClusterName)
	if database.IsNotFoundError(err) {
		return nil
	}
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get Cluster: %w", err))
	}

	kms := cluster.CustomerProperties.Etcd.DataEncryption.CustomerManaged
	if kms == nil || kms.Kms == nil {
		return nil
	}

	kmsIdentityResourceID := cluster.CustomerProperties.Platform.OperatorsAuthentication.UserAssignedIdentities.ControlPlaneOperators[string(azure.ClusterOperatorIdentifierKMS)]
	if kmsIdentityResourceID == nil {
		return nil
	}

	clusterIdentityURL := cluster.ServiceProviderProperties.ManagedIdentitiesDataPlaneIdentityURL
	if clusterIdentityURL == "" {
		return nil
	}

	vaultURL := fmt.Sprintf("https://%s.%s", kms.Kms.ActiveKey.VaultName, c.keyVaultDNSSuffix)

	keysClient, err := c.keyvaultKeysClientFactory(ctx, clusterIdentityURL, kmsIdentityResourceID, vaultURL)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to create KeyVault keys client: %w", err))
	}

	latestVersion, err := c.findLatestEnabledKeyVersion(ctx, keysClient, kms.Kms.ActiveKey.Name)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to find latest key version: %w", err))
	}
	if latestVersion == "" {
		logger.Info("No enabled, non-expired key version found in KeyVault")
		return nil
	}

	existingServiceProviderCluster, err := database.GetOrCreateServiceProviderCluster(ctx, c.resourcesDBClient, key.GetResourceID())
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get or create ServiceProviderCluster: %w", err))
	}

	currentVersion := ""
	if existingServiceProviderCluster.Spec.EtcdEncryption != nil {
		currentVersion = existingServiceProviderCluster.Spec.EtcdEncryption.CurrentKeyVersion
	}
	if currentVersion == latestVersion {
		return nil
	}

	logger.Info("Etcd encryption key version changed", "oldVersion", currentVersion, "newVersion", latestVersion)

	existingServiceProviderCluster.Spec.EtcdEncryption = &api.ServiceProviderClusterEtcdEncryptionSpec{
		CurrentKeyVersion:  latestVersion,
		PreviousKeyVersion: currentVersion,
	}

	serviceProviderClustersCosmosClient := c.resourcesDBClient.ServiceProviderClusters(key.SubscriptionID, key.ResourceGroupName, key.HCPClusterName)
	_, err = serviceProviderClustersCosmosClient.Replace(ctx, existingServiceProviderCluster, nil)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to replace ServiceProviderCluster: %w", err))
	}

	return nil
}

// findLatestEnabledKeyVersion iterates all key versions via the KeyVault data
// plane and returns the version string of the latest enabled, non-expired key.
// "Latest" is determined by the most recent Updated (or Created) timestamp.
func (c *etcdEncryptionKeyVersionSyncer) findLatestEnabledKeyVersion(
	ctx context.Context,
	keysClient azureclient.KeyVaultKeysClient,
	keyName string,
) (string, error) {
	pager := keysClient.NewListKeyPropertiesVersionsPager(keyName, nil)

	var latestVersion string
	var latestTimestamp time.Time

	now := time.Now()

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to list key versions: %w", err)
		}

		for _, key := range page.Value {
			if key == nil || key.Attributes == nil {
				continue
			}

			attrs := key.Attributes
			if attrs.Enabled == nil || !*attrs.Enabled {
				continue
			}
			if attrs.Expires != nil && !attrs.Expires.After(now) {
				continue
			}

			var timestamp time.Time
			if attrs.Updated != nil {
				timestamp = *attrs.Updated
			} else if attrs.Created != nil {
				timestamp = *attrs.Created
			}

			if timestamp.After(latestTimestamp) {
				latestTimestamp = timestamp
				if key.KID != nil {
					latestVersion = key.KID.Version()
				}
			}
		}
	}

	return latestVersion, nil
}
