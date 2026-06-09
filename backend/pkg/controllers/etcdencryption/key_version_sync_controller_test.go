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
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	azureclient "github.com/Azure/ARO-HCP/backend/pkg/azure/client"
	"github.com/Azure/ARO-HCP/backend/pkg/controllers/controllerutils"
	"github.com/Azure/ARO-HCP/internal/api"
	"github.com/Azure/ARO-HCP/internal/api/arm"
	controllerutil "github.com/Azure/ARO-HCP/internal/controllerutils"
	"github.com/Azure/ARO-HCP/internal/database"
	"github.com/Azure/ARO-HCP/internal/databasetesting"
	"github.com/Azure/ARO-HCP/internal/utils"
)

const (
	testSubscriptionID    = "00000000-0000-0000-0000-000000000001"
	testResourceGroupName = "test-rg"
	testClusterName       = "test-cluster"
	testVaultName         = "test-vault"
	testKeyName           = "etcd-encryption-key"
	testIdentityURL       = "https://dummyhost.identity.azure.net/dummy"
)

type alwaysSyncCooldownChecker struct{}

func (a *alwaysSyncCooldownChecker) CanSync(ctx context.Context, key any) bool {
	return true
}

var _ controllerutil.CooldownChecker = &alwaysSyncCooldownChecker{}

type mockKeysClient struct {
	keys []*azkeys.KeyProperties
	err  error
}

func (m *mockKeysClient) NewListKeyPropertiesVersionsPager(_ string, _ *azkeys.ListKeyPropertiesVersionsOptions) *runtime.Pager[azkeys.ListKeyPropertiesVersionsResponse] {
	return runtime.NewPager(runtime.PagingHandler[azkeys.ListKeyPropertiesVersionsResponse]{
		More: func(page azkeys.ListKeyPropertiesVersionsResponse) bool {
			return false
		},
		Fetcher: func(ctx context.Context, page *azkeys.ListKeyPropertiesVersionsResponse) (azkeys.ListKeyPropertiesVersionsResponse, error) {
			if m.err != nil {
				return azkeys.ListKeyPropertiesVersionsResponse{}, m.err
			}
			return azkeys.ListKeyPropertiesVersionsResponse{
				KeyPropertiesListResult: azkeys.KeyPropertiesListResult{
					Value: m.keys,
				},
			}, nil
		},
	})
}

var _ azureclient.KeyVaultKeysClient = (*mockKeysClient)(nil)

func mockFactory(client azureclient.KeyVaultKeysClient) KeyVaultKeysClientFactory {
	return func(ctx context.Context, clusterIdentityURL string, kmsIdentityResourceID *azcorearm.ResourceID, vaultURL string) (azureclient.KeyVaultKeysClient, error) {
		return client, nil
	}
}

func mockFactoryError(err error) KeyVaultKeysClientFactory {
	return func(ctx context.Context, clusterIdentityURL string, kmsIdentityResourceID *azcorearm.ResourceID, vaultURL string) (azureclient.KeyVaultKeysClient, error) {
		return nil, err
	}
}

func testKey() controllerutils.HCPClusterKey {
	return controllerutils.HCPClusterKey{
		SubscriptionID:    testSubscriptionID,
		ResourceGroupName: testResourceGroupName,
		HCPClusterName:    testClusterName,
	}
}

func createClusterWithKMS(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient, vaultName, keyName, version string) {
	t.Helper()

	clusterResourceID := api.Must(azcorearm.ParseResourceID(
		"/subscriptions/" + testSubscriptionID +
			"/resourceGroups/" + testResourceGroupName +
			"/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/" + testClusterName))
	kmsIdentityResourceID := api.Must(azcorearm.ParseResourceID(
		"/subscriptions/" + testSubscriptionID +
			"/resourcegroups/" + testResourceGroupName +
			"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-kms-identity"))

	cluster := &api.HCPOpenShiftCluster{
		CosmosMetadata: arm.CosmosMetadata{
			ResourceID: clusterResourceID,
		},
		TrackedResource: arm.TrackedResource{
			Resource: arm.Resource{
				ID:   clusterResourceID,
				Name: testClusterName,
				Type: api.ClusterResourceType.String(),
			},
			Location: "eastus",
		},
		CustomerProperties: api.HCPOpenShiftClusterCustomerProperties{
			Etcd: api.EtcdProfile{
				DataEncryption: api.EtcdDataEncryptionProfile{
					CustomerManaged: &api.CustomerManagedEncryptionProfile{
						Kms: &api.KmsEncryptionProfile{
							ActiveKey: api.KmsKey{
								Name:      keyName,
								VaultName: vaultName,
								Version:   version,
							},
						},
					},
				},
			},
			Platform: api.CustomerPlatformProfile{
				OperatorsAuthentication: api.OperatorsAuthenticationProfile{
					UserAssignedIdentities: api.UserAssignedIdentitiesProfile{
						ControlPlaneOperators: map[string]*azcorearm.ResourceID{
							"kms": kmsIdentityResourceID,
						},
					},
				},
			},
		},
		ServiceProviderProperties: api.HCPOpenShiftClusterServiceProviderProperties{
			ProvisioningState:                     arm.ProvisioningStateSucceeded,
			ManagedIdentitiesDataPlaneIdentityURL: testIdentityURL,
		},
	}
	_, err := db.HCPClusters(testSubscriptionID, testResourceGroupName).Create(ctx, cluster, nil)
	require.NoError(t, err)
}

func createClusterWithoutKMS(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
	t.Helper()

	clusterResourceID := api.Must(azcorearm.ParseResourceID(
		"/subscriptions/" + testSubscriptionID +
			"/resourceGroups/" + testResourceGroupName +
			"/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/" + testClusterName))

	cluster := &api.HCPOpenShiftCluster{
		CosmosMetadata: arm.CosmosMetadata{
			ResourceID: clusterResourceID,
		},
		TrackedResource: arm.TrackedResource{
			Resource: arm.Resource{
				ID:   clusterResourceID,
				Name: testClusterName,
				Type: api.ClusterResourceType.String(),
			},
			Location: "eastus",
		},
		ServiceProviderProperties: api.HCPOpenShiftClusterServiceProviderProperties{
			ProvisioningState: arm.ProvisioningStateSucceeded,
		},
	}
	_, err := db.HCPClusters(testSubscriptionID, testResourceGroupName).Create(ctx, cluster, nil)
	require.NoError(t, err)
}

func makeKey(version string, enabled bool, updated time.Time, expired *time.Time) *azkeys.KeyProperties {
	kid := azkeys.ID(fmt.Sprintf("https://%s.vault.azure.net/keys/%s/%s", testVaultName, testKeyName, version))
	return &azkeys.KeyProperties{
		KID: &kid,
		Attributes: &azkeys.KeyAttributes{
			Enabled: ptr.To(enabled),
			Updated: ptr.To(updated),
			Expires: expired,
		},
	}
}

func TestEtcdEncryptionKeyVersionSyncer_SyncOnce(t *testing.T) {
	ts1 := time.Unix(1000, 0)
	ts2 := time.Unix(2000, 0)
	ts3 := time.Unix(3000, 0)
	expiredTime := time.Unix(1, 0)

	tests := []struct {
		name          string
		seedDB        func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient)
		factory       KeyVaultKeysClientFactory
		expectedError bool
		validateAfter func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient)
	}{
		{
			name: "cluster not found returns nil",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
			},
			factory:       mockFactory(&mockKeysClient{}),
			expectedError: false,
		},
		{
			name: "no KMS config skips",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithoutKMS(t, ctx, db)
			},
			factory:       mockFactory(&mockKeysClient{}),
			expectedError: false,
		},
		{
			name: "no KMS managed identity skips",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				clusterResourceID := api.Must(azcorearm.ParseResourceID(
					"/subscriptions/" + testSubscriptionID +
						"/resourceGroups/" + testResourceGroupName +
						"/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/" + testClusterName))
				cluster := &api.HCPOpenShiftCluster{
					CosmosMetadata: arm.CosmosMetadata{ResourceID: clusterResourceID},
					TrackedResource: arm.TrackedResource{
						Resource: arm.Resource{ID: clusterResourceID, Name: testClusterName, Type: api.ClusterResourceType.String()},
						Location: "eastus",
					},
					CustomerProperties: api.HCPOpenShiftClusterCustomerProperties{
						Etcd: api.EtcdProfile{
							DataEncryption: api.EtcdDataEncryptionProfile{
								CustomerManaged: &api.CustomerManagedEncryptionProfile{
									Kms: &api.KmsEncryptionProfile{
										ActiveKey: api.KmsKey{Name: testKeyName, VaultName: testVaultName, Version: "v1"},
									},
								},
							},
						},
					},
					ServiceProviderProperties: api.HCPOpenShiftClusterServiceProviderProperties{
						ProvisioningState:                     arm.ProvisioningStateSucceeded,
						ManagedIdentitiesDataPlaneIdentityURL: testIdentityURL,
					},
				}
				_, err := db.HCPClusters(testSubscriptionID, testResourceGroupName).Create(ctx, cluster, nil)
				require.NoError(t, err)
			},
			factory:       mockFactory(&mockKeysClient{}),
			expectedError: false,
		},
		{
			name: "single enabled version differs from stored updates SPC",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory: mockFactory(&mockKeysClient{
				keys: []*azkeys.KeyProperties{
					makeKey("v2", true, ts2, nil),
				},
			}),
			expectedError: false,
			validateAfter: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				spc, err := db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Get(ctx, api.ServiceProviderClusterResourceName)
				require.NoError(t, err)
				require.NotNil(t, spc.Spec.EtcdEncryption)
				assert.Equal(t, "v2", spc.Spec.EtcdEncryption.CurrentKeyVersion)
				assert.Equal(t, "", spc.Spec.EtcdEncryption.PreviousKeyVersion)
			},
		},
		{
			name: "version matches stored is no-op",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
				spcKey := testKey()
				spc, err := database.GetOrCreateServiceProviderCluster(ctx, db, spcKey.GetResourceID())
				require.NoError(t, err)
				spc.Spec.EtcdEncryption = &api.ServiceProviderClusterEtcdEncryptionSpec{
					CurrentKeyVersion: "v1",
				}
				_, err = db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Replace(ctx, spc, nil)
				require.NoError(t, err)
			},
			factory: mockFactory(&mockKeysClient{
				keys: []*azkeys.KeyProperties{
					makeKey("v1", true, ts1, nil),
				},
			}),
			expectedError: false,
			validateAfter: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				spc, err := db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Get(ctx, api.ServiceProviderClusterResourceName)
				require.NoError(t, err)
				require.NotNil(t, spc.Spec.EtcdEncryption)
				assert.Equal(t, "v1", spc.Spec.EtcdEncryption.CurrentKeyVersion)
			},
		},
		{
			name: "rotation sets previous version",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
				spcKey := testKey()
				spc, err := database.GetOrCreateServiceProviderCluster(ctx, db, spcKey.GetResourceID())
				require.NoError(t, err)
				spc.Spec.EtcdEncryption = &api.ServiceProviderClusterEtcdEncryptionSpec{
					CurrentKeyVersion: "v1",
				}
				_, err = db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Replace(ctx, spc, nil)
				require.NoError(t, err)
			},
			factory: mockFactory(&mockKeysClient{
				keys: []*azkeys.KeyProperties{
					makeKey("v2", true, ts2, nil),
					makeKey("v1", true, ts1, nil),
				},
			}),
			expectedError: false,
			validateAfter: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				spc, err := db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Get(ctx, api.ServiceProviderClusterResourceName)
				require.NoError(t, err)
				require.NotNil(t, spc.Spec.EtcdEncryption)
				assert.Equal(t, "v2", spc.Spec.EtcdEncryption.CurrentKeyVersion)
				assert.Equal(t, "v1", spc.Spec.EtcdEncryption.PreviousKeyVersion)
			},
		},
		{
			name: "multiple versions selects latest enabled",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory: mockFactory(&mockKeysClient{
				keys: []*azkeys.KeyProperties{
					makeKey("v3", true, ts3, nil),
					makeKey("v2", false, time.Unix(2500, 0), nil),
					makeKey("v1", true, ts1, nil),
				},
			}),
			expectedError: false,
			validateAfter: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				spc, err := db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Get(ctx, api.ServiceProviderClusterResourceName)
				require.NoError(t, err)
				require.NotNil(t, spc.Spec.EtcdEncryption)
				assert.Equal(t, "v3", spc.Spec.EtcdEncryption.CurrentKeyVersion)
			},
		},
		{
			name: "all versions disabled does not update",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory: mockFactory(&mockKeysClient{
				keys: []*azkeys.KeyProperties{
					makeKey("v2", false, ts2, nil),
					makeKey("v1", false, ts1, nil),
				},
			}),
			expectedError: false,
		},
		{
			name: "latest expired selects next enabled non-expired",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory: mockFactory(&mockKeysClient{
				keys: []*azkeys.KeyProperties{
					makeKey("v3", true, ts3, &expiredTime),
					makeKey("v2", true, ts2, nil),
					makeKey("v1", true, ts1, nil),
				},
			}),
			expectedError: false,
			validateAfter: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				spc, err := db.ServiceProviderClusters(testSubscriptionID, testResourceGroupName, testClusterName).Get(ctx, api.ServiceProviderClusterResourceName)
				require.NoError(t, err)
				require.NotNil(t, spc.Spec.EtcdEncryption)
				assert.Equal(t, "v2", spc.Spec.EtcdEncryption.CurrentKeyVersion)
			},
		},
		{
			name: "KeyVault API error returns error",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory: mockFactory(&mockKeysClient{
				err: fmt.Errorf("keyvault unavailable"),
			}),
			expectedError: true,
		},
		{
			name: "factory error returns error",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory:       mockFactoryError(fmt.Errorf("credential retrieval failed")),
			expectedError: true,
		},
		{
			name: "empty key versions does not update",
			seedDB: func(t *testing.T, ctx context.Context, db *databasetesting.MockResourcesDBClient) {
				t.Helper()
				createClusterWithKMS(t, ctx, db, testVaultName, testKeyName, "v1")
			},
			factory:       mockFactory(&mockKeysClient{keys: []*azkeys.KeyProperties{}}),
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runCtx := utils.ContextWithLogger(context.Background(), logr.Discard())
			db := databasetesting.NewMockResourcesDBClient()

			tt.seedDB(t, runCtx, db)

			syncer := &etcdEncryptionKeyVersionSyncer{
				cooldownChecker:           &alwaysSyncCooldownChecker{},
				resourcesDBClient:         db,
				keyvaultKeysClientFactory: tt.factory,
			}

			err := syncer.SyncOnce(runCtx, testKey())

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.validateAfter != nil && !tt.expectedError {
				tt.validateAfter(t, runCtx, db)
			}
		})
	}
}
