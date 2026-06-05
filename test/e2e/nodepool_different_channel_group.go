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

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/blang/semver/v4"

	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/Azure/ARO-HCP/internal/cincinnati"
	"github.com/Azure/ARO-HCP/test/util/framework"
	"github.com/Azure/ARO-HCP/test/util/labels"
)

var _ = Describe("Customer", func() {
	DescribeTable("should create a nodepool with a different channel group than the cluster",
		func(ctx context.Context, minor string) {
			clusterChannelGroup := "stable"
			nodePoolChannelGroup := "candidate"

			clusterVersion, err := framework.GetLatestVersionInMinor(ctx, clusterChannelGroup, minor)
			if cincinnati.IsCincinnatiVersionNotFoundError(err) {
				Skip(fmt.Sprintf("no version found for minor %s on channel %s", minor, clusterChannelGroup))
			}
			Expect(err).NotTo(HaveOccurred(), "failed to get latest version for cluster channel group %s", clusterChannelGroup)

			nodePoolVersion, err := framework.GetLatestVersionInMinor(ctx, nodePoolChannelGroup, minor)
			if cincinnati.IsCincinnatiVersionNotFoundError(err) {
				Skip(fmt.Sprintf("no version found for minor %s on channel %s", minor, nodePoolChannelGroup))
			}
			Expect(err).NotTo(HaveOccurred(), "failed to get latest version for nodepool channel group %s", nodePoolChannelGroup)

			clusterSemver, err := semver.ParseTolerant(clusterVersion)
			Expect(err).NotTo(HaveOccurred(), "failed to parse cluster version %s", clusterVersion)
			nodePoolSemver, err := semver.ParseTolerant(nodePoolVersion)
			Expect(err).NotTo(HaveOccurred(), "failed to parse nodepool version %s", nodePoolVersion)
			if !nodePoolSemver.GT(clusterSemver) {
				Skip(fmt.Sprintf("candidate version %s is not greater than stable version %s for minor %s", nodePoolVersion, clusterVersion, minor))
			}

			tc := framework.NewTestContext()

			if tc.UsePooledIdentities() {
				err := tc.AssignIdentityContainers(ctx, 1, 60*time.Second)
				Expect(err).NotTo(HaveOccurred(), "failed to assign pooled identity containers")
			}

			versionLabel := strings.ReplaceAll(minor, ".", "-")
			suffix := rand.String(6)
			clusterName := "np-diff-cg-" + versionLabel + "-" + suffix

			By("creating resource group")
			resourceGroup, err := tc.NewResourceGroup(ctx, "rg-np-diff-cg-"+versionLabel+"-"+suffix, tc.Location())
			Expect(err).NotTo(HaveOccurred(), "failed to create resource group")

			By("creating cluster parameters")
			clusterParams := framework.NewDefaultClusterParams20240610()
			clusterParams.ClusterName = clusterName
			clusterParams.OpenshiftVersionId = clusterVersion
			clusterParams.ChannelGroup = clusterChannelGroup
			managedResourceGroupName := framework.SuffixName(*resourceGroup.Name+"-np-dcg-"+suffix, "-managed", 64)
			clusterParams.ManagedResourceGroupName = managedResourceGroupName

			By("creating customer resources")
			clusterParams, err = tc.CreateClusterCustomerResources20240610(ctx,
				resourceGroup,
				clusterParams,
				map[string]any{
					"customerNsgName":        "customer-nsg-np-dcg-" + suffix,
					"customerVnetName":       "customer-vnet-np-dcg-" + suffix,
					"customerVnetSubnetName": "customer-vnet-subnet-np-dcg-" + suffix,
				},
				TestArtifactsFS,
				framework.RBACScopeResourceGroup,
			)
			Expect(err).NotTo(HaveOccurred(), "failed to create cluster customer resources")

			By(fmt.Sprintf("creating the HCP cluster with version %s on channel %s", clusterVersion, clusterChannelGroup))
			err = tc.CreateHCPClusterFromParam20240610(
				ctx,
				GinkgoLogr,
				*resourceGroup.Name,
				clusterParams,
				framework.ClusterCreationTimeout,
			)
			Expect(err).NotTo(HaveOccurred(), "failed to create HCP cluster %s", clusterName)

			By(fmt.Sprintf("creating nodepool with version %s on channel %s (cluster is %s on %s)", nodePoolVersion, nodePoolChannelGroup, clusterVersion, clusterChannelGroup))
			customerNodePoolName := "np-diff-cg"
			nodePoolParams := framework.NewDefaultNodePoolParams20240610()
			nodePoolParams.NodePoolName = customerNodePoolName
			nodePoolParams.OpenshiftVersionId = nodePoolVersion
			nodePoolParams.ChannelGroup = nodePoolChannelGroup
			err = tc.CreateNodePoolFromParam20240610(
				ctx,
				GinkgoLogr,
				*resourceGroup.Name,
				managedResourceGroupName,
				clusterName,
				nodePoolParams,
				framework.NodePoolCreationTimeout,
			)
			Expect(err).NotTo(HaveOccurred(), "failed to create node pool %s with channel group %s (cluster channel group: %s)", customerNodePoolName, nodePoolChannelGroup, clusterChannelGroup)

			By("verifying node pool GET reflects the different channel group")
			nodePoolsClient := tc.Get20240610ClientFactoryOrDie(ctx).NewNodePoolsClient()
			npGetResponse, err := framework.GetNodePool20240610(ctx, nodePoolsClient, *resourceGroup.Name, clusterName, customerNodePoolName)
			Expect(err).NotTo(HaveOccurred(), "failed to GET node pool %s", customerNodePoolName)
			Expect(npGetResponse.Properties).NotTo(BeNil(), "node pool GET response Properties was nil")
			Expect(npGetResponse.Properties.Version).NotTo(BeNil(), "node pool GET response Properties.Version was nil")
			Expect(npGetResponse.Properties.Version.ChannelGroup).NotTo(BeNil(), "node pool GET response Properties.Version.ChannelGroup was nil")
			Expect(*npGetResponse.Properties.Version.ChannelGroup).To(Equal(nodePoolChannelGroup),
				"expected node pool channel group to be %s but got %s", nodePoolChannelGroup, *npGetResponse.Properties.Version.ChannelGroup)
			Expect(*npGetResponse.Properties.Version.ID).To(Equal(nodePoolVersion),
				"expected node pool version to be %s but got %s", nodePoolVersion, *npGetResponse.Properties.Version.ID)
		},
		Entry("for 4.20", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "4.20"),
		Entry("for 4.21", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "4.21"),
		Entry("for 4.22", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "4.22"),
		Entry("for 4.23", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "4.23"),
		Entry("for 5.0", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.0"),
		Entry("for 5.1", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.1"),
		Entry("for 5.2", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.2"),
		Entry("for 5.3", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.3"),
		Entry("for 5.4", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.4"),
		Entry("for 5.5", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.5"),
		Entry("for 5.6", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.6"),
		Entry("for 5.7", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.7"),
		Entry("for 5.8", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.8"),
		Entry("for 5.9", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.9"),
		Entry("for 5.10", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.10"),
		Entry("for 5.11", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.11"),
		Entry("for 5.12", labels.RequireNothing, labels.Medium, labels.Positive, labels.AroRpApiCompatible, "5.12"),
	)
})
