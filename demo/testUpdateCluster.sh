#!/bin/bash

set -e

source env_vars
source "$(dirname "$0")"/common.sh



arm_x_ms_identity_url_header() {
  # Requests directly against the frontend
  # need to send a X-Ms-Identity-Url HTTP
  # header, which simulates what ARM performs.
  # By default we set a dummy value, which is
  # enough in the environments where a real
  # Managed Identities Data Plane does not
  # exist like in the development or integration
  # environments. The default can be overwritten
  # by providing the environment variable
  # ARM_X_MS_IDENTITY_URL when running the script.
  : ${ARM_X_MS_IDENTITY_URL:="https://dummyhost.identity.azure.net"}
  echo "X-Ms-Identity-Url: ${ARM_X_MS_IDENTITY_URL}"
}

main() {

  SUBSCRIPTION_ID=$(az account show --query id -o tsv)
  CLUSTER_FILE="cluster.json"


  (arm_system_data_header; correlation_headers; arm_x_ms_identity_url_header) | curl -si -X PATCH "localhost:8443/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${CUSTOMER_RG_NAME}/providers/Microsoft.RedHatOpenshift/hcpOpenShiftClusters/${CLUSTER_NAME}?api-version=2024-06-10-preview" \
    --header @- \
    --json @${CLUSTER_FILE}
}

# Call to the `main` function in the script
main "$@"
