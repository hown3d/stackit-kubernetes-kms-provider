#!/usr/bin/env bash
set -e
KEYRING_ID=$(stackit curl -X POST --data '{"displayName": "test"}' -H 'Content-Type: application/json' https://kms.api.eu01.qa.stackit.cloud/v1alpha/projects/6c600839-6c5e-411a-957a-d5e6c405b0cf/keyrings | jq -r '.id')
echo "keyringID: $KEYRING_ID"
KEY_ID=$(stackit curl -X POST --data '{"backend": "software", "purpose": "symmetric_encrypt_decrypt", "displayName": "test", "algorithm": "aes_256_gcm"}' -H 'Content-Type: application/json' https://kms.api.eu01.qa.stackit.cloud/v1alpha/projects/6c600839-6c5e-411a-957a-d5e6c405b0cf/keyrings/${KEYRING_ID}/keys | jq -r '.id')
echo "keyID: $KEY_ID"
