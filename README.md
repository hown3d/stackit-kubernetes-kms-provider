# STACKIT Kubernetes KMS Plugin

This repo contains a KMS Plugin for Kubernetes using STACKIT KMS.

```
Usage of kubernetes-kms-plugin:
  -key string
        key to use for Encrypt and decryption. Format is {projectId}/{keyRingId}/{keyId}/{version}
  -listen string
        path where to bind the unix socket (default "/var/run/kmsplugin/socket.sock")
  -region string
        STACKIT region to use (default "eu01")
  -timeout duration
        timeout for the grpc server (default 10s)
```

## Testing locally

1. Place your STACKIT creds in `test/stackit/credentials.json`
1. Create a keyring and key in your STACKIT KMS \
    You can use the script provided in `scripts/testkey.sh`
2. Adjust the kube-apiserver patch with your **projectID**, **keyringID** and **keyID**.
3. Build the image with `make image`
4. Start your local kind cluster `make kind`
5. If the control plane does not start, you can view the logs of the kmsplugin using `make stream-kms-plugin-logs`
6. Verify that the secrets are encrypted: `kubectl exec -n kube-system etcd-kind-control-plane -- etcdctl --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key  get /registry/secrets/default/{SECRETNAME} | hexdump -C`
