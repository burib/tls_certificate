# tls_certificate

### Get github oidc certs and print them out

```bash
./build_and_run.sh
```

### to get only the sha1 fingerprint

```bash
./build_and_run.sh | jq .sha1_fingerprints  
```
