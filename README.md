# tls_certificate

### Get github oidc certs and print them out

```bash
./build_and_run.sh
```

<img width="1495" alt="image" src="https://github.com/burib/tls_certificate/assets/956227/3e89e5d3-904c-4c89-a0af-a1ccd0112180">

### to get only the sha1 fingerprint

```bash
./build_and_run.sh | jq .sha1_fingerprints  
```
<img width="1497" alt="image" src="https://github.com/burib/tls_certificate/assets/956227/25072513-cc6d-49b2-89ae-d7a1740bb2e6">
