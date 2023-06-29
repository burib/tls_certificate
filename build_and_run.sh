#!/bin/zsh


pushd ./get_github_oidc_certs >> /dev/null

go build -o get_github_oidc_certs get_github_oidc_certs.go

./get_github_oidc_certs | jq

popd >> /dev/null
