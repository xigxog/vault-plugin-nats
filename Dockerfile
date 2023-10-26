ARG VAULT_VERSION

FROM registry.hub.docker.com/hashicorp/vault:$VAULT_VERSION

USER root

COPY ./bin/* /xigxog/vault/plugins/

RUN apk add --no-cache jq && \
    wget -O /usr/bin/kubectl https://dl.k8s.io/release/v1.28.2/bin/linux/amd64/kubectl && \
    chmod +x /usr/bin/kubectl && \
    chown 100:1000 /xigxog/vault/plugins

USER 100
