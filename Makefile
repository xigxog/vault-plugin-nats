VAULT_VERSION := 1.14.1
GIT_REF := $(shell git symbolic-ref -q --short HEAD || git describe --tags --exact-match)

TARGET_DIR := bin
BIN := nats-plugin-$(GIT_REF)
IMAGE_REGISTRY := ghcr.io/xigxog
IMAGE := $(IMAGE_REGISTRY)/vault:$(VAULT_VERSION)-$(GIT_REF)


.PHONY: all
all: clean bin

.PHONY: push
push: image
	buildah push "$(IMAGE)"

.PHONY: image
image: bin
	$(eval container=$(shell buildah from docker.io/hashicorp/vault:$(VAULT_VERSION)))
	buildah run $(container) -- /bin/sh -c "\
		apk add --no-cache jq && \
		wget -O /usr/bin/kubectl "https://dl.k8s.io/release/$$(wget -q -O - https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
		chmod +x /usr/bin/kubectl"
	buildah add $(container) "$(TARGET_DIR)/*" "/xigxog/vault/plugins/"
	buildah commit $(container) "$(IMAGE)"

.PHONY: bin
bin: clean
	@# Use of CGO_ENABLED=0 allows use in Alpine Linux
	CGO_ENABLED=0 go build -o "$(TARGET_DIR)/$(BIN)"
	echo -n "$(GIT_REF)" > $(TARGET_DIR)/nats-plugin.version
	cd $(TARGET_DIR) && sha256sum "$(BIN)" > "$(BIN).sha256sum"

.PHONY: start
start: export VAULT_LOG_LEVEL=debug
start: bin
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(TARGET_DIR)

.PHONY: enable
enable: export VAULT_ADDR=http://127.0.0.1:8200
enable: bin
	vault login root && \
	vault secrets enable -path=nats $(BIN)

.PHONY: clean
clean:
	go clean
	rm -rf $(TARGET_DIR)

.PHONY: fmt
fmt:
	go fmt ./...
