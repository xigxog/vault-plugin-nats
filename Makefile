build_dir = bin
bin = nats-plugin

.PHONY: all
all: clean build

.PHONY: build
build:
	go build -o ${build_dir}/${bin}

.PHONY: release
release: clean
	@if [ -z "${VERSION}" ]; then echo "Environment variable VERSION must be set for release target"; exit 1; fi

	@# Use of CGO_ENABLED=0 allows use in Alpine Linux
	CGO_ENABLED=0 go build -o ${build_dir}/${bin}-${VERSION} -ldflags "-s -w"
	
	cd ${build_dir} && sha256sum ${bin}-${VERSION} > ${bin}-${VERSION}.sha256sum

.PHONY: start
start: export VAULT_LOG_LEVEL=debug
start: build
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=${build_dir}

.PHONY: enable
enable: export VAULT_ADDR=http://127.0.0.1:8200
enable: build
	vault login root; \
	vault secrets enable -path=nats ${bin}

.PHONY: clean
clean:
	go clean
	rm -rf ${build_dir}

.PHONY: fmt
fmt:
	go fmt ./...
