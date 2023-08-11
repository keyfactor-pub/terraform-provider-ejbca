PROVIDER_DIR := $(PWD)
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=keyfactor.com
GOFMT_FILES  := $$(find $(PROVIDER_DIR) -name '*.go' |grep -v vendor)
NAMESPACE=keyfactor-pub
NAME=ejbca
BINARY=terraform-provider-${NAME}
VERSION=1.0.0
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
BASEDIR := ~/.terraform.d/plugins
INSTALLDIR := ${BASEDIR}/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

default: testacc

# Run acceptance tests
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

install:
	go build -o ${BINARY}
	rm -rf ${INSTALLDIR}
	mkdir -p ${INSTALLDIR}
	mv ${BINARY} ${INSTALLDIR}
	rm .terraform.lock.hcl || true
	terraform init -upgrade

.PHONY: testacc install