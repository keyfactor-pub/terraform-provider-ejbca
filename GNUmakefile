PROVIDER_DIR := $(PWD)
TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=registry.terraform.io
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
	@echo "Building ${BINARY}..."
	@go build -o ${BINARY}
	@echo "Installing ${BINARY} into ${INSTALLDIR}..."
	@rm -rf ${INSTALLDIR}
	@mkdir -p ${INSTALLDIR}
	@mv ${BINARY} ${INSTALLDIR}
	@rm .terraform.lock.hcl || true
	@echo "Upgrading Terraform..."
	terraform init -upgrade

local-config:
	@echo "Modifying CLI Configuration File to use local provider..."
	@if [ ! -f ~/.terraformrc ]; then \
  		echo "Creating ~/.terraformrc..."; \
		touch ~/.terraformrc; \
	fi

	@grep -q "filesystem_mirror" ~/.terraformrc || ( \
		echo "Configuring .terraformrc for local installation..."; \
		echo "provider_installation {" >> ~/.terraformrc; \
		echo "  filesystem_mirror {" >> ~/.terraformrc; \
		echo "    path    = \"/Users/$(shell whoami)/.terraform.d/plugins\"" >> ~/.terraformrc; \
		echo "    include = [\"${HOSTNAME}/${NAMESPACE}/${NAME}\"]" >> ~/.terraformrc; \
		echo "  }" >> ~/.terraformrc; \
		echo "  direct {" >> ~/.terraformrc; \
		echo "    exclude = [\"${HOSTNAME}/${NAMESPACE}/${NAME}\"]" >> ~/.terraformrc; \
		echo "  }" >> ~/.terraformrc; \
		echo "}" >> ~/.terraformrc; \
		echo ".terraformrc configured successfully!"; \
	)

	@echo "Done configuring .terraformrc"

uninstall-local:
	@echo "Removing ${INSTALLDIR}..."
	@rm -rf ${INSTALLDIR}
	@if [ -f ~/.terraformrc ]; then \
		echo "Removing configuration from .terraformrc..."; \
		awk 'BEGIN {flag=0; braces=0} /provider_installation {/{flag=1; braces=1; next} flag && /{/{braces++} flag && /}/{braces--} flag && braces == 0 {flag=0; next} !flag {print}' ~/.terraformrc > ~/.terraformrc.tmp && mv ~/.terraformrc.tmp ~/.terraformrc; \
		echo "Configuration removed successfully!"; \
	else \
		echo "~/.terraformrc not found!"; \
	fi
	@echo "Done."

.PHONY: testacc install