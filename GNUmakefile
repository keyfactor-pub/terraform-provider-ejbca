DIR := ${CURDIR}

# There is no reason GOROOT should be set anymore. Unset it so it doesn't mess
# with our go toolchain detection/usage.
ifneq ($(GOROOT),)
	export GOROOT=
endif

E:=@
ifeq ($(V),1)
	E=
endif

cyan := $(shell which tput > /dev/null && tput setaf 6 2>/dev/null || echo "")
reset := $(shell which tput > /dev/null && tput sgr0 2>/dev/null || echo "")
bold  := $(shell which tput > /dev/null && tput bold 2>/dev/null || echo "")

.PHONY: default all help

default: build

all: build lint test

help:
	@echo "$(bold)Usage:$(reset) make $(cyan)<target>$(reset)"
	@echo
	@echo "$(bold)Build:$(reset)"
	@echo "  $(cyan)build$(reset)                                 - build the ejbca terraform provider binary (default)"
	@echo
	@echo "$(bold)Test:$(reset)"
	@echo "  $(cyan)test$(reset)                                  - run unit tests"
	@echo "  $(cyan)race-test$(reset)                             - run unit tests with race detection"
	@echo "  $(cyan)testacc$(reset)                               - run terraform acceptance tests"
	@echo
	@echo "$(bold)Lint:$(reset)"
	@echo "  $(cyan)lint$(reset)                                  - lint the code and markdown files"
	@echo "  $(cyan)lint-code$(reset)                             - lint the code"
	@echo "  $(cyan)lint-md$(reset)                               - lint markdown files"
	@echo
	@echo "$(bold)Build, lint and test:$(reset)"
	@echo "  $(cyan)all$(reset)                                   - build the ejbca terraform binary, run linters and unit tests"

# Used to force some rules to run every time
FORCE: ;

############################################################################
# OS/ARCH detection
############################################################################
os1=$(shell uname -s)
os2=
ifeq ($(os1),Darwin)
os1=darwin
os2=osx
else ifeq ($(os1),Linux)
os1=linux
os2=linux
else ifeq (,$(findstring MYSYS_NT-10-0-, $(os1)))
os1=windows
os2=windows
else
$(error unsupported OS: $(os1))
endif

arch1=$(shell uname -m)
ifeq ($(arch1),x86_64)
arch2=amd64
else ifeq ($(arch1),aarch64)
arch2=arm64
else ifeq ($(arch1),arm64)
arch2=arm64
else ifeq ($(arch1),s390x)
arch2=s390x
else ifeq ($(arch1),ppc64le)
arch2=ppc64le
else
$(error unsupported ARCH: $(arch1))
endif

############################################################################
# Vars
############################################################################

binary := terraform-provider-ejbca

build_dir := $(DIR)/.build/$(os1)-$(arch1)

go_version := $(shell cat .go-version)
go_dir := $(build_dir)/go/$(go_version)
tool_versions := $(shell cat .tool-versions)

ifeq ($(os1),windows)
	go_bin_dir = $(go_dir)/go/bin
	go_url = https://go.dev/dl/go$(go_version).$(os1)-$(arch2).zip
	exe=".exe"
else
	go_bin_dir = $(go_dir)/bin
	go_url = https://go.dev/dl/go$(go_version).$(os1)-$(arch2).tar.gz
	exe=
endif

go_path := PATH="$(go_bin_dir):$(PATH)"

golangci_lint_version := $(shell echo "$(tool_versions)" | tr ' ' '\n' | awk '/golangci_lint/{getline; print}')

golangci_lint_dir = $(build_dir)/golangci_lint/$(golangci_lint_version)
golangci_lint_bin = $(golangci_lint_dir)/golangci-lint
golangci_lint_cache = $(golangci_lint_dir)/cache

markdown_lint_version := $(shell echo "$(tool_versions)" | tr ' ' '\n' | awk '/markdown_lint/{getline; print}')
markdown_lint_image = ghcr.io/igorshubovych/markdownlint-cli:$(markdown_lint_version)

# There may be more than one tag. Only use one that starts with 'v' followed by
# a number, e.g., v0.9.3.
git_tag := $(shell git tag --points-at HEAD | grep '^v[0-9]*')
git_hash := $(shell git rev-parse --short=7 HEAD)
git_dirty := $(shell git status -s)

# The following vars are used in rule construction
comma := ,
null  :=
space := $(null) #

#############################################################################
# Utility functions
#############################################################################

tolower = $(shell echo $1 | tr '[:upper:]' '[:lower:]')

goenv = $(shell PATH="$(go_bin_dir):$(PATH)" go env $1)

############################################################################
# Determine go flags
############################################################################

# Flags passed to all invocations of go test
go_test_flags :=
ifeq ($(NIGHTLY),)
	# Cap unit-test timout to 90s unless we're running nightlies.
	go_test_flags += -timeout=90s
endif

go_flags :=
ifneq ($(GOPARALLEL),)
	go_flags += -p=$(GOPARALLEL)
endif

ifneq ($(GOVERBOSE),)
	go_flags += -v
endif

# Determine the ldflags passed to the go linker. The git tag and hash will be
# provided to the linker unless the git status is dirty.
go_ldflags := -s -w

#############################################################################
# Build Targets
#############################################################################

.PHONY: build
build: tidy bin/$(binary)

go_build := $(go_path) CGO_ENABLED=0 go build $(go_flags) -ldflags '$(go_ldflags)' -o

bin/$(binary): | go-check
	@echo Building $@…
	$(E)$(go_build) $@$(exe) ./main.go

#############################################################################
# Test Targets
#############################################################################

.PHONY: test race-test integration

test: | go-check
ifneq ($(COVERPROFILE),)
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) -covermode=atomic -coverprofile="$(COVERPROFILE)" ./...
else
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) ./...
endif

race-test: | go-check
ifneq ($(COVERPROFILE),)
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) -race -coverprofile="$(COVERPROFILE)" ./...
else
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) -race ./...
endif

testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

#############################################################################
# Code cleanliness
#############################################################################

.PHONY: tidy tidy-check lint lint-code
tidy: | go-check
	$(E)$(go_path) go mod tidy

tidy-check:
ifneq ($(git_dirty),)
	$(error tidy-check must be invoked on a clean repository)
endif
	@echo "Running go tidy..."
	$(E)$(MAKE) tidy
	@echo "Ensuring git repository is clean..."
	$(E)$(MAKE) git-clean-check

lint: lint-code lint-md

lint-code: $(golangci_lint_bin)
	$(E)PATH="$(go_bin_dir):$(PATH)" GOLANGCI_LINT_CACHE="$(golangci_lint_cache)" $(golangci_lint_bin) run ./...

lint-md:
	@echo ""
	$(E)docker run --rm -v "$(DIR):/workdir" $(markdown_lint_image) "**/*.md"

#############################################################################
# Toolchain
#############################################################################

# go-check checks to see if there is a version of Go available matching the
# required version. The build cache is preferred. If not available, it is
# downloaded into the build cache. Any rule needing to invoke tools in the go
# toolchain should depend on this rule and then prepend $(go_bin_dir) to their
# path before invoking go or use $(go_path) go which already has the path prepended.
# Note that some tools (e.g. anything that uses golang.org/x/tools/go/packages)
# execute on the go binary and also need the right path in order to locate the
# correct go binary.
go-check:
ifeq (go$(go_version), $(shell $(go_path) go version 2>/dev/null | cut -f3 -d' '))
else ifeq ($(os1),windows)
	@echo "Installing go$(go_version)..."
	$(E)rm -rf $(dir $(go_dir))
	$(E)mkdir -p $(go_dir)
	$(E)curl -o $(go_dir)\go.zip -sSfL $(go_url)
	$(E)unzip -qq $(go_dir)\go.zip -d $(go_dir)
else
	@echo "Installing go$(go_version)..."
	$(E)rm -rf $(dir $(go_dir))
	$(E)mkdir -p $(go_dir)
	$(E)curl -sSfL $(go_url) | tar xz -C $(go_dir) --strip-components=1
endif

go-bin-path: go-check
	@echo "$(go_bin_dir):${PATH}"

install-golangci-lint: $(golangci_lint_bin)

$(golangci_lint_bin): | go-check
	@echo "Installing golangci-lint $(golangci_lint_version)..."
	$(E)rm -rf $(dir $(golangci_lint_dir))
	$(E)mkdir -p $(golangci_lint_dir)
	$(E)mkdir -p $(golangci_lint_cache)
	$(E)GOBIN=$(golangci_lint_dir) $(go_path) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_lint_version)
