.PHONY: build dist test lint install-local uninstall-local kandji-syntax release-plan

VERSION ?= dev

build: ## Build the trustguard-copilot hook binary into ./bin/
	@mkdir -p bin
	go build -buildvcs=false -trimpath -ldflags "-s -w" -o bin/trustguard-copilot ./cli

dist: ## Cross-compile every release binary into ./dist/ (VERSION=X.Y.Z)
	@scripts/build-dist.sh $(VERSION)

test: ## Run the test suite
	go test -race ./cli/

lint: ## Vet the sources
	go vet ./cli/

kandji-syntax: ## Shell-check Kandji MDM scripts (bash; they are not POSIX sh)
	@bash -n mdm/kandji/install-trustguard-copilot.sh
	@bash -n mdm/kandji/audit-trustguard-copilot.sh
	@echo "kandji scripts: syntax ok"

release-plan: ## Print what the Release workflow would do (mode + version)
	@python3 scripts/release.py plan

# Install the binary for local plugin testing.
install-local: build ## Install binary to ~/.trustguard/bin for local testing
	@mkdir -p "$(HOME)/.trustguard/bin"
	@cp bin/trustguard-copilot "$(HOME)/.trustguard/bin/trustguard-copilot"
	@chmod 0755 "$(HOME)/.trustguard/bin/trustguard-copilot" trustguard/hooks/trustguard-hook.sh
	@echo "installed $(HOME)/.trustguard/bin/trustguard-copilot"
	@echo "run: copilot plugin install $(CURDIR)/trustguard"
	@echo "or:  copilot plugin marketplace add $(CURDIR)"
	@echo "config: ~/.trustguard/copilot.json  (see README)"

uninstall-local: ## Remove the locally installed binary
	@rm -f "$(HOME)/.trustguard/bin/trustguard-copilot"
	@echo "removed local trustguard-copilot binary"
