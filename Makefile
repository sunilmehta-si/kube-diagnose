# kube-diagnose: make test runs what CI's test job runs.
GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/sunilmehta-si/kube-diagnose/internal/cli.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test vuln docs dist

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/kube-diagnose ./cmd/kube-diagnose

test:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# Rewrite docs/rules.md from the rule catalogue after adding or changing a rule.
docs:
	$(GO) test ./internal/diagnose -run TestRulesDocIsCurrent -update-docs

# Release binaries for every platform, with checksums. Each archive holds kube-diagnose and kubectl-diagnose.
dist:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		mkdir -p dist/$$os-$$arch && \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/$$os-$$arch/kube-diagnose$$ext ./cmd/kube-diagnose || exit 1; \
		cp dist/$$os-$$arch/kube-diagnose$$ext dist/$$os-$$arch/kubectl-diagnose$$ext; \
		tar -czf dist/kube-diagnose-$(VERSION)-$$os-$$arch.tar.gz -C dist/$$os-$$arch . || exit 1; \
	done
	cd dist && (sha256sum kube-diagnose-$(VERSION)-*.tar.gz 2>/dev/null || shasum -a 256 kube-diagnose-$(VERSION)-*.tar.gz) > checksums.txt
