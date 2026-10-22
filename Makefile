VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS  := -s -w -X github.com/cpibia/tripwatch/internal/buildinfo.Version=$(VERSION) -X github.com/cpibia/tripwatch/internal/buildinfo.Commit=$(COMMIT)
COVERAGE_MIN ?= 80
BINARIES := tripwatch-sensor tripwatch-verifier
PLATFORMS := linux/amd64 linux/arm64

.PHONY: all build dist test cover lint fmt clean

all: lint test build

build:
	@mkdir -p bin
	@for b in $(BINARIES); do CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$$b ./cmd/$$b; done

# Static Linux binaries: the sensor must run on old or unpatched distributions without any dependency.
dist:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		for b in $(BINARIES); do \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$b-$$os-$$arch ./cmd/$$b || exit 1; \
		done; \
	done

test:
	go test -race ./...

cover:
	# -coverpkg counts code exercised from other packages' tests too: transport and pki are
	# tested end to end through the verifier's ingest.
	go test -race -coverpkg=./internal/... -coverprofile=coverage.out ./internal/...
	@go tool cover -func=coverage.out | awk -v min=$(COVERAGE_MIN) '/^total:/ { sub("%", "", $$3); printf "coverage %s%% (min %s%%)\n", $$3, min; if ($$3 + 0 < min) exit 1 }'

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -w .

clean:
	rm -rf bin dist coverage.out
