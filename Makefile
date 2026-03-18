.PHONY: build test lint clean install

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -X main.Version=$(VERSION) -s -w
BIN      = network-agent

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/network-agent

install:
	CGO_ENABLED=0 go install -ldflags "$(LDFLAGS)" ./cmd/network-agent

test:
	go test -race -count=1 ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

lint:
	golangci-lint run ./...

clean:
	rm -f $(BIN) coverage.out

# Cross-compile targets matching GoReleaser matrix
build-all:
	GOOS=linux   GOARCH=amd64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-amd64   ./cmd/network-agent
	GOOS=linux   GOARCH=arm64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-arm64   ./cmd/network-agent
	GOOS=darwin  GOARCH=amd64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-amd64  ./cmd/network-agent
	GOOS=darwin  GOARCH=arm64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-arm64  ./cmd/network-agent
	GOOS=windows GOARCH=amd64  CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-windows-amd64.exe ./cmd/network-agent
