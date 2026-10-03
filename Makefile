GO ?= go

.PHONY: build test unit integration fmt vet demo clean

build:
	./scripts/build.sh

# -count=1 because the integration suite builds the plugin from source, which
# the go test cache does not track.
test:
	$(GO) test ./... -count=1

unit:
	$(GO) test ./internal/...

integration:
	$(GO) test ./test/integration/ -count=1 -v

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

demo:
	./scripts/demo.sh

clean:
	rm -rf bin
