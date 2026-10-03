GO ?= go

.PHONY: build test unit integration fmt vet demo clean

build:
	./scripts/build.sh

test:
	$(GO) test ./...

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
