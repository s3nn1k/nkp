.PHONY: build bundle fmt install lint test

build:
	@./scripts/build.sh

bundle:
	@./scripts/bundle.sh $(SECRETS)

fmt:
	gofmt -w *.go

install:
	@./scripts/install.sh

lint:
	@files="$$(gofmt -l *.go)"; [ -z "$$files" ] || { printf '%s\n' "$$files"; exit 1; }
	go vet ./...

test:
	go test ./...
