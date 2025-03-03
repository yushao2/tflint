default: build

prepare:
	go run ./plugin/stub-generator

test: prepare
	go test -timeout 5m $$(go list ./... | grep -v test-fixtures | grep -v stub-generator | grep -v integrationtest)

build:
	mkdir -p dist
	go build -v -o dist/tflint

install:
	go install

e2e: prepare install
	go test -timeout 5m ./integrationtest/...

lint:
	golangci-lint run ./...
	cd terraform/ && golangci-lint run ./...

clean:
	rm -rf dist/

generate:
	go generate ./...

.PHONY: prepare test build install e2e lint clean generate
