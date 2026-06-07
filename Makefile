.PHONY: build test lint run clean

BINARY_NAME=gonet
BUILD_DIR=bin

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gonet

test:
	go test -v ./...

lint:
	golangci-lint run

run: build
	sudo ./$(BUILD_DIR)/$(BINARY_NAME) start

clean:
	rm -rf $(BUILD_DIR)
	go clean
