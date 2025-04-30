SERVICE_NAME=snowflizzle
BINARY=$(SERVICE_NAME)

BASE_DIR=$(CURDIR)

.PHONY: all build clean image

all: build

build: $(BINARY)

clean:
	rm -f $(BINARY)

$(BINARY): $(shell find $(BASE_DIR) -name '*.go')
	CGO_ENABLED=0 go build -o $(BASE_DIR)/$(BINARY)

image:
	docker build -t $(SERVICE_NAME) .

image-dev:
	docker build -t $(SERVICE_NAME):dev --target=dev .

test:
	go test -v race ./...
