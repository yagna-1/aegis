BINARY   := aegis
CMD      := ./cmd/aegis
VERSION  := 1.0.0
LDFLAGS  := -ldflags "-s -w -X main.Version=$(VERSION)"

.PHONY: build run-proxy run-mcp test tidy install clean

build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

install:
	go install $(LDFLAGS) $(CMD)

run-proxy: build
	./$(BINARY) -mode proxy

run-mcp: build
	./$(BINARY) -mode mcp

test:
	go test ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)

dist:
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   $(CMD)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  $(CMD)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  $(CMD)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(CMD)
