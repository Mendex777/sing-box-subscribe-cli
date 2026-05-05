APP := sbs
PKG := ./cmd/sbs
DIST := dist

.PHONY: build build-linux-amd64 build-linux-arm64 release clean

build:
	go build -o $(APP) $(PKG)

build-linux-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(APP)-linux-amd64 $(PKG)

build-linux-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(APP)-linux-arm64 $(PKG)

release: build-linux-amd64 build-linux-arm64

clean:
	rm -rf $(DIST) $(APP)
