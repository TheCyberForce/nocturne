.PHONY: build test e2e
build:
	go build -trimpath -ldflags="-s -w" -o bin/noc ./cmd/noc
test:
	go test ./...
e2e: build
	unshare -Urnm scripts/netns-test.sh
