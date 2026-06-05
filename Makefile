build-agent:
	go generate ./...
	./build.sh netledger-agent ./cmd/agent/main.go

build-classifier:
	./build.sh netledger-classifier ./cmd/classifier/main.go

test:
	go test ./cmd/... -v
	go test ./internal/... -v