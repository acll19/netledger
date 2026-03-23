build-agent:
	go generate ./...
	./build.sh netledger-agent ./cmd/agent/main.go
	docker build --platform=linux/amd64 -f Dockerfile.agent -t netledger-agent:${VERSION} .
	docker tag netledger-agent:${VERSION} netledger-agent:${HASH}

build-classifier:
	./build.sh netledger-classifier ./cmd/classifier/main.go
	docker build --platform=linux/amd64 -f Dockerfile.classifier -t netledger-classifer:${VERSION} .
	docker tag netledger-classifer:${VERSION} netledger-classifer:${HASH}

test:
	go test ./cmd/... -v
	go test ./internal/... -v