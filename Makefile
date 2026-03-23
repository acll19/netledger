build-agent:
	go generate ./...
	./build.sh netledger-agent ./cmd/agent/main.go
	docker build --platform=linux/amd64 -f Dockerfile.agent -t ${REPO}/netledger-agent:${VERSION} .

build-classifier:
	./build.sh netledger-classifier ./cmd/classifier/main.go
	docker build --platform=linux/amd64 -f Dockerfile.classifier -t ${REPO}/netledger-classifier:${VERSION} .

test:
	go test ./cmd/... -v
	go test ./internal/... -v