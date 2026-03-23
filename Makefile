build-agent:
	go generate ./...
	./build.sh netledger-agent ./cmd/agent/main.go
	docker build --platform=linux/amd64 -f Dockerfile.agent -t ${REPO}/netledger-agent:${VERSION} .
	docker tag ${REPO}/netledger-agent:${VERSION} ${REPO}/netledger-agent:${HASH}

build-classifier:
	./build.sh netledger-classifier ./cmd/classifier/main.go
	docker build --platform=linux/amd64 -f Dockerfile.classifier -t ${REPO}/netledger-classifier:${VERSION} .
	docker tag ${REPO}/netledger-classifier:${VERSION} ${REPO}/netledger-classifier:${HASH}

test:
	go test ./cmd/... -v
	go test ./internal/... -v