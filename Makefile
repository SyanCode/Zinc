.PHONY: build test vet run
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o zinc .
test:
	go test -race -count=1 ./...
vet:
	go vet ./...
run: build
	./zinc serve
