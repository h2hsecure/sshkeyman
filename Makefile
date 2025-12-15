build: audit
	go build -o sshkeyman cmd/auth/main.go
	CGO_CFLAGS="-g -O2 -D __LIB_NSS_NAME=sshkeyman" go build -ldflags '-s' --buildmode=c-shared -o libnss_sshkeyman.so.2 cmd/nss/lib.go

install: build
	 sudo cp libnss_sshkeyman.so.2 /usr/lib/x86_64-linux-gnu/libnss_sshkeyman.so.2
	 sudo cp sshkeyman /usr/bin/sshkeyman
	 sudo mkdir -p /var/lib/sshkeyman
	 sudo cp -rf nss_sshkeyman.conf /etc/nss_sshkeyman.conf

vet:
	@go vet ./...

lint: fmt
	@golangci-lint run --new-from-rev=master ./...

fmt:
	@go install mvdan.cc/gofumpt@v0.5.0
	@gofumpt -l -w -extra ./.
	@go install github.com/daixiang0/gci@v0.11.0
	@go mod tidy

audit: vet lint fmt staticcheck
	go mod verify && \
	go tool govulncheck -show verbose ./...

staticcheck:
	go tool staticcheck \
		-checks=all,-ST1000,-ST1001,-ST1003,-ST1005,-SA1019,-ST1020,-ST1021,-ST1022 ./...

unit-tests: audit
	@go mod download
	@go get -v ./...
	@go test -cover -race -covermode=atomic -coverprofile coverage  ./...
	@go tool cover -func=coverage
	@rm coverage