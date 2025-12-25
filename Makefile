vet:
	@go vet ./...

fmt:
	@go tool gofumpt -l -w -extra ./.
	@go mod tidy

staticcheck:
	@go tool staticcheck \
		-checks=all,-ST1000,-ST1001,-ST1003,-ST1005,-SA1019,-ST1020,-ST1021,-ST1022 ./...

lint: fmt
	@go tool golangci-lint run --new-from-rev=master ./...

audit: vet lint fmt staticcheck
	@go mod verify 
	@go tool govulncheck -show verbose ./...

unit-tests: audit
	@go mod download
	@go get -v ./...
	@go test -cover -race -covermode=atomic -coverprofile coverage  ./...
	@go tool cover -func=coverage
	@rm coverage

build: audit
	@go build -o sshkeyman cmd/auth/main.go
	#@CGO_CFLAGS="-O2 -D __LIB_NSS_NAME=sshkeyman" go build -ldflags '-s' --buildmode=c-shared -o libnss_sshkeyman.so.2 cmd/nss/lib.go
	@gcc -fPIC -shared -o libnss_sshkeyman.so.2 library/sshkeyman.c

install: build
	sudo cp libnss_sshkeyman.so.2 /usr/lib/x86_64-linux-gnu/libnss_sshkeyman.so.2
	sudo cp sshkeyman /usr/bin/sshkeyman
	sudo mkdir -p /var/lib/sshkeyman
	#sudo cp -rf nss_sshkeyman.conf /etc/nss_sshkeyman.conf

package: build
	mkdir -p dist
	mv libnss_sshkeyman.so.2 dist
	mv sshkeyman dist
	mv install.sh dist
	docker run --rm -v ./dist:/dist realtimeneil/makeself:latest ./dist /sshkeyman.run "sshkeyman install" ./install.sh
