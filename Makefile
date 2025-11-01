main_package_path = ./cmd/main
binary_name = go-shadowsocks2
bin_dir = ./bin


.PHONY: tidy
tidy:
	go mod tidy -v

.PHONY: test
test:
	./test/test.sh

.PHONY: build
build:
	go build -race -o $(bin_dir)/$(binary_name) $(main_package_path)
