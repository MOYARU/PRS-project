.PHONY: all build run clean test deps help

BINARY_NAME=prs

all: build

build: ## 바이너리 빌드 (Build the binary)
	@echo "Building..."
	go build -o $(BINARY_NAME) main.go

run: ## 애플리케이션 실행 (Run the application)
	@echo "Running..."
	go run main.go

clean: ## 빌드 아티팩트 및 리포트 제거 (Clean build artifacts and reports)
	@echo "Cleaning..."
	go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f prs_report_*.html
	rm -f prs_report_*.json

test: ## 테스트 실행 (Run tests)
	@echo "Testing..."
	go test ./...

deps: ## 의존성 다운로드 (Download dependencies)
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

help: ## 도움말 표시 (Display this help screen)
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'