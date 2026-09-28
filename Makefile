.PHONY: help up down logs run build test test-integration lint tidy fmt

COMPOSE := docker compose -f deployments/docker-compose.yml

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Start postgres, redis and nats
	$(COMPOSE) up -d

down: ## Stop the dependencies and drop their volumes
	$(COMPOSE) down -v

logs: ## Tail dependency logs
	$(COMPOSE) logs -f

run: ## Run the API against the local dependencies
	go run ./cmd/app

build: ## Compile the binary into bin/day-journal
	go build -o bin/day-journal ./cmd/app

test: ## Run the unit tests (no containers needed)
	go test ./... -race -count=1

TEST_POSTGRES_DSN ?= postgres://journal:journal@localhost:5432/day_journal?sslmode=disable
test-integration: ## Run the Postgres adapter tests too (needs `make up`)
	TEST_POSTGRES_DSN='$(TEST_POSTGRES_DSN)' go test ./... -race -count=1

fmt: ## Format the tree
	gofmt -w .

tidy: ## Sync go.mod/go.sum
	go mod tidy

lint: ## Vet the tree
	go vet ./...
