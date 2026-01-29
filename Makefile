.PHONY: build run test generate clean

build:
	go build -o bin/api ./cmd/api

run:
	air

run-direct:
	go run ./cmd/api

generate: generate-openapi generate-sqlc

generate-openapi:
	oapi-codegen --config oapi-codegen.yaml api/openapi.yaml

generate-sqlc:
	sqlc generate

test:
	go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

migrate-up:
	migrate -path db/migrations -database "postgres://app_user:$$DB_PASSWORD@localhost:6432/bfc_vpn?sslmode=require" up

migrate-down:
	migrate -path db/migrations -database "postgres://app_user:$$DB_PASSWORD@localhost:6432/bfc_vpn?sslmode=require" down 1

clean:
	rm -rf bin/ tmp/ coverage.out
