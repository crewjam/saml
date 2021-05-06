.PHONY: help
.DEFAULT_GOAL := help

test: ## Run package tests
	@GO111MODULE=auto go test

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_\/-]+:.*?## / {printf "\033[34m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | \
	sort | \
	grep -v '#'
