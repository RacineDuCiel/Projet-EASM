# Makefile for EASM Project

.PHONY: help build up down logs shell-backend shell-worker clean

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build or rebuild services
	docker-compose build

up: ## Start services in detached mode
	docker-compose up -d

down: ## Stop and remove containers, networks
	docker-compose down

logs: ## View output from containers
	docker-compose logs -f

shell-backend: ## Access the backend container shell
	docker-compose exec backend /bin/bash

shell-worker: ## Access the worker_discovery container shell
	docker-compose exec worker_discovery /bin/bash

clean: ## Remove stopped containers and unused images
	docker-compose down -v --remove-orphans
	docker system prune -f
