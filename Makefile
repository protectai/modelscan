.DEFAULT_GOAL := help
VERSION ?= $(shell dunamai from git --style pep440 --format "{base}.dev{distance}+{commit}")

.PHONY: env
env: ## Display information about the current environment.
	poetry env info

.PHONY: install-dev
install-dev:  ## Install all dependencies including dev and test dependencies, as well as pre-commit.
	poetry install --with dev --with test --extras "tensorflow h5py"
	pre-commit install

.PHONY: install
install: ## Install required dependencies.
	poetry install

.PHONY: install-prod
install-prod:  ## Install prod dependencies.
	poetry install --with prod

.PHONY: install-test
install-test: ## Install test dependencies.
	poetry install --with test --extras "tensorflow h5py"

.PHONY: clean
clean:  ## Uninstall modelscan
	python -m pip uninstall modelscan

.PHONY: test
test: ## Run pytests.
	poetry run pytest tests/

.PHONY: test-cov
test-cov: ## Run pytests with code coverage.
	poetry run pytest --cov=modelscan --cov-report xml:cov.xml tests/

.PHONY: build
build: ## Build the source and wheel achive.
	poetry build

.PHONY: build-prod
build-prod: version
build-prod: ## Update the version and build wheel archive.
	poetry build

.PHONY: version
version: ## Bumps the version of the project.
	echo "__version__ = '$(VERSION)'" > modelscan/_version.py
	poetry version $(VERSION)

.PHONY: lint
lint: bandit mypy
lint: ## Run all the linters.

.PHONY: bandit
bandit: ## Run SAST scanning.
	poetry run bandit -c pyproject.toml -r .

.PHONY: mypy
mypy: ## Run type checking.
	poetry run mypy --ignore-missing-imports --strict --check-untyped-defs .

.PHONY: black
format: ## Run black to format the code.
	black .


.PHONY: help
help: ## List all targets and help information.
	@grep --no-filename -E '^([a-z.A-Z_%-/]+:.*?)##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?(## ?)"}; { \
			if (length($$1) > 0) { \
				printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2; \
			} else { \
				printf "%s\n", $$2; \
			} \
		}'
