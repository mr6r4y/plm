# Makefile
SHELL := /bin/bash

.DEFAULT_GOAL := all

.PHONY: all clean

PROJECT_NAME := plm

help: ## Show help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n make \033[36m\033[0m\n"} /^[$$()% 0-9a-zA-Z_-]+:.*?##/ { printf " \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

venv:
	virtualenv -p python3 venv/
	source venv/bin/activate && pip3 install conan

CMakeUserPresets.json: venv
	source venv/bin/activate && conan profile detect --force

build/Release: export CMAKE_POLICY_VERSION_MINIMUM = 3.5
build/Release: CMakeUserPresets.json venv
	source venv/bin/activate && conan install . --settings=build_type=Release --build=missing

build/Debug: export CMAKE_POLICY_VERSION_MINIMUM = 3.5
build/Debug: CMakeUserPresets.json venv
	source venv/bin/activate && conan install . --settings=build_type=Debug --build=missing

build/Release/Makefile: build/Release
	cmake --preset conan-release

build/Debug/Makefile: build/Debug
	cmake --preset conan-debug

build/Debug/$(PROJECT_NAME): build/Debug/Makefile
	cmake --build --preset conan-debug

build/Release/$(PROJECT_NAME): build/Release/Makefile
	cmake --build --preset conan-release

clean: ## Clean all build artifacts
	rm -rf build/
	rm -rf venv/

all: ## Build the whole thing
	$(MAKE) build/Release/$(PROJECT_NAME)
	$(MAKE) build/Debug/$(PROJECT_NAME)


