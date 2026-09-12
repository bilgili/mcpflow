PUBLISH_URL ?= 

.PHONY: build publish docker-build docker-build-local test

build:
	uv build

publish: build
	uv publish --publish-url $(PUBLISH_URL) dist/*

docker-build:
	docker build -t mcpflow:latest .

docker-build-local:
	uv build && docker build --build-context wheels=./dist -t mcpflow:dev .

test:
	pytest
