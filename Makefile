# Package index to publish to, e.g. https://upload.pypi.org/legacy/
# No default: `make publish` refuses to run until you set it.
PUBLISH_URL ?=

.PHONY: build publish docker-build docker-build-local test

build:
	uv build

publish: build
	@test -n "$(PUBLISH_URL)" || { echo "PUBLISH_URL is not set; pass make publish PUBLISH_URL=<index url>"; exit 1; }
	uv publish --publish-url $(PUBLISH_URL) dist/*

docker-build:
	docker build -t mcpflow:latest .

docker-build-local:
	uv build && docker build --build-context wheels=./dist -t mcpflow:dev .

test:
	pytest
