.PHONY: help install test docker docker-run release-dry
VERSION := $(shell tr -d '[:space:]' < VERSION)
IMAGE ?= cyber-posture:local
GHCR ?= ghcr.io/marctheshark3/cyber-posture

help:
	@echo "targets: install test docker docker-run release-dry"
	@echo "version: $(VERSION)"

install:
	./install.sh

test:
	python3 -m py_compile lib/cyber_posture/*.py bin/cyber-posture
	python3 -m unittest discover -s tests -v
	@for script in install.sh scripts/*.sh cron/*.sh; do bash -n "$$script" || exit; done

docker:
	docker build -t $(IMAGE) -t $(GHCR):$(VERSION) -t $(GHCR):local .

docker-run:
	CYBER_IMAGE=$(IMAGE) ./scripts/docker-run-host.sh scan

release-dry:
	@echo "Would tag v$(VERSION) and push → triggers Release workflow"
	@echo "  git tag -a v$(VERSION) -m 'Release v$(VERSION)'"
	@echo "  git push origin v$(VERSION)"
