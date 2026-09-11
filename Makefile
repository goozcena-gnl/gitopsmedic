PYTHON ?= python
REPLACEMENT_IMAGE ?=
override REPLACEMENT_IMAGE := $(value REPLACEMENT_IMAGE)
export REPLACEMENT_IMAGE
export PYTHONPATH := src

.PHONY: test eval demo demo-llm scan propose compile observability-up observability-down model-up model-pull clean

test:
	$(PYTHON) -m unittest discover -s tests -v

eval:
	$(PYTHON) scripts/run_evals.py

compile:
	$(PYTHON) -m compileall -q src scripts tests

demo:
	@set --; \
	if [ -n "$$REPLACEMENT_IMAGE" ]; then set -- --replacement-image "$$REPLACEMENT_IMAGE"; fi; \
	$(PYTHON) -m gitops_medic demo "$$@"

demo-llm:
	@set --; \
	if [ -n "$$REPLACEMENT_IMAGE" ]; then set -- --replacement-image "$$REPLACEMENT_IMAGE"; fi; \
	$(PYTHON) -m gitops_medic demo --llm "$$@"

scan:
	$(PYTHON) -m gitops_medic scan examples/insecure/deployment.json

propose:
	@set --; \
	if [ -n "$$REPLACEMENT_IMAGE" ]; then set -- --replacement-image "$$REPLACEMENT_IMAGE"; fi; \
	$(PYTHON) -m gitops_medic propose examples/insecure/deployment.json "$$@"

observability-up:
	docker compose --profile observability up -d lgtm

observability-down:
	docker compose --profile observability down

model-up:
	docker compose --profile ai up -d ollama

model-pull:
	docker compose --profile ai exec ollama ollama pull qwen3:4b

clean:
	rm -rf .gitops-medic
