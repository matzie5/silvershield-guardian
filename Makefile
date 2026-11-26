.PHONY: install install-gcp lint format typecheck test eval eval-live playground serve tf-init tf-validate tf-plan deploy

install:
	uv sync --extra dev

install-gcp:
	uv sync --extra dev --extra gcp

lint:
	uv run ruff check app tests

format:
	uv run ruff format app tests

typecheck:
	uv run mypy app

test:
	uv run pytest -m "not integration" -v

eval:
	uv run python tests/eval/run_golden_eval.py

eval-live:
	uv run adk eval app tests/eval/evalsets/scam_and_fake_news.evalset.json --config_file_path tests/eval/eval_config.json

playground:
	uv run adk web .

serve:
	uv run uvicorn app.fast_api_app:fast_api_app --host 0.0.0.0 --port 8080 --reload

tf-init:
	terraform -chdir=deployment/terraform init -backend=false

tf-validate:
	terraform -chdir=deployment/terraform fmt -check -recursive
	terraform -chdir=deployment/terraform validate

tf-plan:
	terraform -chdir=deployment/terraform plan -var-file=terraform.tfvars

# Compatible with Google Agent Starter Pack / google-agents-cli workflow
deploy:
	agents-cli deploy --no-confirm-project
