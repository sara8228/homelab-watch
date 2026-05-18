.PHONY: test audit help

help:
	@echo "Available targets:"
	@echo "  make test   - pytest を実行"
	@echo "  make audit  - pip-audit で依存脆弱性スキャン"

test:
	.venv/bin/pytest

audit:
	.venv/bin/pip-audit
