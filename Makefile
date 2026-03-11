.PHONY: demo demo-interactive demo-down demo-logs \
        multipc multipc-interactive \
        test test-ln test-e2e

# ── Una sola máquina ──────────────────────────────────────────────────────────

demo:
	docker compose up --build

demo-interactive:
	INTERACTIVE=1 docker compose run --rm -it coordinator

demo-down:
	docker compose down -v

demo-logs:
	docker compose logs -f

# ── Multi-PC (simula N PCs en una sola máquina) ────────────────────────────────

multipc:
	bash scripts/test_local_multipc.sh

multipc-interactive:
	INTERACTIVE=1 bash scripts/test_local_multipc.sh

# ── Tests ─────────────────────────────────────────────────────────────────────

test:
	python -m pytest tests/test_protocol.py tests/test_coordinator.py tests/test_lnrpc.py tests/test_api_participant_ln.py -v

test-ln:
	docker compose -f docker-compose.test.yml down --volumes
	docker compose -f docker-compose.test.yml up --build --exit-code-from test-runner

test-e2e:
	bash scripts/regtest_setup.sh && python -m pytest tests/test_e2e_regtest.py -v -s
