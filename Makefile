.PHONY: demo demo-down demo-logs bitcoind test test-e2e

demo:
	docker compose up --build

# Multi-PC: levanta solo bitcoind en PC-A (los participantes corren en sus propias máquinas)
bitcoind:
	docker compose up bitcoind

demo-down:
	docker compose down -v

demo-logs:
	docker compose logs -f

test:
	python -m pytest tests/test_protocol.py tests/test_coordinator.py -v

test-e2e:
	bash scripts/regtest_setup.sh && python -m pytest tests/test_e2e_regtest.py -v -s
