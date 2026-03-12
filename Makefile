.PHONY: demo demo-interactive demo-down demo-logs \
        multipc multipc-interactive \
        coord coord-run coord-down \
        participant participant-down \
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

# ── Multi-PC real (una máquina por participante en red local) ─────────────────
#
# PC-Coord:
#   make coord                          # levanta bitcoind + cln-coordinator
#   N_PARTICIPANTS=3 \
#   P0_URL=http://192.168.1.11:8080 \
#   P0_CLN_HOST=192.168.1.11 \
#   P1_URL=http://192.168.1.12:8080 \
#   P1_CLN_HOST=192.168.1.12 \
#   P2_URL=http://192.168.1.13:8080 \
#   P2_CLN_HOST=192.168.1.13 \
#     make coord-run                    # abre canales + corre N rondas
#
# Cada PC participante (sustituir 192.168.1.10 por IP del coordinador):
#   BITCOIND_HOST=192.168.1.10 make participant

coord:
	docker compose -f deploy/coord.yml -f deploy/coord.local.yml up --build -d

coord-run:
	docker compose \
	  -f deploy/coord.yml \
	  -f deploy/run.yml \
	  -f deploy/run.local.yml \
	  up coordinator

coord-down:
	docker compose -f deploy/coord.yml down -v

participant:
	docker compose -f deploy/participant.yml up --build -d

participant-down:
	docker compose -f deploy/participant.yml down -v

# ── Tests ─────────────────────────────────────────────────────────────────────

test:
	python -m pytest tests/test_protocol.py tests/test_coordinator.py tests/test_lnrpc.py tests/test_api_participant_ln.py -v

test-ln:
	docker compose -f docker-compose.test.yml down --volumes
	docker compose -f docker-compose.test.yml up --build --exit-code-from test-runner

test-e2e:
	bash scripts/regtest_setup.sh && python -m pytest tests/test_e2e_regtest.py -v -s
