# Tanda LN — N participantes en red local

Tutorial para correr el protocolo tanda sobre Lightning Network con N participantes,
tanto en una sola máquina (desarrollo) como distribuido en varias PCs de la misma red local.

---

## Arquitectura

Cada participante necesita:

- Un **nodo CLN** propio con el plugin `hold` (BoltzExchange/hold) instalado.
- Un **servidor FastAPI** que habla con su nodo CLN vía socket unix.

El coordinador necesita:

- Su propio **nodo CLN** para emitir y liquidar hold invoices.
- Acceso HTTP a los servidores FastAPI de todos los participantes.

```
                    ┌──────────────────────────────┐
                    │  Coordinador CLN node         │
                    │                               │
       canal 200k   │  P0 ←──── 150k sat outbound  │
       push 150k ───┤  P1 ←──── 150k sat outbound  │
                    │  P2 ←──── 150k sat outbound  │
                    │  ...                          │
                    └──────────────────────────────┘
                              ↑
                    Bitcoin Core (regtest)
```

### Archivos Docker Compose

| Archivo | Uso |
|---|---|
| `docker-compose.yml` | Una sola máquina (demo + tests locales) |
| `docker-compose.test.yml` | Tests e2e automatizados |
| `deploy/coord.yml` | **Multi-PC** — PC-Coord: bitcoind + CLN coordinador |
| `deploy/coord.local.yml` | Override Linux para coord (extra_hosts) |
| `deploy/participant.yml` | **Multi-PC** — PC participante: CLN + API |
| `deploy/run.yml` | **Multi-PC** — PC-Coord: script coordinador |
| `deploy/run.local.yml` | Override Linux para run (extra_hosts) |

---

## Opción A — Una sola máquina (desarrollo)

```bash
# Levantar toda la infraestructura:
docker compose up --build

# Ejecutar el coordinador de forma interactiva (pausa entre rondas):
INTERACTIVE=1 docker compose run --rm -it coordinator

# O con make:
make demo
make demo-interactive
```

Ver `docs/sequence-diagrams-ln.md` para el flujo completo.

---

## Opción B — Múltiples PCs en red local

### Inicio rápido (con scripts)

**En cada PC participante** (clonar repo, un comando):

```bash
git clone <repo-url> tanda-btc && cd tanda-btc
./scripts/start_participant.sh 192.168.1.10   # IP del coordinador
```

**En PC-Coord** (un comando con las IPs de todos los participantes):

```bash
git clone <repo-url> tanda-btc && cd tanda-btc
./scripts/start_coordinator.sh 192.168.1.10 192.168.1.11 192.168.1.12

# Modo interactivo (pausa entre rondas):
INTERACTIVE=1 ./scripts/start_coordinator.sh 192.168.1.10 192.168.1.11 192.168.1.12
```

Los scripts automáticamente:
- Esperan a que `cln-coordinator` esté `healthy` antes de lanzar el coordinador.
- Exportan todas las variables de entorno necesarias (`P{i}_URL`, `P{i}_CLN_HOST`, etc.).
- En modo interactivo (`INTERACTIVE=1`), conectan `stdin` para pausar entre rondas.

---

### Prueba local (una sola máquina)

Para verificar el flujo completo antes de usar hardware real, `test_local_multipc.sh`
simula N participantes en una sola PC usando project names Docker distintos y puertos desplazados:

| Stack | CLN P2P | API HTTP |
|---|---|---|
| coord | :9735 | — |
| P0 | :9736 | :8080 |
| P1 | :9737 | :8081 |
| P2 | :9738 | :8082 |

```bash
# Básico (3 participantes, limpia al terminar):
./scripts/test_local_multipc.sh
make multipc

# Con más participantes:
N=4 ./scripts/test_local_multipc.sh

# Modo interactivo (pausa entre rondas):
INTERACTIVE=1 ./scripts/test_local_multipc.sh
make multipc-interactive

# Debug (containers quedan activos al terminar):
KEEP=1 ./scripts/test_local_multipc.sh
```

> **Nota Linux:** los overrides `deploy/coord.local.yml` y `deploy/run.local.yml`
> añaden `extra_hosts: host.docker.internal:host-gateway` para que los containers
> internos puedan comunicarse entre redes Docker distintas.
> En Mac/Windows Docker Desktop esto ya funciona sin override.

---

### Comandos manuales (referencia)

#### Topología de ejemplo (N=3)

```
PC-Coord  192.168.1.10  — bitcoind  +  cln-coordinator  +  coordinator script
PC-P0     192.168.1.10  — cln-p0   +  participant-p0 API    (puede coincidir con PC-Coord)
PC-P1     192.168.1.11  — cln-p1   +  participant-p1 API
PC-P2     192.168.1.12  — cln-p2   +  participant-p2 API
```

### Prerrequisitos (todas las PCs)

- Docker + Docker Compose v2
- `git clone <repo-url> tanda-btc && cd tanda-btc`

---

### Paso 1 — PC-Coord: bitcoind + CLN coordinador

```bash
docker compose -f deploy/coord.yml up --build -d
```

Verificar que el coordinador está listo:

```bash
docker compose -f deploy/coord.yml exec cln-coordinator \
  lightning-cli --lightning-dir=/data --network=regtest getinfo
```

---

### Paso 2 — Cada PC participante: CLN + API

```bash
# En PC-P1 (192.168.1.11):
BITCOIND_HOST=192.168.1.10 \
  docker compose -f deploy/participant.yml up --build -d

# En PC-P2 (192.168.1.12):
BITCOIND_HOST=192.168.1.10 \
  docker compose -f deploy/participant.yml up --build -d
```

`BITCOIND_HOST` apunta a la IP del PC-Coord donde corre bitcoind.

Verificar que el API de cada participante responde:

```bash
curl http://192.168.1.11:8080/health
curl http://192.168.1.12:8080/health
# → {"status":"ok","pubkey_hex":"03...","channels":[]}
```

---

### Paso 3 — PC-Coord: lanzar el coordinador

```bash
# En PC-Coord, después de que deploy/coord.yml ya esté corriendo:
N_PARTICIPANTS=3 \
P0_URL=http://192.168.1.10:8080 \
P1_URL=http://192.168.1.11:8080 \
P2_URL=http://192.168.1.12:8080 \
P0_CLN_HOST=192.168.1.10 \
P1_CLN_HOST=192.168.1.11 \
P2_CLN_HOST=192.168.1.12 \
  docker compose \
    -f deploy/coord.yml \
    -f deploy/run.yml \
    up coordinator
```

El coordinador imprime su progreso y sale al terminar las N rondas.

---

### Escalar a N=4, 5, … participantes

1. Arrancar `deploy/participant.yml` en cada PC adicional con el `BITCOIND_HOST` correcto.

2. Añadir las variables del participante extra al comando del Paso 3:

```bash
N_PARTICIPANTS=4 \
... \
P3_URL=http://192.168.1.13:8080 \
P3_CLN_HOST=192.168.1.13 \
  docker compose -f deploy/coord.yml -f deploy/run.yml up coordinator
```

`deploy/run.yml` ya declara `P3_*` y `P4_*`; el script `run_coordinator_ln.py`
lee hasta `P{N_PARTICIPANTS-1}` automáticamente.

---

## Variables de entorno del coordinador

| Variable | Descripción | Default |
|---|---|---|
| `N_PARTICIPANTS` | Número de participantes | `3` |
| `CONTRIBUTION_SATS` | Aportación por participante (sats) | `10000` |
| `BITCOIND_RPC_URL` | URL del nodo Bitcoin Core | `http://user:password@bitcoind:18443` |
| `CLN_COORDINATOR_RPC` | Socket unix del CLN coordinador | `/cln/coordinator/regtest/lightning-rpc` |
| `P{i}_URL` | URL de la API FastAPI del participante i | `http://127.0.0.1:{8080+i}` |
| `P{i}_CLN_HOST` | IP del nodo CLN del participante i (para `connect`) | `127.0.0.1` |
| `P{i}_CLN_P2P_PORT` | Puerto P2P del CLN del participante i | `9735` |

## Variables de entorno del participante

| Variable | Descripción | Default |
|---|---|---|
| `BITCOIND_HOST` | IP del PC-Coord donde corre bitcoind | `192.168.1.10` |
| `BITCOIND_PORT` | Puerto RPC de bitcoind | `18443` |
| `CLN_P2P_PORT` | Puerto P2P del nodo CLN | `9735` |
| `API_PORT` | Puerto HTTP de la API FastAPI | `8080` |

---

## Puertos a abrir en el firewall

| PC | Puerto | Quién lo usa |
|---|---|---|
| PC-Coord | 18443 | Todos → bitcoind RPC |
| PC-Coord | 9735 | Participantes → coordinador CLN P2P |
| PC-Pi | 9735 | Coordinador → participante CLN P2P (abrir canal) |
| PC-Pi | 8080 | Coordinador → participante API HTTP |

```bash
# Linux (ufw) — en PC-Coord:
sudo ufw allow from 192.168.1.0/24 to any port 18443
sudo ufw allow from 192.168.1.0/24 to any port 9735

# En cada PC participante:
sudo ufw allow from 192.168.1.0/24 to any port 9735
sudo ufw allow from 192.168.1.0/24 to any port 8080
```

---

## Verificar canales y balances

```bash
# Canales del coordinador:
docker compose -f deploy/coord.yml exec cln-coordinator \
  lightning-cli --lightning-dir=/data --network=regtest listpeerchannels

# Fondos on-chain del coordinador:
docker compose -f deploy/coord.yml exec cln-coordinator \
  lightning-cli --lightning-dir=/data --network=regtest listfunds

# Balance de un participante vía API:
curl http://192.168.1.11:8080/health | python3 -m json.tool
```

---

## Tests e2e (una sola máquina)

```bash
# Limpiar estado previo y correr tests:
docker compose -f docker-compose.test.yml down --volumes
docker compose -f docker-compose.test.yml up --build --exit-code-from test-runner

# O con make:
make test-ln
```

---

## Notas de seguridad

- `bitcoin-docker.conf` tiene `rpcallowip=0.0.0.0/0` para simplificar el demo.
  En producción restringir al rango de la LAN (`192.168.1.0/24`).
- Las claves privadas de los nodos CLN se generan automáticamente y se almacenan
  en los volúmenes Docker. No compartir ni exponer esos volúmenes.
- Para mainnet habría que usar nodos CLN reales con fondos reales y eliminar el
  `rm -rf /data/regtest` del entrypoint (ese paso es solo para tests).
