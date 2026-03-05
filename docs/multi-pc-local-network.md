# Demo multi-PC en red local

Tres participantes en PCs distintos corren el protocolo tanda sobre Bitcoin regtest.
Un PC aloja `bitcoind`; cada PC aloja su propio servidor participante; el coordinador
corre en cualquiera de los tres.

## Topología

```
PC-A (192.168.1.10)  — bitcoind  +  P0  +  coordinador
PC-B (192.168.1.11)  — P1
PC-C (192.168.1.12)  — P2
```

Ajusta las IPs al rango de tu red local.

---

## Prerequisitos (los 3 PCs)

- Python 3.10+
- Git
- PC-A además necesita Docker (solo para bitcoind)

```bash
git clone <repo-url> tanda-btc
cd tanda-btc
pip install -r requirements.txt -r requirements-demo.txt
```

---

## Paso 1 — PC-A: arrancar bitcoind

Solo levantamos el servicio `bitcoind` del compose. Los participantes
corren directamente en cada PC — sin contenedor.

```bash
make bitcoind
# equivalente: docker compose up bitcoind
```

Verificar que está listo:

```bash
docker compose exec bitcoind bitcoin-cli -datadir=/data/.bitcoin getblockchaininfo
```

---

## Paso 2 — Cada PC arranca su servidor participante

Cada servidor genera su clave privada a partir de `SK_SEED` (sha256 del string).
El coordinador solo necesita las claves públicas — los secretos nunca salen del PC.

**PC-A — P0:**

```bash
SK_IDX=0 \
SK_SEED=participant_0_key \
BITCOIND_RPC_URL=http://user:password@192.168.1.10:18443 \
uvicorn tanda.api_participant:app --host 0.0.0.0 --port 8080
```

**PC-B — P1:**

```bash
SK_IDX=1 \
SK_SEED=participant_1_key \
BITCOIND_RPC_URL=http://user:password@192.168.1.10:18443 \
uvicorn tanda.api_participant:app --host 0.0.0.0 --port 8080
```

**PC-C — P2:**

```bash
SK_IDX=2 \
SK_SEED=participant_2_key \
BITCOIND_RPC_URL=http://user:password@192.168.1.10:18443 \
uvicorn tanda.api_participant:app --host 0.0.0.0 --port 8080
```

Verificar que los tres responden:

```bash
curl http://192.168.1.10:8080/health
curl http://192.168.1.11:8080/health
curl http://192.168.1.12:8080/health
# → {"status":"ok","idx":N,"pubkey_hex":"..."}
```

---

## Paso 3 — PC-A: configurar el coordinador

El script `run_coordinator.py` lee las URLs de los participantes desde variables de
entorno. Añade estas líneas a tu shell o a un archivo `.env.local`:

```bash
export BITCOIND_RPC_URL=http://user:password@192.168.1.10:18443
export P0_URL=http://192.168.1.10:8080
export P1_URL=http://192.168.1.11:8080
export P2_URL=http://192.168.1.12:8080
export AMOUNT_BTC=0.1
export T_CLAIM=5
export T_REFUND=10
```

Para que `run_coordinator.py` use estas variables, edita las tres líneas de `P_URLS`:

```python
# scripts/run_coordinator.py
P_URLS = [
    os.environ.get("P0_URL", "http://p0:8080"),
    os.environ.get("P1_URL", "http://p1:8080"),
    os.environ.get("P2_URL", "http://p2:8080"),
]
```

Alternativa sin tocar el código: agregar entradas en `/etc/hosts` de PC-A:

```
192.168.1.10  p0
192.168.1.11  p1
192.168.1.12  p2
```

---

## Paso 4 — PC-A: correr el coordinador

```bash
python scripts/run_coordinator.py
```

Salida esperada:

```
Waiting for bitcoind...
  bitcoind ready
Waiting for http://p0:8080...
  http://p0:8080 ready  pubkey=02a1b2c3d4e5f6...
Waiting for http://p1:8080...
  http://p1:8080 ready  pubkey=03f1e2d3c4b5a6...
Waiting for http://p2:8080...
  http://p2:8080 ready  pubkey=02c3d4e5f6a7b8...

--- Bootstrap ---
Mining 101 blocks to coordinator wallet...
Funding participants (5 BTC each)...
  Sent 5 BTC → P0 (bcrt1p...)
  Sent 5 BTC → P1 (bcrt1p...)
  Sent 5 BTC → P2 (bcrt1p...)

--- Tanda Setup ---
Setup distributed to all participants.

=== Round 0: Cooperative MuSig2 (P0 wins) ===
  Requesting contributions...
    P0 txid=a1b2c3d4e5f6...
    P1 txid=b2c3d4e5f6a7...
    P2 txid=c3d4e5f6a7b8...
  MuSig2 signing...
    input 0 signed
    input 1 signed
    input 2 signed
  ✓ P0 claimed pot. txid=d4e5f6a7b8c9...

=== Round 1: HTLC fallback (P1 wins, P0 refuses) ===
  ...
  ✓ P1 claimed via HTLC. txid=e5f6a7b8c9d0...

=== Round 2: Collective refund (P2 disappears) ===
  ...
  ✓ Refund broadcast. txid=f6a7b8c9d0e1...

✓ All 3 rounds complete.
```

---

## Puertos a abrir en el firewall

| PC | Puerto | Quién lo usa |
|----|--------|--------------|
| PC-A | 18443 | P0, P1, P2, coordinador (bitcoind RPC) |
| PC-A | 8080 | coordinador (servidor P0) |
| PC-B | 8080 | coordinador (servidor P1) |
| PC-C | 8080 | coordinador (servidor P2) |

```bash
# Linux (ufw) — ejecutar en cada PC
sudo ufw allow 8080/tcp

# PC-A también necesita exponer bitcoind
sudo ufw allow 18443/tcp
```

---

## Qué hace cada ronda

| Ronda | Ganador | Camino de gasto | Qué se simula |
|-------|---------|-----------------|---------------|
| 0 | P0 | keypath MuSig2 | Todos cooperan; firma agregada en una sola tx |
| 1 | P1 | leaf1 HTLC | P0 "rechaza" firmar; P1 revela preimage tras `T_CLAIM` bloques |
| 2 | P2 | leaf2 refund | P2 "desaparece"; P0 y P1 recuperan fondos tras `T_REFUND` bloques |

---

## Notas de seguridad

- `SK_SEED` es la semilla de la clave privada. En este demo es un string predecible
  compartido en la documentación — **suficiente para regtest, nunca usar en mainnet**.
- En un despliegue real cada participante generaría su propia clave (`secrets.token_bytes(32)`)
  y compartiría solo la clave pública con el coordinador.
- `bitcoind` está configurado con `rpcallowip=0.0.0.0/0` para simplificar el demo.
  En producción restringir al rango de la red local (`192.168.1.0/24`).
