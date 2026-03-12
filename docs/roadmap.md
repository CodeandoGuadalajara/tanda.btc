# Tanda-BTC: Roadmap

---

## Parte 0 — Renovación criptográfica de tandas (implementado)

Cuando un ciclo de N rondas termina, el coordinador propone un nuevo ciclo con los
mismos términos (mismo orden, misma contribución). Cada participante firma la propuesta
con la clave de su nodo CLN antes de que el ciclo comience.

Mensaje canónico firmado:
```
tanda-renew:cycle={N}:sats={S}:coordinator={node_id}
```

El coordinador verifica la firma via `checkmessage` antes de iniciar el ciclo.
Si cualquier participante rechaza o la firma no verifica, el proceso se detiene.
Los canales LN permanecen abiertos; no se requiere ninguna operación on-chain.

**Limitación:** la prueba de aceptación la tiene solo el coordinador. Si hay disputa,
no existe árbitro externo que pueda verificarla. Ver Parte 3 para la solución.

---

## Parte 3 — Renovación vía Nostr (coordinación descentralizada)

Reemplaza el `POST /renew` HTTP con eventos Nostr firmados, publicados en relays
públicos. La aceptación de cada participante queda registrada de forma auditable y
verificable por cualquiera, sin depender del coordinador como única fuente de verdad.

### Flujo

```
Coordinador publica evento kind=30078 en relays:
  tags: [["d","tanda-renew"],["cycle","N"],["sats","S"],["coordinator","npub..."]]

Cada participante:
  1. Lee el evento del relay
  2. Publica evento kind=30078 de respuesta:
     tags: [["e","<event_id_coordinador>"],["accept","true"]]
  3. El evento está firmado con su clave Nostr

Coordinador:
  1. Espera eventos de respuesta de todos los participantes
  2. Verifica firmas Nostr (ed25519)
  3. Si todos aceptaron → inicia el ciclo
```

### Integración con Mostro

[Mostro](https://mostro.network/) es un protocolo P2P sobre Nostr + LN para comprar/vender
Bitcoin sin custodio. Los participantes que ya tienen clave Nostr para Mostro usan la
misma identidad para las tandas.

Flujo de DCA grupal con Mostro:
1. Al terminar cada ronda, el coordinador publica una orden de compra en Mostro
2. Un vendedor acepta la orden y recibe el pot vía LN
3. El ganador recibe los sats on-chain (reverse swap implícito en el protocolo Mostro)

### Archivos a crear/modificar

| Archivo | Cambio |
|---|---|
| `tanda/nostr_renewal.py` | Publicar/leer eventos de renovación en relays |
| `tanda/api_participant_ln.py` | Modo Nostr opcional via `RENEWAL_METHOD=nostr` env var |
| `scripts/run_coordinator_ln.py` | `collect_renewals_nostr()` que suscribe a eventos |
| `tests/test_nostr_renewal.py` | Unit tests con relay mock |

---

## Parte 1 — BOLT12 + Lightning Address (pagos al ganador)

Estado actual: el coordinador paga al ganador con `cln.pay(bolt11)` — la factura BOLT11
la crea el participante en el momento de la ronda. El ganador recibe **liquidez en canal**,
no un UTXO on-chain.

Permite que cada participante registre su preferencia de pago **antes** de la ronda.
El coordinador selecciona el método correcto sin cambios en el flujo de hold invoices.

### Cambios en `api_participant_ln.py`

```
GET /payment_info
```

Respuesta según `PAYMENT_METHOD` env var:

| `PAYMENT_METHOD` | Respuesta |
|---|---|
| `bolt11` (default) | `{"method":"bolt11"}` — coordinador llama `POST /create_invoice` como hasta ahora |
| `bolt12` | `{"method":"bolt12","offer":"lno1..."}` — coordinador fetches invoice del offer |
| `lnaddress` | `{"method":"lnaddress","address":"alice@domain.com"}` — coordinador resuelve LNURL-pay |

```
GET /offer          (solo si PAYMENT_METHOD=bolt12)
```

Devuelve el BOLT12 offer estático del nodo CLN (`cln.fetchinvoice` se llama desde el coordinador).

### Cambios en `lnrpc.py`

```python
CLNRpc.create_offer(amount_msat, description) -> str          # bolt12 offer
CLNRpc.fetch_invoice(offer, amount_msat, label) -> str        # bolt12 invoice desde offer
```

### Cambios en `scripts/run_coordinator_ln.py`

Nueva función `pay_winner(cln, winner_url, amount_msat, round_idx)`:

```
GET winner_url/payment_info
├── method == "bolt11"    → POST /create_invoice → cln.pay(bolt11)
├── method == "bolt12"    → cln.fetch_invoice(offer, amount_msat) → cln.pay(bolt12_inv)
└── method == "lnaddress" → resolve LNURL-pay → POST amount → cln.pay(bolt11)
```

### Variables de entorno nuevas

| Variable | Descripción | Default |
|---|---|---|
| `PAYMENT_METHOD` | `bolt11` / `bolt12` / `lnaddress` | `bolt11` |
| `LIGHTNING_ADDRESS` | `alice@domain.com` (si `lnaddress`) | — |
| `CLN_OFFER` | offer BOLT12 estático (pre-generado) | — |

### Archivos a crear/modificar

| Archivo | Cambio |
|---|---|
| `tanda/api_participant_ln.py` | `GET /payment_info`, `GET /offer` |
| `tanda/lnrpc.py` | `create_offer()`, `fetch_invoice()` |
| `scripts/run_coordinator_ln.py` | `pay_winner()` dispatcher |
| `tests/test_api_participant_ln.py` | tests para nuevos endpoints |

---

## Parte 2 — Boltz submarine swap (pago on-chain al ganador)

El ganador recibe un **UTXO on-chain** en lugar de liquidez en canal.
Mecanismo: reverse submarine swap (LN → on-chain).

```
Coordinador  ──LN──►  Boltz  ──on-chain──►  Ganador
```

Flujo:
1. Coordinador crea un reverse swap con Boltz (`create_reverse_swap`)
2. Boltz genera una factura LN y una HTLC on-chain (bloqueada con hash H)
3. Coordinador paga la factura LN → Boltz revela preimage → HTLC on-chain activa
4. El participante ganador reclama el UTXO on-chain con su firma + preimage

La garantía trustless del protocolo se preserva: el coordinador paga antes de recuperar
los hold invoices.

---

### Fase 0 — Boltz en regtest Docker

**Archivo:** `docker-compose.boltz.yml`

Componentes:
- `boltz-backend` — Boltz Core en regtest
- `boltz-lnd` o `boltz-cln` — nodo LN conectado a bitcoind regtest
- Variables: `BOLTZ_API_URL=http://boltz-backend:9001`

Resultado: `docker compose -f docker-compose.boltz.yml up` levanta Boltz local
con canales pre-financiados para pruebas.

---

### Fase 1 — `tanda/boltzrpc.py`

Wrapper sobre la Boltz REST API v2.

```python
class BoltzRpc:
    def __init__(self, base_url: str)

    def get_fee_estimate(self, pair: str) -> dict
    # GET /v2/swap/reverse/fees/{pair}

    def create_reverse_swap(
        self,
        invoice_amount_sat: int,
        on_chain_address: str,
        claim_public_key_hex: str,
        pair: str = "BTC/BTC",
    ) -> dict
    # POST /v2/swap/reverse
    # Devuelve: {id, invoice, lockup_address, redeem_script,
    #            timeout_block_height, onchain_amount}

    def get_swap_status(self, swap_id: str) -> dict
    # GET /v2/swap/{id}
    # Estados: invoice.set → transaction.mempool → transaction.confirmed →
    #          transaction.claimed / swap.expired
```

**Archivo:** `tests/test_boltzrpc.py` — unit tests con mock HTTP (no Boltz real).

---

### Fase 2 — Flujo reverse swap en el coordinador

Modificaciones en `scripts/run_coordinator_ln.py`:

```python
async def pay_winner_boltz(
    cln: CLNRpc,
    boltz: BoltzRpc,
    winner_url: str,
    amount_msat: int,
    round_idx: int,
):
    # 1. Obtener dirección on-chain + claim pubkey del ganador
    info = GET winner_url/payment_info   # method == "boltz"
    on_chain_address = info["on_chain_address"]
    claim_pubkey_hex  = info["claim_pubkey"]

    # 2. Crear reverse swap
    swap = boltz.create_reverse_swap(
        invoice_amount_sat=amount_msat // 1000,
        on_chain_address=on_chain_address,
        claim_public_key_hex=claim_pubkey_hex,
    )
    # swap.invoice  — factura LN que paga el coordinador
    # swap.lockup_address — HTLC on-chain que Boltz fondea tras recibir el pago LN

    # 3. Pagar la factura LN → Boltz fondea el HTLC on-chain
    cln.pay(swap["invoice"])

    # 4. Notificar al participante: id + redeem_script para que reclame
    POST winner_url/claim_swap {
        "swap_id": swap["id"],
        "redeem_script": swap["redeem_script"],
        "timeout_block_height": swap["timeout_block_height"],
    }
```

El coordinador paga la factura LN (paso 3) **antes** de liquidar los hold invoices,
preservando la garantía trustless.

---

### Fase 3 — `POST /claim_swap` en el participante

Nuevo endpoint en `api_participant_ln.py`:

```
POST /claim_swap
{
  "swap_id": "...",
  "redeem_script": "...",
  "timeout_block_height": N
}
```

El servidor:
1. Llama `boltz.get_swap_status(swap_id)` hasta `transaction.mempool`
2. Construye la claim transaction on-chain (P2WPKH output → `CLAIM_ADDRESS`)
3. Firma con la clave privada del participante (`CLAIM_PRIVKEY` env var)
4. Broadcast via Bitcoin RPC (`BITCOIN_RPC_URL` env var)

Variables de entorno del participante:

| Variable | Descripción |
|---|---|
| `CLAIM_ADDRESS` | Dirección on-chain donde recibir los sats |
| `CLAIM_PRIVKEY` | Clave privada para firmar la claim TX (WIF o hex) |
| `BOLTZ_API_URL` | URL del backend Boltz |
| `BITCOIN_RPC_URL` | URL del nodo Bitcoin para broadcast |

**Archivo a crear:** `tanda/boltz_claim.py` — construye y firma la claim TX del reverse swap.

---

### Fase 4 — Tests

| Archivo | Qué prueba |
|---|---|
| `tests/test_boltzrpc.py` | Unit: `BoltzRpc` con mock HTTP |
| `tests/test_api_participant_ln.py` | Unit: `POST /claim_swap` con mock Boltz + mock CLN |
| `tests/test_e2e_boltz_docker.py` | E2E: stack Docker completo (bitcoind + CLN + Boltz + API) |

Test E2E mínimo:
1. Levantar `docker-compose.boltz.yml` + participante API
2. Ejecutar una ronda completa con `payment_method=boltz`
3. Verificar UTXO on-chain en `CLAIM_ADDRESS` tras la ronda

---

### Fase 5 — Integración en el dispatcher

`pay_winner()` en `run_coordinator_ln.py` soporta `method == "boltz"`:

```python
match info["method"]:
    case "bolt11"    -> POST /create_invoice → cln.pay(bolt11)
    case "bolt12"    -> cln.fetch_invoice(offer) → cln.pay(bolt12_inv)
    case "lnaddress" -> resolve LNURL-pay → cln.pay(bolt11)
    case "boltz"     -> pay_winner_boltz(cln, boltz, ...)
```

`PAYMENT_METHOD=boltz` activa el flujo completo.

---

## Resumen del roadmap

| Parte | Descripción | Entrega al ganador |
|---|---|---|
| Estado actual | `POST /create_invoice` + `cln.pay(bolt11)` | Liquidez en canal |
| Parte 1a | BOLT12 offer (`GET /offer` + `cln.fetch_invoice`) | Liquidez en canal |
| Parte 1b | Lightning Address (`LNURL-pay` resolver) | Liquidez en canal |
| Parte 2 | Reverse submarine swap (Boltz) | **UTXO on-chain** |

La Parte 1 es no-breaking: el flujo de hold invoices no cambia, solo se extiende
`pay_winner()`. La Parte 2 requiere un backend Boltz y acceso on-chain desde el
participante, pero preserva la garantía trustless del protocolo.
