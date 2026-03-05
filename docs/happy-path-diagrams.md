# Tanda-BTC: Happy Path Diagrams

Diagramas del camino cooperativo completo: 3 rondas, 3 participantes,
todos cooperan en cada ronda. La ruta keypath de MuSig2 se usa en todo momento.
Nunca se activan los fallbacks (HTLC leaf1 ni refund leaf2).

---

## 1. Vista general — Ciclo feliz completo

Tres rondas, tres ganadores, todos cooperan. El coordinador nunca necesita
activar fallbacks. Los fondos se mueven directamente entre participantes.

```mermaid
sequenceDiagram
    actor P0
    actor P1
    actor P2
    actor BTC as Bitcoin

    rect rgb(220, 240, 255)
        Note over P0,BTC: RONDA 0 — P0 gana · todos cooperan
        P0->>BTC: 0.01 BTC → address_0
        P1->>BTC: 0.01 BTC → address_0
        P2->>BTC: 0.01 BTC → address_0
        Note over P0,BTC: MuSig2 keypath (2 rondas × 3 inputs)
        BTC-->>P0: 0.03 BTC − fee ✓
    end

    rect rgb(220, 255, 220)
        Note over P0,BTC: RONDA 1 — P1 gana · todos cooperan
        P0->>BTC: 0.01 BTC → address_1
        P1->>BTC: 0.01 BTC → address_1
        P2->>BTC: 0.01 BTC → address_1
        Note over P0,BTC: MuSig2 keypath (2 rondas × 3 inputs)
        BTC-->>P1: 0.03 BTC − fee ✓
    end

    rect rgb(255, 245, 210)
        Note over P0,BTC: RONDA 2 — P2 gana · todos cooperan
        P0->>BTC: 0.01 BTC → address_2
        P1->>BTC: 0.01 BTC → address_2
        P2->>BTC: 0.01 BTC → address_2
        Note over P0,BTC: MuSig2 keypath (2 rondas × 3 inputs)
        BTC-->>P2: 0.03 BTC − fee ✓
    end

    Note over P0,BTC: Cada participante aportó 0.03 BTC en total<br/>y recibió el pot completo (0.03 BTC − fee) exactamente una vez.<br/>On-chain: indistinguible de pagos P2TR simples.
```

---

## 2. Ronda (cualquiera) — Flujo cooperativo detallado

El mecanismo es idéntico en las 3 rondas. Solo cambia `address_k` y el ganador `P_k`.

```mermaid
sequenceDiagram
    actor C as Coordinator
    actor P0
    actor Pk as Pk (ganador)
    actor Pn as P[otros]
    actor BTC as Bitcoin

    rect rgb(220, 240, 255)
        Note over C,BTC: Fase 1 — Contribuciones
        P0->>BTC: 0.01 BTC → address_k
        Pk->>BTC: 0.01 BTC → address_k
        Pn->>BTC: 0.01 BTC → address_k
        BTC->>BTC: Mina 1 bloque
        C->>BTC: scantxoutset("addr(address_k)")
        BTC-->>C: N UTXOs confirmados (0.01 BTC cada uno)
    end

    rect rgb(220, 255, 220)
        Note over C,BTC: Fase 2 — Firma MuSig2 cooperativa (keypath)
        C->>C: Construye claim_tx:<br/>N inputs (un UTXO por participante) → Pk_address<br/>amount = N × 0.01 BTC − fee

        C-->>P0: claim_tx
        C-->>Pk: claim_tx
        C-->>Pn: claim_tx

        loop Para cada input i = 0 … N−1  (nonces frescos por input)
            Note over C,Pn: Ronda 1 — Intercambio de nonces públicos
            P0->>P0: (sec_nonce_0, pub_nonce_0) = nonce_gen(sk_0, pk_0, agg_pk)
            Pk->>Pk: (sec_nonce_k, pub_nonce_k) = nonce_gen(sk_k, pk_k, agg_pk)
            Pn->>Pn: (sec_nonce_n, pub_nonce_n) = nonce_gen(sk_n, pk_n, agg_pk)
            P0-->>C: pub_nonce_0
            Pk-->>C: pub_nonce_k
            Pn-->>C: pub_nonce_n

            C->>C: agg_nonce = NonceAgg(todos los pub_nonces)<br/>sighash_i = taproot_sighash(claim_tx, inp_idx=i, utxos)<br/>session_ctx = SessionContext(agg_nonce, kac, sighash_i)
            C-->>P0: session_ctx
            C-->>Pk: session_ctx
            C-->>Pn: session_ctx

            Note over C,Pn: Ronda 2 — Firmas parciales
            P0->>P0: psig_0 = partial_sign(sec_nonce_0, sk_0, session_ctx)
            Pk->>Pk: psig_k = partial_sign(sec_nonce_k, sk_k, session_ctx)
            Pn->>Pn: psig_n = partial_sign(sec_nonce_n, sk_n, session_ctx)
            P0-->>C: psig_0
            Pk-->>C: psig_k
            Pn-->>C: psig_n

            C->>C: sig_i = PartialSigAgg([psig_0, …, psig_n], session_ctx)<br/>g = 1 si Q.y par, else N−1<br/>s = Σs_i + e·g·tacc (mod n)<br/>claim_tx.inputs[i].witness = [sig_i]
        end

        C->>BTC: broadcast claim_tx (keypath spend — una sola firma de 64 bytes por input)
        BTC->>BTC: Verifica schnorr_verify(sig_i, sighash_i, output_key_xonly)<br/>Mina 1 bloque
        BTC-->>Pk: N × 0.01 BTC − fee ✓
    end
```

---

## 3. Por qué el happy path es óptimo on-chain

```mermaid
flowchart LR
    A[claim_tx on-chain] --> B{Ruta usada}
    B -->|keypath — happy path| C["witness: [64-byte Schnorr sig]\n— Indistinguible de P2TR single-key\n— Sin scripts visibles en la cadena\n— Fee mínimo"]
    B -->|leaf1 — HTLC fallback| D["witness: [sig, preimage, script, ctrl_block]\n— Revela estructura HTLC\n— Fee mayor (más bytes)"]
    B -->|leaf2 — refund fallback| E["witness: [b'', sig1, sig0, script, ctrl_block]\n— Revela refund script\n— Requiere esperar t_refund bloques\n— Fee mayor"]

    style C fill:#d4edda,stroke:#28a745
    style D fill:#fff3cd,stroke:#ffc107
    style E fill:#f8d7da,stroke:#dc3545
```

---

## 4. Setup — Preparación de las 3 rondas

El coordinador genera todos los parámetros antes de que comience cualquier ronda.
Los preimages HTLC se envían en privado a cada ganador aunque nunca se usen
en el happy path — sirven de garantía si el coordinador desaparece.

```mermaid
sequenceDiagram
    actor C as Coordinator
    actor P0
    actor P1
    actor P2

    Note over C: n=3, amount=0.01 BTC<br/>winner_order = [P0, P1, P2]<br/>t_claim=6, t_refund=576

    loop Para k = 0, 1, 2
        C->>C: preimage_k = os.urandom(32)<br/>H_k = SHA256(preimage_k)
        C->>C: agg_pk = MuSig2_KeyAgg(P0, P1, P2)<br/>kac = apply_tweak(kac, taproot_tweak(agg_pk, tap_tree))<br/>assert kac.agg_pk == output_key_xonly
        C->>C: address_k = bech32(Taproot(agg_pk, leaf1_k, leaf2))
    end

    Note over C: Distribuye parámetros públicos
    C-->>P0: {address_k, H_k} para k=0,1,2
    C-->>P1: {address_k, H_k} para k=0,1,2
    C-->>P2: {address_k, H_k} para k=0,1,2

    Note over C: Envía preimage SOLO al ganador de cada ronda (confidencial)
    C--xP0: preimage_0  [solo P0 lo recibe]
    C--xP1: preimage_1  [solo P1 lo recibe]
    C--xP2: preimage_2  [solo P2 lo recibe]

    Note over P0,P2: Cada participante puede verificar:<br/>SHA256(preimage_k) == H_k<br/>Si el coordinador desaparece, Pk puede reclamar por leaf1
```
