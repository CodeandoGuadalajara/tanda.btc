# Taproot y Schnorr Signatures en Bitcoin

## 1. Schnorr Signatures

### El problema con ECDSA

Bitcoin usó ECDSA desde su inicio. ECDSA funciona, pero tiene limitaciones importantes:

- **No es lineal**: no puedes sumar firmas de distintas partes y obtener una firma válida combinada.
- **Maleable**: terceros pueden modificar una firma sin invalidarla (corregido parcialmente por SegWit).
- **Verboso en multisig**: un 3-of-5 requiere exponer las 3 firmas y las 5 claves públicas on-chain.

### La construcción de Schnorr

Una firma Schnorr sobre el mensaje `m` con clave privada `x` y clave pública `P = x·G`:

```
1. Elegir nonce k (aleatorio, secreto)
2. R = k·G                          (punto de curva, parte pública del nonce)
3. e = H(R || P || m)               (hash determinista)
4. s = k + e·x   (mod n)            (escalar)

Firma = (R, s)
```

Verificación: comprobar que `s·G = R + e·P`

```
s·G = (k + e·x)·G = k·G + e·x·G = R + e·P  ✓
```

### Linealidad: la propiedad clave

Si dos partes tienen claves `x₁`, `x₂` con públicas `P₁ = x₁·G`, `P₂ = x₂·G`, y cada una produce una firma parcial `s₁`, `s₂` sobre el mismo nonce agregado `R = R₁ + R₂`:

```
s₁ = k₁ + e·x₁
s₂ = k₂ + e·x₂

s  = s₁ + s₂ = (k₁+k₂) + e·(x₁+x₂)
```

Esta `s` es una firma válida bajo la clave agregada `P = P₁ + P₂`. **Una sola firma, una sola clave pública**, indistinguible de una firma individual.

Esto es la base de MuSig2 (BIP-327), que es exactamente lo que usa este proyecto para las contribuciones cooperativas de la tanda.

### BIP-340: Schnorr en Bitcoin

BIP-340 estandariza Schnorr para Bitcoin con tres decisiones de diseño importantes:

**1. Claves x-only (32 bytes en lugar de 33)**

Una clave pública es un punto `(x, y)` en la curva secp256k1. Para cada `x` hay exactamente dos puntos: uno con `y` par y otro con `y` impar. BIP-340 siempre asume `y` par y solo serializa `x` (32 bytes). Si tu punto tiene `y` impar, negas la clave (`P → -P`).

**2. Nonce con paridad fija**

Por la misma razón, `R` siempre tiene `y` par. Si `k·G` tiene `y` impar, usa `k → n-k` (negación del nonce).

**3. Hash tagged**

```
H_tag(x) = SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || x)
```

Los hashes etiquetados evitan colisiones entre distintos contextos del protocolo.

---

## 2. Taproot (BIP-341)

Taproot es una mejora de Bitcoin activada en noviembre de 2021 que combina tres ideas:

- **Schnorr signatures** (BIP-340)
- **MAST** — Merkelized Abstract Syntax Trees
- **Pay-to-Taproot** (P2TR) — el nuevo tipo de output

### La estructura de un output P2TR

Un output Taproot tiene el scriptPubKey:

```
OP_1 <32-byte x-only pubkey>
```

Esos 32 bytes son la **output key** `Q`, que codifica dos cosas a la vez:

```
Q = P + t·G
```

donde:
- `P` es la **internal key**: la clave que puede gastar cooperativamente (keypath spend)
- `t = H(P || merkle_root)` es el **tweak** que compromete a todos los scripts alternativos
- `merkle_root` es la raíz de un árbol Merkle de scripts de gasto

```
         Q  (output key, on-chain)
         │
    tweak│= H(P || root)
         │
         P  (internal key, off-chain)
         │
       root (merkle root, off-chain)
       /   \
    branch  leaf_c
    /    \
leaf_a  leaf_b
```

### Tres formas de gastar un output P2TR

**Keypath spend** — el camino cooperativo y privado

Solo se publica una firma Schnorr sobre `Q`. No se revela ni el internal key, ni los scripts. Desde fuera, es idéntico a un pago simple. Es el camino más barato (solo 64 bytes en el witness).

```
witness: [<64-byte Schnorr sig>]
```

**Scriptpath spend** — revelar y ejecutar un leaf

Para gastar via `leaf_a`, se revela:
1. El script de `leaf_a`
2. Un **control block**: internal key `P` + parity bit de `Q` + camino Merkle de `leaf_a` a la raíz

El nodo verifica que el camino Merkle más el tweak produce exactamente la output key `Q` on-chain. Si sí, ejecuta el script.

```
witness: [<inputs del script>  <script>  <control block>]
```

**¿Por qué es poderoso?**

- Con N scripts alternativos, solo se revela el que se usa. Los demás permanecen privados.
- Un multisig cooperativo (keypath) es indistinguible de un pago P2PKH.
- Los scripts se pueden hacer tan complejos como se quiera sin costo en el caso cooperativo.

---

## 3. El Taproot Tweak

### ¿Qué es y por qué existe?

El tweak `t` es lo que "compromete" la output key `Q` al árbol de scripts. Sin él:

- Podrías gastar via keypath sin conocer los scripts, y los scripts serían inutilizables.
- O podrías gastar via scriptpath revelando un árbol vacío, saltándote la internal key.

El tweak matemáticamente liga `P` y `merkle_root` de forma inseparable:

```
t = H_taptweak(P || merkle_root)
Q = P + t·G
```

Si `merkle_root` es vacío (solo keypath, sin scripts), se usa:

```
t = H_taptweak(P)
Q = P + t·G
```

### La construcción del Merkle tree

Cada leaf del árbol es un **TapLeaf**:

```
leaf_hash = H_tapleaf(version || compact_size(len(script)) || script)
```

Los branches combinan dos hashes (siempre en orden canónico para evitar ambigüedad):

```
branch_hash = H_tapbranch(min(h1,h2) || max(h1,h2))
```

### BIP-341 sighash: lo que se firma

Cuando se firma un input en keypath spend, el sighash incluye (entre otras cosas):

```
epoch (0x00) || hash_type || nVersion || nLockTime ||
sha_prevouts || sha_amounts || sha_scriptpubkeys ||
sha_sequences || sha_outputs || spend_type || input_index
```

El campo `input_index` es crítico en transacciones multi-input: cada input tiene un sighash distinto, y por tanto necesita una firma distinta (y nonces MuSig2 distintos).

### El tweak en MuSig2

Cuando se firma via keypath con MuSig2, la clave que firma no es `P` (la clave interna) sino `Q = P + t·G`. Esto requiere ajustar el flujo de firma:

```python
# Aplicar el tweak al KeyAggContext antes de firmar
kac = key_agg(pubkeys)           # agrega las N claves → P
kac = apply_tweak(kac, t, is_xonly=True)   # P → Q
# Ahora kac.agg_pk == Q == output_key_xonly
```

La firma parcial de cada participante usa implícitamente `Q` como clave pública final.

En `partial_sig_agg`, el acumulador de tweak `tacc` entra en la firma final:

```python
g = 1 if Q.y_is_even else n - 1   # paridad de Q
s = sum(s_i) + e * g * tacc  (mod n)
```

El factor `g` corrige la paridad de `Q`: si `Q` tiene `y` impar, BIP-340 usa `lift_x(Q.x) = -Q` para verificar, así que tanto las firmas parciales como el acumulador de tweak deben negarse.

---

## 4. Cómo encaja todo en este proyecto

### La output key de cada ronda

```
internal_key = MuSig2_key_agg(pk_0, pk_1, pk_2)

tap_tree:
  leaf1: <winner_xonly> OP_CHECKSIGVERIFY OP_SHA256 <H> OP_EQUAL   (HTLC)
  leaf2: <t_refund> OP_CSV OP_DROP <pk0> OP_CHECKSIG ...            (refund)

merkle_root = H_tapbranch(leaf1_hash, leaf2_hash)
tweak t     = H_taptweak(internal_key || merkle_root)
output_key  = internal_key + t·G
```

### Los tres caminos de gasto

| Camino | Mecanismo | Cuándo se usa |
|--------|-----------|---------------|
| **Keypath** | MuSig2 (los 3 firman) | Ronda cooperativa: 1 firma, 0 scripts revelados |
| **Leaf1 (HTLC)** | Firma del ganador + preimage SHA256 | El ganador reclama si alguno no coopera |
| **Leaf2 (Refund)** | k-of-N tras CSV timelock | Recuperación colectiva si el ganador desaparece |

### Por qué Taproot es ideal para la tanda

1. **Privacidad**: en el caso cooperativo (>90% de los casos), la transacción on-chain es una firma Schnorr de 64 bytes. Nadie sabe que había scripts de fallback.

2. **Eficiencia**: keypath spend es el witness más pequeño posible en Bitcoin.

3. **Trustlessness**: los scripts de fallback están comprometidos criptográficamente en la output key. El coordinador no puede "olvidarlos" ni alterarlos una vez que los participantes tienen la dirección.

4. **Non-custodial**: nadie puede mover los fondos sin satisfacer exactamente una de las tres condiciones codificadas en `Q`.
