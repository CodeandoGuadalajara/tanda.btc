import matplotlib.pyplot as plt
import numpy as np

# ────────────────────────────────────────────────
# Parámetros de la tanda (ejemplo realista)
# ────────────────────────────────────────────────
n_personas = 10
aporte_por_periodo = 1000          # $1,000 por período
pozo = n_personas * aporte_por_periodo  # $10,000

periodos = np.arange(0, n_personas + 1)   # 0 → 10
turnos_a_graficar = [1, 3, 5, 7, 10]      # turnos representativos

# Colores para diferenciar turnos
colores = ['#2ca02c', '#1f77b4', '#9467bd', '#ff7f0e', '#d62728']

# ────────────────────────────────────────────────
# Figura con dos subgráficas
# ────────────────────────────────────────────────
fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(11, 13), sharex=False)

# ────────────────────────────────────────────────
# Gráfica 1: Tanda - Saldo neto acumulado por turno
# ────────────────────────────────────────────────
ax1.set_title('Tanda rotativa justa (10 personas)\nSaldo neto acumulado según turno de recepción', 
              fontsize=14, fontweight='bold')
ax1.set_ylabel('Saldo neto ($)', fontsize=12)
ax1.set_xlabel('Período', fontsize=12)
ax1.grid(True, alpha=0.3, linestyle='--')

for i, turno in enumerate(turnos_a_graficar):
    saldo = np.zeros(len(periodos))
    
    for t in range(1, len(periodos)):
        # Aportación en cada período
        saldo[t] = saldo[t-1] - aporte_por_periodo
        
        # Recepción del pozo (neto: +pozo - aporte del período)
        if t == turno:
            saldo[t] += pozo
    
    # Graficar
    label = f'Turno {turno}'
    ax1.plot(periodos[1:], saldo[1:], 'o-', linewidth=2.3, markersize=6,
             color=colores[i], label=label)
    
    # Resaltar el salto
    ax1.plot(turno, saldo[turno], 'o', markersize=12, 
             color=colores[i], alpha=0.5, markeredgewidth=2)

ax1.axhline(0, color='gray', linestyle='--', linewidth=1.2, alpha=0.6)
ax1.legend(fontsize=9, loc='upper right', ncol=3, framealpha=0.9,
           handlelength=1.5, handletextpad=0.5, columnspacing=1.0)
ax1.set_ylim(-11000, 11000)
ax1.set_xticks(range(0, n_personas+1))

# ────────────────────────────────────────────────
# Gráfica 2: Bono cupón cero
# ────────────────────────────────────────────────
tasa_anual = 0.08               # 8% anual (típica CETES + spread ~2024-2026)
valor_nominal = pozo            # mismo monto final: $10,000
tiempo_anos = np.linspace(10, 0, 101)   # curva suave (más puntos)

precio_bono = valor_nominal / (1 + tasa_anual) ** tiempo_anos

ax2.set_title(f'Bono cupón cero (valor nominal ${valor_nominal:,})\nValor presente – tasa {tasa_anual*100:.0f}% anual', 
              fontsize=14, fontweight='bold')
ax2.set_xlabel('Años restantes hasta vencimiento', fontsize=12)
ax2.set_ylabel('Valor presente ($)', fontsize=12)
ax2.grid(True, alpha=0.3, linestyle='--')

ax2.plot(tiempo_anos, precio_bono, color='teal', linewidth=2.8, label=f'tasa {tasa_anual*100:.1f}%')
ax2.axhline(valor_nominal, color='gray', linestyle='--', alpha=0.5, 
            label=f'Nominal ${valor_nominal:,}')
ax2.axvline(0, color='black', linestyle='-', alpha=0.4)

# Anotaciones útiles
ax2.annotate(f'Precio hoy ≈ ${precio_bono[0]:,.0f}',
             xy=(10, precio_bono[0]), xytext=(7.5, precio_bono[0]+800),
             arrowprops=dict(facecolor='black', shrink=0.05, width=1.5),
             fontsize=11, fontweight='bold')

ax2.annotate(f'Vencimiento\n${valor_nominal:,}',
             xy=(0, valor_nominal), xytext=(1.2, valor_nominal-1500),
             arrowprops=dict(facecolor='black', shrink=0.05, width=1.5),
             fontsize=11, fontweight='bold')

ax2.legend(loc='lower left', fontsize=10,
           handlelength=1.5, handletextpad=0.5)
ax2.set_ylim(0, valor_nominal * 1.15)
ax2.set_xlim(10.5, -0.5)

# ────────────────────────────────────────────────
# Gráfica 3: Serie de bonos cupón cero en sats
#   Ganador n recibe el pozo y compra un bono a n años
# ────────────────────────────────────────────────
valor_nominal_sats = 1_000_000          # pozo en sats = 1 M sats
tasa_btc = 0.008                        # inflación protocolo BTC ~0.8% anual

cmap = plt.get_cmap('plasma', n_personas)

ax3.set_title(
    f'Tanda-bono: {n_personas} ganadores, cada uno compra un cupón cero a n años\n'
    f'Valor nominal {valor_nominal_sats:,} sats – tasa {tasa_btc*100:.1f}% anual (inflación BTC)',
    fontsize=14, fontweight='bold')
ax3.set_xlabel('Años restantes hasta vencimiento', fontsize=12)
ax3.set_ylabel('Valor presente (sats)', fontsize=12)
ax3.grid(True, alpha=0.3, linestyle='--')

for n in range(1, n_personas + 1):
    # Curva desde t_restante = n hasta 0 (el ganador n compra en el año n)
    t = np.linspace(n, 0, n * 50 + 1)
    precio = valor_nominal_sats / (1 + tasa_btc) ** t
    color = cmap(n - 1)

    ax3.plot(t, precio, color=color, linewidth=2.2, label=f'Turno {n}')

    # Punto de compra (inicio del bono)
    precio_compra = valor_nominal_sats / (1 + tasa_btc) ** n
    ax3.plot(n, precio_compra, 'o', color=color, markersize=7, zorder=5)

    # Etiqueta con el precio de compra al lado del punto inicial
    offset_y = 1_500 if n % 2 == 0 else -3_500
    ax3.annotate(f'{precio_compra:,.0f}',
                 xy=(n, precio_compra), xytext=(n + 0.1, precio_compra + offset_y),
                 fontsize=7, color='black', va='center', zorder=10,
                 bbox=dict(boxstyle='round,pad=0.15', fc='white', ec='none', alpha=0.7))

# Línea de nominal y vencimiento
ax3.axhline(valor_nominal_sats, color='gray', linestyle='--', alpha=0.5,
            label=f'Nominal {valor_nominal_sats:,} sats')
ax3.plot(0, valor_nominal_sats, 'k^', markersize=10, zorder=6, label='Vencimiento')

ax3.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x):,}'))
ax3.legend(loc='upper left', fontsize=8, ncol=2,
           handlelength=1.2, handletextpad=0.4, columnspacing=0.8)
ax3.set_ylim(valor_nominal_sats * 0.915, valor_nominal_sats * 1.025)
ax3.set_xlim(10.5, -0.5)

plt.tight_layout()
plt.show()
