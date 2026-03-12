# Multi-PC Troubleshooting: Docker sin acceso a la LAN

## Síntoma

Desde el host funciona, pero desde dentro de un contenedor Docker no:

```bash
# Host → OK
curl http://192.168.100.85:18443/

# Docker → falla con "Failed to connect to server"
docker run --rm curlimages/curl http://192.168.100.85:18443/
```

## Causa

Docker necesita IP forwarding habilitado en el kernel y una regla MASQUERADE en iptables para que los contenedores puedan enrutar tráfico hacia IPs externas (fuera del bridge de Docker).

---

## Solución

### 1. Verificar estado actual

```bash
cat /proc/sys/net/ipv4/ip_forward
# Si imprime 0 → está deshabilitado, continúa con el paso 2
# Si imprime 1 → ya está habilitado, ve al paso 3
```

### 2. Habilitar IP forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### 3. Identificar la interfaz de red

```bash
ip route | grep default
# Ejemplo de salida: default via 192.168.100.1 dev eth0 proto dhcp ...
#                                                        ^^^^
#                                                   esta es la interfaz
```

La interfaz suele llamarse `eth0`, `wlan0`, `enp3s0`, `ens33`, etc.

### 4. Añadir regla MASQUERADE

Sustituye `eth0` por la interfaz real del paso anterior:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### 5. Verificar que funciona

```bash
docker run --rm curlimages/curl http://192.168.100.85:18443/
# Debe responder (aunque sea un error HTTP 401, eso ya es conexión exitosa)
```

---

## Hacer los cambios permanentes

Sin esto, los cambios se pierden al reiniciar la PC.

```bash
# Instalar iptables-persistent
sudo apt-get install -y iptables-persistent

# Guardar las reglas actuales
sudo netfilter-persistent save

# IP forwarding permanente
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
```

---

## Alternativa rápida (sin tocar iptables)

Si no quieres modificar iptables, puedes reiniciar el servicio Docker — a veces Docker recrea sus propias reglas al arrancar:

```bash
sudo systemctl restart docker
docker run --rm curlimages/curl http://192.168.100.85:18443/
```

---

## Levantar el participante después del fix

Una vez que el contenedor Docker tenga conectividad, levantar el nodo participante normalmente:

```bash
# Sustituir 192.168.100.85 por la IP real del coordinador
BITCOIND_HOST=192.168.100.85 docker compose -f deploy/participant.yml up --build -d

# Verificar que el nodo CLN arrancó correctamente
docker compose -f deploy/participant.yml logs -f
```
