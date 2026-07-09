# TQSC v2.0 — Docker Isolation
## Aislamiento de red: cada núcleo en su contenedor

### Arquitectura

```
                    ┌─────────────────────────┐
                    │      INTERNET           │
                    └─────────┬───────────────┘
                              │
                    ┌─────────▼───────────────┐
                    │   tqsc_exposed (bridge) │
                    │   2222, 8080 → host     │
                    └─────────┬───────────────┘
                              │
                    ┌─────────▼───────────────┐
                    │   tqsc-honeypot         │
                    │   (único con acceso     │
                    │    a Internet)          │
                    └─────────┬───────────────┘
                              │
              ═══════════════╪═══════════════════
         ┌───────────────────┼───────────────────┐
         │     tqsc_internal (bridge, internal)  │
         │      ⛔ SIN acceso a Internet         │
         │      ⛔ SIN acceso al host            │
         └───────────────────────────────────────┘
              │  │  │  │  │  │  │  │  │  │
    ┌─────────┘  │  │  │  │  │  │  │  │  └──────────┐
    ▼            ▼  ▼  ▼  ▼  ▼  ▼  ▼  ▼             ▼
  supervisor   ia  def  qua  ent  cor  mem  paz  bc  honeypot

  leyenda:
    ia  = IA Core        def = Defense       qua = Quantum
    ent = Entropy        cor = Cortex        mem = Memoria
    paz = ProtocoloPaz   bc  = Blockchain    honeypot = Honeypot
```

### Servicios

| Contenedor | Red | Puertos | Volumen /proc | Propósito |
|:-----------|:---:|:-------:|:-------------:|:----------|
| tqsc-supervisor | internal | — | — | Watchdog |
| tqsc-ia | internal | — | — | IA Autoevolutiva |
| tqsc-blockchain | internal | — | — | Blockchain |
| tqsc-defense | internal | — | ✅ /proc:ro | Defensa física |
| tqsc-quantum | internal | — | — | Criptografía |
| tqsc-entropy | internal | — | — | Entropía |
| tqsc-cortex | internal | — | — | Supervisor IA |
| tqsc-memoria | internal | — | — | Memoria |
| tqsc-paz | internal | — | — | Protocolo Paz |
| **tqsc-honeypot** | **internal + exposed** | **2222, 8080** | — | Honeypot (único expuesto) |

### Seguridad

| Propiedad | Cómo se logra |
|:----------|:--------------|
| Sin acceso a Internet | `network.internal: true` en `tqsc_internal` |
| Sin acceso al host | bridge network sin `network_mode: host` |
| Aislamiento entre núcleos | Cada uno es un contenedor separado con su propia pila de red |
| Datos persistentes | Volumen Docker `tqsc_data` compartido en `/app/data` |
| Honeypot aislado | Solo él tiene acceso a `tqsc_exposed` |
| Defense con /proc | Solo defense monta `/proc` (read-only), el resto no |

### Uso

```bash
# Build imágenes
docker compose build

# Iniciar todos los núcleos
docker compose up -d

# Ver logs de un núcleo específico
docker compose logs -f tqsc-ia

# Ver estado de todos los contenedores
docker compose ps

# Detener todo
docker compose down
```
