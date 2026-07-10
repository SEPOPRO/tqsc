"""
packed_ternary.py — Trits empaquetados en bites reales
Cada trit = 2 bits. 6 trits = 12 bits = 1.5 bytes.
vs float32 = 4 bytes por peso.
"""
import math, struct
from typing import List, Optional

# ═══════════════════════════════════════════
#  CODIFICACIÓN BINARIA DE TRITS
# ═══════════════════════════════════════════

# Mapa: trit real (-1, 0, 1) → 2 bits
_TRIT_TO_BITS = {-1: 0b00, 0: 0b01, 1: 0b10}
_BITS_TO_TRIT = {0b00: -1, 0b01: 0, 0b10: 1, 0b11: 0}  # 0b11 = error, default 0

def _trits_to_bytes(trits: List[int]) -> bytes:
    """Empaqueta N trits en ceil(N*2/8) bytes."""
    bits = 0
    n_bits = 0
    for t in trits:
        bits |= (_TRIT_TO_BITS[t] & 0b11) << n_bits
        n_bits += 2
    return bits.to_bytes((n_bits + 7) // 8, 'little')

def _bytes_to_trits(data: bytes, n_trits: int) -> List[int]:
    """Desempaqueta N trits desde bytes."""
    bits = int.from_bytes(data, 'little')
    trits = []
    for i in range(n_trits):
        trits.append(_BITS_TO_TRIT[(bits >> (i * 2)) & 0b11])
    return trits

# ═══════════════════════════════════════════
#  PACKED TERNARY ARRAY
# ═══════════════════════════════════════════

class PackedTernaryArray:
    """
    Arreglo de pesos en ternario balanceado empaquetados.
    Cada peso = N trits. Cada trit = 2 bits.
    
    Ejemplo: 768×768 pesos × 8 trits = 4,718,592 trits
    = 9,437,184 bits = 1,179,648 bytes = 1.12 MB
    vs 768×768×4 = 2,359,296 bytes = 2.25 MB (float32)
    """
    
    def __init__(self, shape: tuple, trits_per_weight: int = 8):
        self.shape = shape
        self.trits_per_weight = trits_per_weight
        self.n_weights = shape[0] * shape[1]
        self.n_trits = self.n_weights * trits_per_weight
        
        # Almacenamiento real: bytes empaquetados
        n_bytes = (self.n_trits * 2 + 7) // 8
        self._data = bytearray(n_bytes)
        
        # Almacenar escala por fila para decodificación
        self._scales = [1.0] * shape[0]
    
    @staticmethod
    def _encode_weight(value: float, n_trits: int) -> List[int]:
        """Convierte float en [-1,1] a trits (base 3 con 2→-1)."""
        q = int((value + 1.0) / 2.0 * (3**n_trits - 1))
        q = max(0, min(3**n_trits - 1, q))
        trits = []
        for _ in range(n_trits):
            r = q % 3
            trits.append(-1 if r == 2 else r)  # 2→-1 para empaquetar
            q //= 3
        return trits
    
    @staticmethod
    def _decode_weight(trits: List[int]) -> float:
        """Convierte trits (con -1) a float en [-1,1]."""
        q = 0
        for i, t in enumerate(trits):
            d = t if t >= 0 else 2  # -1→2
            q += d * (3 ** i)
        max_q = 3**len(trits) - 1
        return (q / max_q) * 2.0 - 1.0

    def set_weight(self, row: int, col: int, value: float):
        """Almacena un peso como trits empaquetados."""
        idx = row * self.shape[1] + col
        trits = self._encode_weight(value, self.trits_per_weight)
        offset = idx * self.trits_per_weight * 2  # 2 bits por trit
        byte_off = offset // 8
        bit_off = offset % 8
        
        bits = 0
        for i, t in enumerate(trits):
            bits |= (_TRIT_TO_BITS[t] & 0b11) << (bit_off + i * 2)
        
        n_bytes = (self.trits_per_weight * 2 + bit_off + 7) // 8
        for b in range(n_bytes):
            if byte_off + b < len(self._data):
                self._data[byte_off + b] = (bits >> (b * 8)) & 0xFF
    
    def get_weight(self, row: int, col: int) -> float:
        """Lee un peso desde trits empaquetados."""
        idx = row * self.shape[1] + col
        offset = idx * self.trits_per_weight * 2
        byte_off = offset // 8
        bit_off = offset % 8
        
        n_bytes = (self.trits_per_weight * 2 + bit_off + 7) // 8
        chunk = self._data[byte_off:byte_off + n_bytes]
        if len(chunk) < n_bytes:
            chunk = chunk + b'\x00' * (n_bytes - len(chunk))
        
        bits = int.from_bytes(chunk, 'little')
        trits = []
        for i in range(self.trits_per_weight):
            trits.append(_BITS_TO_TRIT[(bits >> (bit_off + i * 2)) & 0b11])
        
        return self._decode_weight(trits)
    
    @property
    def size_bytes(self) -> int:
        return len(self._data)
    
    def memory_report(self) -> dict:
        float_sz = self.shape[0] * self.shape[1] * 4
        packed_sz = self.size_bytes
        return {
            "shape": self.shape,
            "trits_per_weight": self.trits_per_weight,
            "n_weights": self.n_weights,
            "float32_bytes": float_sz,
            "packed_bytes": packed_sz,
            "savings_pct": round((1 - packed_sz / float_sz) * 100, 1),
            "bits_per_weight": self.trits_per_weight * 2,
        }


# ═══════════════════════════════════════════
#  HYBRID LINEAR con pesos empaquetados de verdad
# ═══════════════════════════════════════════

import torch
import torch.nn as nn
import torch.nn.functional as F

class PackedHybridLinear(nn.Module):
    """Linear con pesos ternarios empaquetados en bites reales.
    
    Almacenamiento real:
      float32: N×M × 4 bytes
      Ternario empaquetado: N×M × (trits × 2 / 8) bytes
    
    Para 8 trits/peso: 2 bytes/peso vs 4 bytes = 50% ahorro.
    Para 6 trits/peso: 1.5 bytes/peso vs 4 bytes = 62.5% ahorro.
    """
    
    def __init__(self, in_features: int, out_features: int, 
                 trits_per_weight: int = 6):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.trits_per_weight = trits_per_weight
        
        # Almacenamiento ternario empaquetado
        self._weight = PackedTernaryArray(
            (out_features, in_features), trits_per_weight)
        
        # Inicializar pesos aleatorios
        for i in range(out_features):
            for j in range(in_features):
                w = torch.randn(1).item() * 0.02
                self._weight.set_weight(i, j, max(-1.0, min(1.0, w)))
        
        # Bias en float32 (insignificante)
        self.bias = nn.Parameter(torch.zeros(out_features))
        
        # Caché de pesos decodificados (opcional, mejora velocidad)
        self._cache = None
    
    def _decode_all(self) -> torch.Tensor:
        """Decodifica todos los pesos a float32."""
        if self._cache is not None:
            return self._cache
        
        w = torch.zeros(self.out_features, self.in_features)
        for i in range(self.out_features):
            for j in range(self.in_features):
                w[i, j] = self._weight.get_weight(i, j)
        self._cache = w
        return w
    
    def invalidate_cache(self):
        self._cache = None
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        w = self._decode_all()
        return F.linear(x, w, self.bias)
    
    @property
    def weight(self) -> torch.Tensor:
        return self._decode_all()
    
    def report(self) -> str:
        r = self._weight.memory_report()
        return (
            f"PackedHybridLinear({self.in_features}→{self.out_features}, "
            f"{self.trits_per_weight} trits/weight)\n"
            f"  float32:  {r['float32_bytes']/1024:.1f} KB\n"
            f"  Empaquetado: {r['packed_bytes']/1024:.1f} KB\n"
            f"  Ahorro REAL: {r['savings_pct']}%\n"
            f"  Bits/peso: {r['bits_per_weight']}"
        )


# ═══════════════════════════════════════════
#  PACKED HYBRID LORA
# ═══════════════════════════════════════════

class PackedHybridLoRA(nn.Module):
    """LoRA sobre pesos ternarios empaquetados."""
    
    def __init__(self, base: PackedHybridLinear, rank: int = 8, alpha: float = 16.0):
        super().__init__()
        self.base = base
        self.rank = rank
        self.alpha = alpha
        self.scaling = alpha / rank
        
        # LoRA adapters (float32, entrenables)
        self.lora_A = nn.Parameter(torch.zeros(rank, base.in_features))
        self.lora_B = nn.Parameter(torch.zeros(base.out_features, rank))
        nn.init.kaiming_uniform_(self.lora_A, a=math.sqrt(5))
        nn.init.zeros_(self.lora_B)
    
    @property
    def trainable_params(self) -> int:
        return self.lora_A.numel() + self.lora_B.numel()
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        base_out = self.base(x)
        lora_out = (x @ self.lora_A.T) @ self.lora_B.T * self.scaling
        return base_out + lora_out


# ═══════════════════════════════════════════
#  DEMO
# ═══════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("  PACKED TERNARY — Trits empaquetados en memoria real")
    print("=" * 70)
    
    # 1. Precisión de empaquetado
    print("\n📊 1. PRECISIÓN encode/decode")
    print(f"{'Valor original':>15s} | {'Trits':>6s} | {'Decodificado':>14s} | {'Error':>10s}")
    print("-" * 50)
    for v in [0.0, 0.5, 1.0, -0.5, -1.0, 0.333, 0.001, -0.999]:
        for n_trits in [4, 6, 8, 10]:
            enc = PackedTernaryArray._encode_weight(v, n_trits)
            dec = PackedTernaryArray._decode_weight(enc)
            err = abs(v - dec)
            break  # Solo mostrar para 6 trits
        enc = PackedTernaryArray._encode_weight(v, 6)
        dec = PackedTernaryArray._decode_weight(enc)
        print(f"{v:>15.4f} | {6:>6d} | {dec:>14.6f} | {abs(v-dec):>9.6f}")
    
    # 2. Ahorro de memoria real
    print("\n📊 2. AHORRO DE MEMORIA REAL")
    for dims, trits in [((768, 768), 6), ((768, 768), 8),
                         ((1024, 1024), 6)]:
        arr = PackedTernaryArray(dims, trits)
        r = arr.memory_report()
        print(f"  {dims[0]}×{dims[1]} × {trits} trits: "
              f"{r['float32_bytes']/1024/1024:.1f} MB → {r['packed_bytes']/1024/1024:.1f} MB "
              f"({r['savings_pct']}% savings)")
    
    # 3. HybridLinear empaquetado (pequeño para demo rápida)
    print("\n📊 3. PACKED HYBRID LINEAR (pequeño)")
    layer = PackedHybridLinear(256, 256, trits_per_weight=6)
    print(f"  {layer.report()}")
    
    # 4. Forward + LoRA
    print("\n📊 4. PACKED HYBRID LoRA (forward)")
    lora = PackedHybridLoRA(layer, rank=4)
    x = torch.randn(2, 256)
    y = lora(x)
    print(f"  Forward OK: {list(x.shape)} → {list(y.shape)}")
    print(f"  Parámetros entrenables (LoRA): {lora.trainable_params:,}")
    
    # 5. Escalabilidad (estimación rápida, sin inicializar arrays gigantes)
    print("\n📊 5. ESCALABILIDAD (modelo 7B con empaquetado real)")
    # En lugar de inicializar arrays grandes, calcular directamente
    # 6 trits × 2 bits/trit = 12 bits/peso = 1.5 bytes/peso
    # float32 = 4 bytes/peso)
    dims = [
        ("q_proj", 4096, 4096),
        ("k_proj", 4096, 4096),
        ("v_proj", 4096, 4096),
        ("o_proj", 4096, 4096),
        ("gate_proj", 4096, 11008),
        ("up_proj", 4096, 11008),
        ("down_proj", 11008, 4096),
    ]
    n_layers = 32
    trits_pw = 6
    
    total_float = 0
    total_packed = 0
    for name, d_in, d_out in dims:
        arr = PackedTernaryArray((d_out, d_in), trits_pw)
        r = arr.memory_report()
        total_float += r["float32_bytes"] * n_layers
        total_packed += r["packed_bytes"] * n_layers
    
    otros_float = 7 * 1024**3  # ~7GB de otros pesos
    
    print(f"\n  {'Componente':>30s} | {'float32':>12s} | {'Packed':>12s}")
    print("-" * 58)
    for name, d_in, d_out in dims:
        a = PackedTernaryArray((d_out, d_in), trits_pw)
        r = a.memory_report()
        f_sz = r["float32_bytes"] * n_layers / 1024**3
        p_sz = r["packed_bytes"] * n_layers / 1024**3
        print(f"{name:>30s} | {f_sz:>9.1f} GB | {p_sz:>9.1f} GB")
    
    print(f"\n{'Total attn/ffn':>30s} | {total_float/1024**3:>9.1f} GB | {total_packed/1024**3:>9.1f} GB")
    print(f"{'Modelo completo 7B':>30s} | {(total_float+otros_float)/1024**3:>9.1f} GB | {(total_packed+otros_float)/1024**3:>9.1f} GB")
    
    final_savings = round((1 - (total_packed+otros_float)/(total_float+otros_float)) * 100, 1)
    print(f"\n  AHORRO TOTAL: {final_savings}%")
    print(f"  7B en float32: {(total_float+otros_float)/1024**3:.1f} GB")
    print(f"  7B en packed ternary: {(total_packed+otros_float)/1024**3:.1f} GB")
    
    # Conclusión
    print("\n" + "=" * 70)
    print("  CONCLUSIÓN: AHORRO REAL EN MEMORIA")
    print("=" * 70)
    print(f"""
  EMPAQUETADO REAL (2 bits por trit):

  • 6 trits/peso = 12 bits = 1.5 bytes (vs 4 bytes float32)
  • Ahorro en capas lineales: ~{final_savings}%
  • Modelo 7B completo: ~{total_float/1024**3:.0f} GB → ~{(total_packed+otros_float)/1024**3:.0f} GB

  CÓMO USAR EN FINE-TUNING:

  from packed_ternary import PackedHybridLinear, PackedHybridLoRA

  # Capa ternaria empaquetada
  layer = PackedHybridLinear(4096, 4096, trits_per_weight=6)

  # LoRA sobre ella
  lora = PackedHybridLoRA(layer, rank=8)
  y = lora(x)

  # Forward/Backward normal
  loss = F.mse_loss(y, target)
  loss.backward()
  optimizer.step()

  LIMITACIONES:
  • Decodificación O(n²) en CPU (puede ser lento para modelos grandes)
  • Solución: decodificar una capa a la vez (on-demand), no todo el modelo
  • Con cache: solo decodifica la primera vez, reusa después
  • Ideal para: fine-tuning LoRA donde el modelo base no cambia
""")
    print("=" * 70)
