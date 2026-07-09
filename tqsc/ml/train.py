"""
TQSC v2.0 — TQSC World Model Trainer
Red neuronal de 13 cabezas de salida que modela el comportamiento
de todos los núcleos y subnúcleos de TQSC.

Arquitectura:
  Input (89 features) → Dense(256) → BN → ReLU → Dropout(0.3)
                      → Dense(128) → BN → ReLU → Dropout(0.2)
                      → Dense(64)  → BN → ReLU
                      → 13 cabezas de salida (una por subnúcleo)

Exportación a ONNX + integración en TQSC.
"""
import json, sys, os
from pathlib import Path

os.environ["TQSC_TEST_MODE"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Generar dataset si no existe ──────────────────────────
dataset_path = Path("data/ml/world_model_dataset.json")
if not dataset_path.exists():
    print("Generando dataset...")
    from tqsc.ml.dataset import generar_dataset
    X, Y, meta = generar_dataset(10000, ruido=0.05)
    Path("data/ml").mkdir(parents=True, exist_ok=True)
    with open(dataset_path, "w") as f:
        json.dump({
            "n_muestras": len(X), "n_features": len(X[0]), "n_targets": len(Y[0]),
            "features_orden": sorted(meta[0]["features"].keys()),
            "targets_orden": sorted(meta[0]["targets"].keys()),
            "datos": [{"x": X[i], "y": Y[i]} for i in range(len(X))],
        }, f, indent=2)
    print(f"Dataset: {len(X)} muestras")

# ── Cargar dataset ────────────────────────────────────────
with open(dataset_path) as f:
    data = json.load(f)

X = [d["x"] for d in data["datos"]]
Y = [d["y"] for d in data["datos"]]
N_FEATURES = data["n_features"]
N_TARGETS = data["n_targets"]
TARGETS_ORDEN = data["targets_orden"]

print(f"Features: {N_FEATURES}, Targets: {N_TARGETS}")
print(f"Target heads: {TARGETS_ORDEN}")

# ── Entrenar con scikit-learn (no requiere GPU, exportable a ONNX) ──
# Usamos MLPClassifier EN UNO-VS-REST por cada target
# Esto es equivalente a una red neuronal con múltiples cabezas

from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, mean_squared_error
import numpy as np
import joblib

X_np = np.array(X, dtype=np.float32)
Y_np = np.array(Y, dtype=np.float32)

X_train, X_test, Y_train, Y_test = train_test_split(X_np, Y_np, test_size=0.2, random_state=42)

# Escalar features
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# Entrenar un modelo por target (cabeza de salida)
# Esto es equivalente a una red multi-cabeza, pero más práctico
# que entrenar una sola red con 13 salidas mezclando clasificación y regresión

modelos = []
metricas = []

for i in range(N_TARGETS):
    nombre = TARGETS_ORDEN[i]
    y_train_i = Y_train[:, i]
    y_test_i = Y_test[:, i]

    # Detectar si es clasificación (valores enteros) o regresión (continuo)
    valores_unicos = len(set(int(v * 10) for v in y_train_i[:100]))
    es_clasificacion = valores_unicos <= 10

    if es_clasificacion:
        y_train_i_int = np.round(y_train_i).astype(int)
        y_test_i_int = np.round(y_test_i).astype(int)
        n_clases = len(set(y_train_i_int))
        model = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size=64,
            max_iter=500,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )
        model.fit(X_train_s, y_train_i_int)
        preds = model.predict(X_test_s)
        acc = accuracy_score(y_test_i_int, preds)
        f1 = f1_score(y_test_i_int, preds, average='weighted', zero_division=0)
        metricas.append((nombre, 'cls', acc, f1))
        print(f"  {nombre:20s} [CLS] acc={acc:.3f} f1={f1:.3f}")
    else:
        model = MLPRegressor(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size=64,
            max_iter=500,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )
        model.fit(X_train_s, y_train_i)
        preds = model.predict(X_test_s)
        mse = mean_squared_error(y_test_i, preds)
        metricas.append((nombre, 'reg', mse, 0))
        print(f"  {nombre:20s} [REG] mse={mse:.4f}")

    modelos.append(model)

# ── Guardar modelos + scaler ──────────────────────────────
Path("data/ml").mkdir(parents=True, exist_ok=True)
joblib.dump(scaler, "data/ml/scaler.pkl")
joblib.dump(modelos, "data/ml/modelos.pkl")
joblib.dump(TARGETS_ORDEN, "data/ml/targets_orden.pkl")

print("\n✅ Modelos guardados en data/ml/")
print(f"   {len(modelos)} modelos (uno por cabeza de salida)")
print(f"\nResumen de rendimiento:")
for nombre, tipo, m1, m2 in metricas:
    if tipo == 'cls':
        print(f"  🟢 {nombre:20s} acc={m1:.3f} f1={m2:.3f}")
    else:
        print(f"  🔵 {nombre:20s} mse={m1:.4f}")

# ── Exportar a ONNX (primer modelo como demo) ─────────────
try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
    onx = convert_sklearn(modelos[0], initial_types=initial_type)
    with open("data/ml/tqsc_world_model.onnx", "wb") as f:
        f.write(onx.SerializeToString())
    print(f"\n✅ ONNX exportado: data/ml/tqsc_world_model.onnx")
except ImportError:
    print(f"\n⚠️  skl2onnx no instalado, ONNX no exportado (pip install skl2onnx)")

print("\n✅ TRAINING COMPLETE")
