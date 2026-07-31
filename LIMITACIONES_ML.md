# 🤖 World Model ML — Limitaciones y Alcance Real
## Documento de transparencia sobre la "IA" de TQSC

---

## 1. ¿Qué es realmente el World Model ML?

**No es IA autoevolutiva.** Es un conjunto de **13 modelos sklearn pre-entrenados** (RandomForestClassifier + RandomForestRegressor) que se entrenan una vez sobre un dataset sintético y luego se usan en inferencia. No hay aprendizaje continuo, no hay reentrenamiento online, no hay meta-learning.

### Lo que SÍ es:
- Clasificador estático de 13 cabezas
- Entrenamiento offline sobre 68 features sintéticas
- Inferencia en ~0.2ms por predicción
- Precisión >90% en 12/13 cabezas (dataset sintético)

### Lo que NO es:
- ❌ Aprendizaje continuo / online learning
- ❌ Aprendizaje por refuerzo
- ❌ Redes neuronales profundas (es sklearn RandomForest)
- ❌ Capacidad de mejorar con el uso
- ❌ Validación contra datos reales de ataque
- ❌ Detección de concept drift

---

## 2. Limitaciones conocidas

### 2.1 Dataset sintético
El modelo se entrena con datos generados por `ml/dataset.py` usando distribuciones aleatorias controladas. NO ha visto ataques reales. La precisión reportada (>90%) es sobre datos sintéticos con ruido controlado. En producción real, la precisión será significativamente menor.

### 2.2 Sin reentrenamiento
El modelo se entrena una vez en `ml/train.py` y se serializa con joblib. Nunca se reentrena automáticamente. Para actualizarlo:
```bash
python -m ml.train           # regenera dataset
python -m ml.inference       # reentrena modelo
```

### 2.3 68 features frágiles
Las 68 features dependen de que todos los núcleos reporten estado correctamente. Si un núcleo falla, las features correspondientes se rellenan con 0, lo que degrada la predicción. No hay manejo robusto de features faltantes.

### 2.4 Sin detección de deriva
Si el tipo de ataques cambia (nuevos vectores, nuevas técnicas), el modelo no lo detectará. No hay monitoreo de concept drift, ni reentrenamiento automático, ni alertas de degradación.

### 2.5 Cobertura limitada
13 cabezas no cubren todos los escenarios posibles. Por ejemplo:
- No hay cabeza para detectar ataques DDoS
- No hay cabeza para ransomware
- No hay cabeza para ataques a la cadena de suministro
- No hay cabeza para ataques de dia cero

---

## 3. Comparación honesta

| Lo que el nombre sugiere | Lo que realmente es |
|--------------------------|---------------------|
| "World Model" | 13 RandomForest estáticos |
| "IA Autoevolutiva" | Clasificación pre-entrenada |
| "Machine Learning" | sklearn con pipeline simple |
| "13 cabezas de predicción" | 13 modelos sklearn independientes |
| "68 features" | 68 valores numéricos sin normalización |
| "Score >0.90" | Validado sobre dataset sintético |

---

## 4. Cuándo confiar en el ML

| Situación | Confianza |
|-----------|:---------:|
| Patrón visto en entrenamiento sintético | Alta (solo si el ataque real se parece al sintético) |
| Patrón nuevo (no en entrenamiento) | Baja (el modelo clasificará aleatoriamente) |
| Datos incompletos (núcleo caído) | Muy baja (features en 0) |
| Ataque conocido y documentado (SQLi, XSS, brute-force) | Alta (estos SÍ están en el dataset) |

---

## 5. Próximos pasos para mejorar

- [ ] Reentrenamiento periódico con datos reales
- [ ] Detección de concept drift (PSI test)
- [ ] Validación cruzada con datos de producción
- [ ] Features faltantes → imputación no cero
- [ ] Modelos más robustos (XGBoost, LightGBM)
- [ ] Aprendizaje incremental (partial_fit en SGDClassifier)
- [ ] Benchmark contra ataques reales (CICIDS2017, NSL-KDD)

---

## 6. Conclusión

El World Model ML de TQSC es útil como **clasificador rápido de patrones conocidos** en un entorno controlado de pruebas. NO es un sistema de IA autoevolutiva ni debe usarse como única fuente de decisión en producción real. Su verdadero valor está en combinación con las reglas heurísticas del sistema (clasificador híbrido), donde el ML refina decisiones cuando las reglas tienen baja confianza.
