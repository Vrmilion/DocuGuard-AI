import xgboost as xgb
import pandas as pd
import numpy as np

# 1. Kita buat data latihan simulasi (agar modelnya terbentuk dulu)
# Ini pura-puranya data ribuan file malware dan aman
print("Sedang melatih model XGBoost...")

# Fitur: [Ada Shell?, Ada AutoOpen?, Entropy, Ukuran File]
X = pd.DataFrame([
    [1, 1, 7.5, 2500], # Malware berat
    [1, 0, 6.0, 1500], # Malware sedang
    [0, 0, 2.1, 300],  # Aman kecil
    [0, 0, 3.5, 500],  # Aman standar
    [0, 1, 4.0, 800]   # Aman tapi ada macro dikit
], columns=['leksikal_shell', 'leksikal_auto', 'skor_entropy', 'structural_size'])

y = pd.Series([1, 1, 0, 0, 0]) # 1=Malware, 0=Aman

# 2. Latih Model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
model.fit(X, y)

# 3. Simpan jadi file
model.save_model("model_malware.json")
print("✅ SUKSES! File 'model_malware.json' sudah muncul di folder kamu.")