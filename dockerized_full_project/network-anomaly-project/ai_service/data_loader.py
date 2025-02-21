import os
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from tensorflow.keras.utils import to_categorical

# Normalizasyon ve encoderlar
scaler = MinMaxScaler()
label_encoder = LabelEncoder()

def load_json_files(data_dir="data"):
    """
    Belirtilen dizindeki tüm JSON dosyalarını yükleyerek tek bir DataFrame olarak döndürür.
    """
    all_data = []
    
    for file in sorted(os.listdir(data_dir)):
        if file.endswith(".json"):
            with open(os.path.join(data_dir, file), "r") as f:
                data = json.load(f)
                all_data.extend(data)
    
    return pd.DataFrame(all_data)

def preprocess_data(df):
    """
    Veriyi işleyerek modele uygun hale getirir.
    """
    # Zaman bilgisini UNIX formatına çevir
    df["timestamp"] = pd.to_datetime(df["timestamp"]).astype(int) / 10**9

    # Sayısal sütunları normalize et
    df["length"] = scaler.fit_transform(df[["length"]])

    # Kategorik sütunları encode et
    df["protocol"] = label_encoder.fit_transform(df["protocol"])
    
    return df

# Test amaçlı çalıştırma
if __name__ == "__main__":
    df = load_json_files()
    df = preprocess_data(df)
    print(df.head())
