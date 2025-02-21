import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout
import numpy as np
from data_loader import load_json_files, preprocess_data

def create_model(input_shape):
    model = Sequential([
        Conv1D(filters=64, kernel_size=3, activation="relu", input_shape=input_shape),
        Conv1D(filters=32, kernel_size=3, activation="relu"),
        Flatten(),
        Dense(64, activation="relu"),
        Dropout(0.5),
        Dense(1, activation="sigmoid")  # Anomali için 0 veya 1 tahmini yapacak
    ])
    
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model

# Veriyi yükleyip modele uygun hale getir
df = load_json_files()
df = preprocess_data(df)

# Model giriş ve çıkışları
X = np.array(df[["timestamp", "length", "protocol"]])  # Kullanılacak feature'lar
y = np.random.randint(0, 2, size=(X.shape[0],))  # Şimdilik rastgele 0-1 sınıflandırma (anormal-normal)

# CNN giriş formatı için yeniden şekillendirme
X = X.reshape(X.shape[0], X.shape[1], 1)

# Modeli oluştur ve eğit
model = create_model(input_shape=(X.shape[1], 1))
model.fit(X, y, epochs=10, batch_size=32)

# Modeli kaydet
model.save("network_anomaly_cnn.h5")
