import os
import time
import numpy as np
import tensorflow as tf
from data_loader import load_json_files, preprocess_data
from cnn_model import create_model

MODEL_PATH = "./ai_service/network_anomaly_cnn.h5"  # Model dosyası yolu
DATA_DIR = "./data"  # JSON dosyalarının bulunduğu klasör


def train_on_new_data():
    """
    Yeni JSON dosyaları geldikçe modeli eğitir.
    """
    while True:
        # Yeni veriyi oku
        df = load_json_files(DATA_DIR)
        df = preprocess_data(df)

        # Model girişlerini oluştur
        X = np.array(df[["timestamp", "length", "protocol"]])
        X = X.reshape(X.shape[0], X.shape[1], 1)
        y = np.random.randint(0, 2, size=(X.shape[0],))  # Placeholder

        # Modeli yükle ve eğit
        if os.path.exists(MODEL_PATH):
            model = tf.keras.models.load_model(MODEL_PATH)
        else:
            model = create_model(input_shape=(X.shape[1], 1))

        model.fit(X, y, epochs=3, batch_size=32)
        model.save(MODEL_PATH)
        print("Model updated with new data!")

        time.sleep(60)  # 1 dakika bekle, sonra tekrar kontrol et

if __name__ == "__main__":
    train_on_new_data()
