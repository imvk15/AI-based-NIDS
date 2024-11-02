from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import tensorflow as tf
from keras import models
import joblib

# Load your trained model
model = models.load_model(r"C:\Users\vivek\OneDrive\Desktop\proj\nids_model.h5")

# Recompile the model to ensure metrics are built
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Dummy data for training step
num_features = model.input_shape[1]  # Get the number of features from the model's input shape
dummy_x = np.random.random((1, num_features, 1, 1))  # Shape should match your input shape
dummy_y_onehot = np.array([[1] + [0] * (model.output_shape[1] - 1)])  # One-hot for number of classes

# Perform a dummy training step to build the metrics
model.fit(dummy_x, dummy_y_onehot, epochs=1, verbose=0)

# Load the scaler
scaler = joblib.load(r"C:\Users\vivek\OneDrive\Desktop\proj\scaler.pkl")

# Load the label encoder used for encoding the attack types
label_encoder = LabelEncoder()
label_encoder.classes_ = np.load(r"C:\Users\vivek\OneDrive\Desktop\proj\classes.npy", allow_pickle=True)

# Define the number of features
num_features = scaler.mean_.shape[0]  # Dynamically get number of features from the scaler

# Create Flask app
app = Flask(__name__)

def preprocess_data(data):
    # Convert incoming data to DataFrame
    df = pd.DataFrame(data)
    
    # Preprocess the IP addresses (assuming data contains 'IPV4_SRC_ADDR' and 'IPV4_DST_ADDR')
    src_ip_split = df['IPV4_SRC_ADDR'].str.split('.', expand=True).astype(int)
    dst_ip_split = df['IPV4_DST_ADDR'].str.split('.', expand=True).astype(int)
    
    # Drop unnecessary columns and combine octets
    df = df.drop(['Dataset'], axis=1)
    df = pd.concat([df.drop(['IPV4_SRC_ADDR', 'IPV4_DST_ADDR'], axis=1), src_ip_split, dst_ip_split], axis=1)
    
    # Normalize data
    x = df.values
    x_scaled = scaler.transform(x)  # Use the fitted scaler
    
    # Reshape data for CNN
    x_reshaped = x_scaled.reshape(-1, num_features, 1, 1)
    
    return x_reshaped

@app.route('/detect', methods=['POST'])
def detect_attack():
    try:
        # Get data from request
        data = request.get_json()

        # Check if required fields are present
        if 'IPV4_SRC_ADDR' not in data or 'IPV4_DST_ADDR' not in data:
            return jsonify({"error": "Missing required fields: IPV4_SRC_ADDR and IPV4_DST_ADDR"}), 400
        
        # Preprocess the incoming data
        x_new = preprocess_data(data)

        # Make prediction
        predictions = model.predict(x_new)
        predicted_classes = np.argmax(predictions, axis=1)

        # Decode the predicted labels back to original attack names
        decoded_labels = label_encoder.inverse_transform(predicted_classes)

        # Format response
        response = [{"attack": attack} for attack in decoded_labels]

        return jsonify(response), 200

    except Exception as e:
        print(f"Error occurred: {str(e)}")  # Log the error
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
