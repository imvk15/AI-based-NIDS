from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
import tensorflow as tf
from keras import models


# Load the model
model = models.load_model(r"C:\Users\vivek\OneDrive\Desktop\proj\nids_model.h5")

# Recompile the model to ensure metrics are built
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Load the scaler and label encoder
scaler = joblib.load(r"C:\Users\vivek\OneDrive\Desktop\proj\scaler.pkl")
label_encoder = LabelEncoder()
label_encoder.classes_ = np.load(r"C:\Users\vivek\OneDrive\Desktop\proj\classes.npy", allow_pickle=True)

# Define the number of features (dynamically based on the scaler)
num_features = scaler.mean_.shape[0]

# Flask app
app = Flask(__name__)

def preprocess_data(data):
    try:
        # Convert incoming data (a list of dictionaries) to a DataFrame
        df = pd.DataFrame(data)
        print(f"Data before processing:\n{df}")  # Debugging: print incoming DataFrame

        # Define required columns
        required_columns = ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'SRC_PORT', 'DST_PORT', 'PROTOCOL', 'LENGTH', 'PAYLOAD_LEN']
        
        # Ensure the DataFrame has all the required columns and fill missing ones with zeros
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0

        print(f"Data after adding missing columns:\n{df}")  # Debugging: print DataFrame after adding missing columns

        # Preprocess the IP addresses (assuming data contains 'IPV4_SRC_ADDR' and 'IPV4_DST_ADDR')
        src_ip_split = df['IPV4_SRC_ADDR'].str.split('.', expand=True).astype(int)
        dst_ip_split = df['IPV4_DST_ADDR'].str.split('.', expand=True).astype(int)

        # Drop the original IPV4_SRC_ADDR and IPV4_DST_ADDR columns and combine the octets
        df = df.drop(['IPV4_SRC_ADDR', 'IPV4_DST_ADDR'], axis=1)
        df = pd.concat([df, src_ip_split, dst_ip_split], axis=1)

        print(f"Data after IP processing:\n{df}")  # Debugging: print DataFrame after IP processing

        # Normalize the data using the previously fitted scaler
        x = df.values
        x_scaled = scaler.transform(x)  # Use the fitted scaler

        print(f"Data after scaling:\n{x_scaled}")  # Debugging: print scaled data

        # Reshape the data for CNN model input (assuming model expects (batch_size, num_features, 1, 1))
        x_reshaped = x_scaled.reshape(-1, num_features, 1, 1)
        print(f"Data after reshaping:\n{x_reshaped}")  # Debugging: print reshaped data

        return x_reshaped

    except Exception as e:
        print(f"Error in preprocessing data: {str(e)}")  # Log error details
        raise  # Reraise the exception to be caught in the main route

@app.route('/detect', methods=['POST'])
def detect_attack():
    try:
        # Get data from the request
        data = request.get_json()  # No need for 'Dataset' key
        print(f"Received Data: {data}")  # Debugging: print received data

        # Check if required fields are present in the first dictionary
        if 'IPV4_SRC_ADDR' not in data[0] or 'IPV4_DST_ADDR' not in data[0]:
            return jsonify({"error": "Missing required fields: IPV4_SRC_ADDR and IPV4_DST_ADDR"}), 400

        # Preprocess the incoming data (direct data, not inside 'Dataset' key)
        x_new = preprocess_data(data)  # Directly pass the list of dictionaries

        # Log the preprocessed data shape and contents
        print(f"Preprocessed data shape: {x_new.shape}")
        print(f"Preprocessed data: {x_new}")  # Print the final processed data

        # Make prediction
        predictions = model.predict(x_new)
        print(f"Model Predictions: {predictions}")  # Log predictions to inspect model output

        predicted_classes = np.argmax(predictions, axis=1)

        # Decode the predicted labels back to original attack names
        decoded_labels = label_encoder.inverse_transform(predicted_classes)

        print(f"Decoded labels: {decoded_labels}")  # Debugging: print prediction results

        # Format response (with attack type)
        response = [{"attack": attack} for attack in decoded_labels]

        return jsonify(response), 200

    except Exception as e:
        # Log the exception to see exactly where it failed
        print(f"Error occurred during prediction: {str(e)}")  # Log the error
        return jsonify({"error": str(e), "trace": str(e)}), 500  # Return error details in response

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)  # Run the Flask server
