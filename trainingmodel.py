import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import confusion_matrix, classification_report
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import tensorflow as tf
from keras import layers, models, regularizers
import joblib

# Load the dataset
df = pd.read_csv(r"C:\Users\vivek\OneDrive\Desktop\DoS_DDoS_Normal.csv", nrows=1000)

# Convert IP addresses to string and split into octets
df['IPV4_SRC_ADDR'] = df['IPV4_SRC_ADDR'].astype(str)
df['IPV4_DST_ADDR'] = df['IPV4_DST_ADDR'].astype(str)
src_ip_split = df['IPV4_SRC_ADDR'].str.split('.', expand=True).astype(int)
dst_ip_split = df['IPV4_DST_ADDR'].str.split('.', expand=True).astype(int)

# Drop unnecessary columns and combine octets into the dataframe
df = df.drop(['Dataset'], axis=1)
df = pd.concat([df.drop(['IPV4_SRC_ADDR', 'IPV4_DST_ADDR'], axis=1), src_ip_split, dst_ip_split], axis=1)

# Keep the Attack column as an object type
df['Attack'] = df['Attack'].astype(str)
df['Attack'] = df['Attack'].replace({'Infilteration': 'Infiltration'})  # Fix typo if necessary

# Substituting into x and y
y = df['Attack'].values
x = df.drop('Attack', axis=1).values

# Data splitting
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=100)

# Normalize the data
scaler = StandardScaler()
x_train = scaler.fit_transform(x_train)
x_test = scaler.transform(x_test)  # Ensure this remains 2D

# Save the scaler
joblib.dump(scaler, r"C:\Users\vivek\OneDrive\Desktop\proj\scaler.pkl")

# Reshape data for CNN
num_features = x_train.shape[1]
x_train = x_train.reshape(-1, num_features, 1)  # Reshape for Conv1D
x_test = x_test.reshape(-1, num_features, 1)  # Reshape for Conv1D

# Encode labels
label_encoder = LabelEncoder()
y_train_encoded = label_encoder.fit_transform(y_train)
y_test_encoded = label_encoder.transform(y_test)

# One-hot encode the labels
num_classes = len(label_encoder.classes_)
y_train_onehot = tf.keras.utils.to_categorical(y_train_encoded, num_classes)
y_test_onehot = tf.keras.utils.to_categorical(y_test_encoded, num_classes)

# Define and compile the CNN model using Conv1D layers
model = models.Sequential()

# Conv1D layers
model.add(layers.Conv1D(32, 3, activation='relu', input_shape=(num_features, 1)))  # Conv1D layer
model.add(layers.MaxPooling1D(2))  # MaxPooling1D layer
model.add(layers.Conv1D(64, 3, activation='relu'))  # Conv1D layer
model.add(layers.MaxPooling1D(2))  # MaxPooling1D layer
model.add(layers.Conv1D(128, 3, activation='relu'))  # Conv1D layer
model.add(layers.MaxPooling1D(2))  # MaxPooling1D layer

# Flatten and Dense layers
model.add(layers.Flatten())
model.add(layers.Dense(128, activation='relu', kernel_regularizer=regularizers.l2(0.01)))  # Added L2 regularization
model.add(layers.Dropout(0.5))  # Dropout layer to prevent overfitting
model.add(layers.Dense(num_classes, activation='softmax'))

# Compile the model
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Custom Early Stopping Implementation
def early_stopping(train_history, patience=5):
    """
    Custom early stopping function to monitor validation loss and stop training if
    the validation loss does not improve for `patience` epochs.
    """
    best_val_loss = np.inf
    epochs_without_improvement = 0
    best_weights = None
    
    for epoch in range(len(train_history.history['val_loss'])):
        val_loss = train_history.history['val_loss'][epoch]
        
        # If validation loss improves, reset the counter and save the weights
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            epochs_without_improvement = 0
            best_weights = model.get_weights()
        else:
            epochs_without_improvement += 1
        
        # If no improvement for 'patience' epochs, stop training
        if epochs_without_improvement >= patience:
            print(f"Early stopping triggered at epoch {epoch+1}.")
            model.set_weights(best_weights)
            break

# Train the model
history = model.fit(x_train, y_train_onehot, epochs=20, batch_size=32, validation_data=(x_test, y_test_onehot), verbose=1)

# Apply early stopping manually
early_stopping(history, patience=5)

# Save the model after training
model.save(r"C:\Users\vivek\OneDrive\Desktop\proj\nids_model.h5")

# Evaluate the model to ensure metrics are built
loss, accuracy = model.evaluate(x_test, y_test_onehot, verbose=0)
print(f"Test loss: {loss:.4f}, Test accuracy: {accuracy:.4f}")

# Prediction section (optional, can be removed if not needed)
y_pred = model.predict(x_test)
y_pred_classes = np.argmax(y_pred, axis=1)

# Decode the predicted labels back to original attack names
y_true_decoded = label_encoder.inverse_transform(np.argmax(y_test_onehot, axis=1))
y_pred_decoded = label_encoder.inverse_transform(y_pred_classes)

# Print the confusion matrix and classification report
print(confusion_matrix(y_true_decoded, y_pred_decoded))
print(classification_report(y_true_decoded, y_pred_decoded))
