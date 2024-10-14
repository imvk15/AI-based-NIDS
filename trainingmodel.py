#Loading data
import pandas as pd
df = pd.read_csv(r"C:\Users\vivek\Downloads\archive\NF-UQ-NIDS-v2.csv",nrows=1000)
#print(df)


#substituting into x and y
y=df['Attack']
#print(y)
x=df.drop('Attack',axis=1)
#print(x)


#Data spliting
from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=100)
#print(x_test)


#CNN Model
import numpy as np
import tensorflow as tf
from keras import layers, models


# Assuming x_train, x_test, y_train, y_test are already defined and preprocessed
# Reshape the data to fit the CNN input format
# For example, if x_train has shape (num_samples, num_features)
# You might reshape it like this for CNN: (num_samples, height, width, channels)

# Example reshape (if your data is 1D):
num_features = x_train.shape[1]  # Assuming features are flattened
x_train = x_train.reshape(-1, num_features, 1, 1)  # Reshape to (num_samples, height, width, channels)
x_test = x_test.reshape(-1, num_features, 1, 1)  # Same for test set

# Normalize the data (if needed)
x_train = x_train.astype('float32') / np.max(x_train)
x_test = x_test.astype('float32') / np.max(x_test)

# One-hot encode the labels if it's a multi-class problem
num_classes = np.unique(y_train).size
y_train = tf.keras.utils.to_categorical(y_train, num_classes)
y_test = tf.keras.utils.to_categorical(y_test, num_classes)

# Define the CNN model
model = models.Sequential()

# Example CNN architecture
model.add(layers.Conv2D(32, (3, 1), activation='relu', input_shape=x_train.shape[1:]))
model.add(layers.MaxPooling2D((2, 1)))
model.add(layers.Conv2D(64, (3, 1), activation='relu'))
model.add(layers.MaxPooling2D((2, 1)))
model.add(layers.Conv2D(128, (3, 1), activation='relu'))
model.add(layers.MaxPooling2D((2, 1)))

# Flatten the output
model.add(layers.Flatten())
model.add(layers.Dense(128, activation='relu'))
model.add(layers.Dense(num_classes, activation='softmax'))  # Use 'sigmoid' for binary classification

# Compile the model
model.compile(optimizer='adam',
              loss='categorical_crossentropy',  # Use 'binary_crossentropy' for binary classification
              metrics=['accuracy'])

# Train the model
model.fit(x_train, y_train, epochs=10, batch_size=32, validation_data=(x_test, y_test))

# Evaluate the model
test_loss, test_accuracy = model.evaluate(x_test, y_test)
print(f'Test accuracy: {test_accuracy:.4f}')