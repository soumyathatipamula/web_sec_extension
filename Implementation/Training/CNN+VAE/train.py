import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, matthews_corrcoef
import matplotlib.pyplot as plt
from tensorflow.keras import layers, Model
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

# Load data
benign_samples = pd.read_csv("../../Dataset_prep/CNN+VAE/benign_samples.csv")
xss_payloads = pd.read_csv("../../Dataset_prep/CNN+VAE/xss_payloads.csv")

benign_samples = benign_samples[:775974]
benign_samples.drop(columns=['Unnamed: 0'], inplace=True)

cnn_dataset = pd.concat([benign_samples, xss_payloads], axis=0)
cnn_dataset.reset_index(drop=True, inplace=True)
cnn_dataset = cnn_dataset.sample(frac=1, random_state=42)

def preprocess(texts, max_len=100): # Removed normalize. normalization is not used in the CNN
    """Preprocesses text for CNN, ensuring consistent input shape."""
    processed = []
    for text in texts:
        encoded = [ord(c) % 256 for c in text[:max_len]]
        encoded += [0] * (max_len - len(encoded))
        processed.append(encoded)
    return np.array(processed)

# Preprocess data
cnn_X = preprocess(cnn_dataset["payload"], max_len=100).reshape(-1, 100, 1)
cnn_y = np.array(cnn_dataset["xss"]).reshape(-1, 1)

# Split data
cnn_X_train, cnn_X_test, cnn_y_train, cnn_y_test = train_test_split(
    cnn_X, cnn_y, test_size=0.2, random_state=42)

# Define CNN model (explicit input shape)
cnn_model = tf.keras.Sequential([
    layers.Input(shape=(100, 1)), #Explicit Input layer
    layers.DepthwiseConv1D(5, depth_multiplier=8, activation='relu'),
    layers.Conv1D(16, 1, activation='relu'),
    layers.GlobalMaxPooling1D(),
    layers.Dense(1, activation='sigmoid')
])

cnn_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()])

# Callbacks
early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
model_checkpoint = ModelCheckpoint(
    "best_CNN.keras", monitor='val_loss', mode='min', save_best_only=True)

# Train the model
history = cnn_model.fit(cnn_X_train, cnn_y_train, epochs=100, batch_size=32, validation_split=0.2, callbacks=[early_stopping, model_checkpoint])

# Load best model
try:
    cnn_model = tf.keras.models.load_model("best_CNN.keras")
except Exception as e:
    print(e)

# Evaluate the model
y_pred_probs = cnn_model.predict(cnn_X_test)
y_pred = (y_pred_probs > 0.5).astype(int)

precision = precision_score(cnn_y_test, y_pred)
recall = recall_score(cnn_y_test, y_pred)
f1 = f1_score(cnn_y_test, y_pred)
roc_auc = roc_auc_score(cnn_y_test, y_pred_probs)
mcc = matthews_corrcoef(cnn_y_test, y_pred)

print("CNN Evaluation:")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-score: {f1}")
print(f"ROC AUC: {roc_auc}")
print(f"MCC: {mcc}")
print(f"Training Accuracy: {history.history['accuracy'][-1]}")
print(f"Training Loss: {history.history['loss'][-1]}")
print(f"Validation Accuracy: {history.history['val_accuracy'][-1]}")
print(f"Validation Precision: {history.history['val_precision_3'][-1]}")
print(f"Validation Recall: {history.history['val_recall_3'][-1]}")
print(f"Validation Loss: {history.history['val_loss'][-1]}")
print(f"Validation Accuracy: {history.history['val_accuracy'][-1]}")

# Save for TensorFlow.js
cnn_model.save('xss_depthwise_cnn.h5')

# Plotting function
def plot_history(history, model_name):
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot(history.history['accuracy'], label='Training Accuracy')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
    plt.title(f'{model_name} Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title(f'{model_name} Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.show()

plot_history(history, 'CNN')

# Test predictions
test_samples = ["<p>Test</p>", "<script>alert(1)</script>"]
test_X = preprocess(test_samples, max_len=100).reshape(-1, 100, 1)
predictions = cnn_model.predict(test_X)

print("CNN Predictions:", predictions)

for i, prediction in enumerate(predictions):
    result = "Malicious" if prediction[0] > 0.5 else "Benign"
    print(f"Sample {i+1}: '{test_samples[i]}' - Prediction: {prediction[0]:.4f} - {result}")

# Convert for TensorFlow.js
# Use the input_shape flag to ensure the json file has the correct value.
# !tensorflowjs_converter --input_format keras --input_shape 100,1 xss_depthwise_cnn.h5 xss_depthwise_cnn_js