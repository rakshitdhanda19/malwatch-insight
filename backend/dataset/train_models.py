import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils.class_weight import compute_class_weight
import joblib
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.utils import to_categorical

# Create models folder
os.makedirs('models', exist_ok=True)

# Load dataset
df = pd.read_csv('final_dataset.csv')

print(f"Dataset shape: {df.shape}")
print("Columns:", df.columns)

if 'label' not in df.columns:
    raise ValueError("Dataset must contain 'label' column")

# Separate target labels
y = df['label']

# Numeric features (exclude label)
numeric_features = df.select_dtypes(include=[np.number]).drop(columns=['label'])
print(f"Numeric features shape: {numeric_features.shape}")

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(numeric_features)

# Encode labels (for RF and LSTM)
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# Split data for RF (labels as original strings)
X_train_rf, X_test_rf, y_train_rf, y_test_rf = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y)

# Split data for LSTM (use encoded categorical labels)
X_train_lstm, X_test_lstm, y_train_lstm, y_test_lstm = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

# One-hot encode categorical labels for LSTM
num_classes = len(np.unique(y_encoded))
y_train_cat = to_categorical(y_train_lstm, num_classes=num_classes)
y_test_cat = to_categorical(y_test_lstm, num_classes=num_classes)

# -------------------------------
# RANDOM FOREST MODEL TRAINING
# -------------------------------
print("\nTraining Random Forest with class_weight='balanced'...")

rf_clf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight='balanced'  # Important for imbalanced classes
)

rf_clf.fit(X_train_rf, y_train_rf)

y_pred_rf = rf_clf.predict(X_test_rf)

print(f"Random Forest Test Accuracy: {accuracy_score(y_test_rf, y_pred_rf):.4f}")
print("Random Forest Classification Report:")
print(classification_report(y_test_rf, y_pred_rf))

# Save Random Forest model and scaler
joblib.dump(scaler, 'models/scaler.joblib')
joblib.dump(rf_clf, 'models/random_forest_model.joblib')

# -------------------------------
# LSTM MODEL TRAINING
# -------------------------------

# Reshape input for LSTM: (samples, timesteps=1, features)
X_train_lstm = X_train_lstm.reshape((X_train_lstm.shape[0], 1, X_train_lstm.shape[1]))
X_test_lstm = X_test_lstm.reshape((X_test_lstm.shape[0], 1, X_test_lstm.shape[1]))

print("\nCalculating class weights for LSTM...")
# Compute class weights for LSTM training
class_weights = compute_class_weight(
    class_weight='balanced',
    classes=np.unique(y_train_lstm),
    y=y_train_lstm
)
class_weights_dict = dict(enumerate(class_weights))
print("Class weights:", class_weights_dict)

print("\nTraining LSTM model with BatchNormalization and EarlyStopping...")

model = Sequential([
    LSTM(64, input_shape=(1, X_train_lstm.shape[2]), return_sequences=False),
    BatchNormalization(),
    Dropout(0.3),
    Dense(64, activation='relu'),
    Dense(num_classes, activation='softmax')
])

model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

# Callbacks
early_stop = EarlyStopping(monitor='val_loss', patience=7, restore_best_weights=True)
checkpoint = ModelCheckpoint('models/lstm_best_weights.keras', monitor='val_loss', save_best_only=True)

model.fit(
    X_train_lstm, y_train_cat,
    epochs=50,
    batch_size=32,
    validation_data=(X_test_lstm, y_test_cat),
    class_weight=class_weights_dict,
    callbacks=[early_stop, checkpoint]
)

loss, accuracy = model.evaluate(X_test_lstm, y_test_cat)
print(f"LSTM Test Accuracy: {accuracy:.4f}")

# Save final LSTM model
model.save('models/lstm_model.keras')

print("\nAll models trained and saved successfully in 'models/' folder.")
