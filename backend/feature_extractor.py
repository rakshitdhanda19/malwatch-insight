import numpy as np
import os

def extract_features(filepath):
    try:
        # Read raw bytes (not meaningful, just placeholder)
        with open(filepath, 'rb') as f:
            raw = f.read()

        # Convert bytes to array of length 256 (same as your dataset columns, adjust as needed)
        array = np.frombuffer(raw[:1024], dtype=np.uint8)

        # Pad or trim to fixed size (e.g., 256 features)
        desired_length = 56
        if len(array) < desired_length:
            array = np.pad(array, (0, desired_length - len(array)))
        else:
            array = array[:desired_length]

        return array.reshape(1, -1)  # Shape: (1, 256)
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        raise e
