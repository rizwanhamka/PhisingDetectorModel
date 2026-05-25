import pandas as pd
import numpy as np
import joblib
import warnings

warnings.filterwarnings("ignore")

from ucimlrepo import fetch_ucirepo

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    VotingClassifier
)

from sklearn.calibration import CalibratedClassifierCV

print("=" * 60)
print("ADVANCED PHISHING DETECTOR TRAINING")
print("=" * 60)

# =========================================================
# LOAD DATASET
# =========================================================

print("\n[1/5] Downloading dataset...")

dataset = fetch_ucirepo(id=327)

X = dataset.data.features
y = dataset.data.targets["result"]

print(f"Dataset shape: {X.shape}")

# =========================================================
# SPLIT
# =========================================================

print("\n[2/5] Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# =========================================================
# MODELS
# =========================================================

print("\n[3/5] Training ensemble models...")

rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=2,
    random_state=42,
    n_jobs=-1
)

et = ExtraTreesClassifier(
    n_estimators=300,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

gb = GradientBoostingClassifier(
    n_estimators=200,
    learning_rate=0.05,
    random_state=42
)

ensemble = VotingClassifier(
    estimators=[
        ("rf", rf),
        ("et", et),
        ("gb", gb)
    ],
    voting="soft"
)

model = CalibratedClassifierCV(
    estimator=ensemble,
    method="sigmoid",
    cv=3
)

model.fit(X_train, y_train)

# =========================================================
# EVALUATE
# =========================================================

print("\n[4/5] Evaluating...")

pred = model.predict(X_test)

acc = accuracy_score(y_test, pred)
f1 = f1_score(y_test, pred)

print(f"Accuracy : {acc:.4f}")
print(f"F1 Score : {f1:.4f}")

# =========================================================
# SAVE
# =========================================================

print("\n[5/5] Saving model...")

joblib.dump(model, "model.pkl")

feature_names = list(X.columns)

joblib.dump(feature_names, "features.pkl")

print("\nSaved:")
print("- model.pkl")
print("- features.pkl")

print("\nDONE")
