"""
Data preprocessing for the NSL-KDD intrusion detection dataset.
Mirrors the notebook pipeline: column naming → binary labelling → encoding → split.
"""

import logging
import os

import joblib
import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.model_selection import train_test_split

logging.basicConfig(
    filename="logs/ddos_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack", "level",
]

# Top-15 features selected via mutual_info_classif (from notebook)
SELECTED_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "wrong_fragment", "hot",
    "logged_in", "num_compromised", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
]

CAT_FEATURES = ["protocol_type", "service", "flag", "attack"]


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, header=None)
    df.columns = COLUMNS
    logger.info("Loaded dataset: %s rows, %s cols", *df.shape)
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.drop_duplicates()
    df["attack"] = df["attack"].apply(lambda x: "normal" if x == "normal" else "attack")
    return df


def encode(df: pd.DataFrame):
    le = preprocessing.LabelEncoder()
    for col in CAT_FEATURES:
        df[col] = le.fit_transform(df[col])
    # Persist the label encoder fitted on 'attack' for inference use
    os.makedirs("models", exist_ok=True)
    joblib.dump(le, "models/label_encoder.pkl")
    logger.info("Encoding complete; label encoder saved.")
    return df, le


def split(df: pd.DataFrame, test_size: float = 0.1, random_state: int = 43):
    X = df[SELECTED_FEATURES]
    y = df["attack"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state
    )
    logger.info("Split — train: %d, test: %d", len(X_train), len(X_test))
    return X_train, X_test, y_train, y_test


def run(data_path: str = "data/KDDTrain+.txt"):
    os.makedirs("logs", exist_ok=True)
    df = load_dataset(data_path)
    df = clean(df)
    df, le = encode(df)
    X_train, X_test, y_train, y_test = split(df)
    return X_train, X_test, y_train, y_test, le


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, _ = run()
    print(f"Train shape: {X_train.shape} | Test shape: {X_test.shape}")
