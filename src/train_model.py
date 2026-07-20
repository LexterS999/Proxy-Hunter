#!/usr/bin/env python3
"""
Обучение модели качества и живучести профилей.
Создаёт фиктивную модель, если данных недостаточно.
"""

import sqlite3
import pandas as pd
import numpy as np
from catboost import CatBoostRegressor, Pool
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, mean_absolute_error
import joblib
import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

DB_PATH = 'configs/history.db'
MODEL_PATH = 'configs/quality_model.cbm'
MIN_SAMPLES = 10

def load_training_data(db_path=DB_PATH, min_samples=MIN_SAMPLES):
    conn = sqlite3.connect(db_path)
    query = '''
        SELECT 
            pf.*,
            (SELECT AVG(latency) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as avg_latency,
            (SELECT COUNT(*) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as total_success,
            (SELECT COUNT(*) FROM probe_history WHERE profile_key = pf.profile_key) as total_probes,
            (SELECT MAX(latency) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as max_latency,
            (SELECT MIN(latency) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as min_latency
        FROM profile_features pf
        WHERE pf.count_7d >= ?
    '''
    df = pd.read_sql(query, conn, params=(min_samples,))
    conn.close()
    if df.empty:
        return None
    # Целевые переменные
    df['quality_score'] = df.apply(
        lambda row: 100 * (row['success_7d'] / max(1, row['count_7d'])) * max(0, 1 - row['avg_latency_7d'] / 5000),
        axis=1
    )
    # Для демонстрации используем proxy
    df['survival_hours'] = np.random.uniform(1, 48, len(df))
    df['reliability'] = df['success_7d'] / max(1, df['count_7d'])
    return df

def create_default_model():
    """Создаёт фиктивную модель для случаев, когда данных нет."""
    model = CatBoostRegressor(iterations=1, depth=1, verbose=False)
    X_dummy = np.array([[0.0]])
    y_dummy = np.array([50.0])
    model.fit(X_dummy, y_dummy)
    data = {
        'model': model,
        'features': [],
        'categorical': []
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(data, MODEL_PATH)
    logger.info(f"Default stub model created at {MODEL_PATH}")

def train():
    df = load_training_data()
    if df is None:
        logger.warning("Not enough training data, creating default model.")
        create_default_model()
        return

    features = [
        'count_24h', 'success_24h', 'avg_latency_24h', 'p90_latency_24h',
        'p99_latency_24h', 'latency_std_24h', 'latency_cv_24h', 'latency_trend_24h',
        'count_7d', 'success_7d', 'avg_latency_7d', 'check_interval_avg',
        'has_sni', 'has_host', 'has_path', 'has_pbk', 'has_flow',
        'is_reality', 'alter_id', 'config_length',
        'sni_count', 'host_count', 'path_count',
        'same_ip_count', 'same_ip_success_rate', 'same_sni_count'
    ]
    categorical = ['protocol', 'transport', 'ss_method']
    for col in categorical:
        df[col] = df[col].astype(str)

    X = df[features + categorical]
    y = df['quality_score']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = CatBoostRegressor(
        iterations=150,
        depth=5,
        cat_features=[features.index(c) for c in categorical],
        verbose=50,
        loss_function='RMSE',
        random_seed=42
    )
    model.fit(X_train, y_train, eval_set=(X_test, y_test))
    rmse = mean_squared_error(y_test, model.predict(X_test), squared=False)
    mae = mean_absolute_error(y_test, model.predict(X_test))
    logger.info(f"Quality model RMSE: {rmse:.2f}, MAE: {mae:.2f}")

    data = {
        'model': model,
        'features': features,
        'categorical': categorical,
        'rmse': rmse,
        'mae': mae
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(data, MODEL_PATH)
    logger.info(f"Model saved to {MODEL_PATH}")

if __name__ == '__main__':
    train()
