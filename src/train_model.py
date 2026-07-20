#!/usr/bin/env python3
"""
Обучение модели качества и живучести профилей.
Вычисляет survival_hours и reliability из probe_history,
обучает CatBoost, сохраняет метрики в БД и сравнивает с лучшей моделью.
"""

import sqlite3
import pandas as pd
import numpy as np
from catboost import CatBoostRegressor, Pool
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_squared_error, mean_absolute_error
import joblib
import logging
import os
from datetime import datetime, timedelta
from db import get_db

logger = logging.getLogger(__name__)

DB_PATH = 'configs/history.db'
MODEL_PATH = 'configs/quality_model.cbm'
MIN_SAMPLES = 50

def load_training_data(db_path=DB_PATH, min_samples=MIN_SAMPLES):
    conn = sqlite3.connect(db_path)
    query = '''
        SELECT pf.*,
               (SELECT AVG(latency) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as avg_latency,
               (SELECT COUNT(*) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as total_success,
               (SELECT COUNT(*) FROM probe_history WHERE profile_key = pf.profile_key) as total_probes,
               (SELECT MAX(latency) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as max_latency,
               (SELECT MIN(latency) FROM probe_history WHERE profile_key = pf.profile_key AND success=1) as min_latency
        FROM profile_features pf
        WHERE pf.count_7d >= ?
    '''
    df = pd.read_sql(query, conn, params=(min_samples,))
    if df.empty:
        return None, None, None, None

    survival_list = []
    for idx, row in df.iterrows():
        key = row['profile_key']
        probe_query = '''
            SELECT timestamp, success FROM probe_history
            WHERE profile_key = ? ORDER BY timestamp ASC
        '''
        probe_df = pd.read_sql(probe_query, conn, params=(key,))
        if probe_df.empty:
            survival_list.append(24.0)
            continue
        failures = probe_df[probe_df['success'] == 0]
        if failures.empty:
            survival_list.append(24.0)
            continue
        first_fail_time = pd.to_datetime(failures.iloc[0]['timestamp'])
        successes_before = probe_df[(probe_df['success'] == 1) & (pd.to_datetime(probe_df['timestamp']) < first_fail_time)]
        if successes_before.empty:
            survival_list.append(0.5)
            continue
        last_success_time = pd.to_datetime(successes_before.iloc[-1]['timestamp'])
        survival_hours = (first_fail_time - last_success_time).total_seconds() / 3600
        survival_list.append(max(0.1, survival_hours))

    df['survival_hours'] = survival_list
    df['reliability'] = df['success_7d'] / df['count_7d'].clip(lower=1)

    max_lat = df['avg_latency_7d'].max()
    latency_score = 100 * (1 - df['avg_latency_7d'] / max_lat) if max_lat > 0 else 50
    success_score = df['reliability'] * 100
    stability_score = 100 * (1 - df['latency_cv_24h'].clip(upper=1))
    df['quality_score'] = 0.4 * latency_score + 0.4 * success_score + 0.2 * stability_score

    conn.close()
    return df, df['quality_score'], df['survival_hours'], df['reliability']

def create_default_model():
    model = CatBoostRegressor(iterations=1, depth=1, verbose=False)
    X_dummy = np.array([[0.0]])
    y_dummy = np.array([50.0])
    model.fit(X_dummy, y_dummy)
    data = {
        'model': model,
        'features': [],
        'categorical': [],
        'rmse': 0.0,
        'mae': 0.0,
        'version': 'default'
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(data, MODEL_PATH)
    logger.info(f"Default stub model created at {MODEL_PATH}")

def train():
    df, quality, survival, reliability = load_training_data()
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

    # Кросс-валидация
    scores = cross_val_score(model, X, y, cv=5, scoring='neg_mean_squared_error')
    logger.info(f"Cross-validation scores: {scores}")
    mean_cv_rmse = np.sqrt(-scores.mean())
    logger.info(f"Mean CV RMSE: {mean_cv_rmse:.2f}")

    model.fit(X_train, y_train, eval_set=(X_test, y_test))
    rmse = mean_squared_error(y_test, model.predict(X_test), squared=False)
    mae = mean_absolute_error(y_test, model.predict(X_test))
    logger.info(f"Quality model RMSE: {rmse:.2f}, MAE: {mae:.2f}")

    db = get_db()
    version = f"catboost_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    db.save_model_version(version, rmse, mae, datetime.now().isoformat())

    best = db.get_best_model()
    if best is None or rmse < best['rmse']:
        data = {
            'model': model,
            'features': features,
            'categorical': categorical,
            'rmse': rmse,
            'mae': mae,
            'version': version
        }
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(data, MODEL_PATH)
        logger.info(f"✅ New best model saved (RMSE={rmse:.2f})")
    else:
        logger.info(f"ℹ️ Current model remains best (RMSE={best['rmse']:.2f})")

if __name__ == '__main__':
    train()
