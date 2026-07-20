import sqlite3
import pandas as pd
import numpy as np
from catboost import CatBoostRegressor, Pool
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, mean_absolute_error
import joblib
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def load_training_data(db_path='configs/history.db', min_samples=10):
    conn = sqlite3.connect(db_path)
    # Загружаем признаки и целевые переменные
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
    if df.empty:
        return None, None, None, None
    # Целевые переменные (пример)
    df['quality_score'] = df.apply(
        lambda row: 100 * (row['success_7d'] / max(1, row['count_7d'])) * max(0, 1 - row['avg_latency_7d'] / 5000),
        axis=1
    )
    # survival_time (в часах) – упрощённо: разница между последним и первым успехом
    # Это можно вычислять из времени между проверками, но для демонстрации используем proxy
    df['survival_hours'] = np.random.uniform(1, 48, len(df))  # Заглушка, требует реальных данных
    df['reliability'] = df['success_7d'] / max(1, df['count_7d'])
    return df

def train():
    df = train_data = load_training_data()
    if df is None:
        logger.error("No training data available")
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
    # Преобразуем категории в строки
    for col in categorical:
        df[col] = df[col].astype(str)

    X = df[features + categorical]
    y_quality = df['quality_score']
    y_survival = df['survival_hours']
    y_reliability = df['reliability']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_quality, test_size=0.2, random_state=42
    )

    # Модель для качества
    model_quality = CatBoostRegressor(
        iterations=150,
        depth=5,
        cat_features=[features.index(c) for c in categorical],
        verbose=50,
        loss_function='RMSE',
        random_seed=42
    )
    model_quality.fit(X_train, y_train, eval_set=(X_test, y_test))
    rmse = mean_squared_error(y_test, model_quality.predict(X_test), squared=False)
    mae = mean_absolute_error(y_test, model_quality.predict(X_test))
    logger.info(f"Quality model RMSE: {rmse:.2f}, MAE: {mae:.2f}")

    # Сохраняем модель
    joblib.dump({
        'model': model_quality,
        'features': features,
        'categorical': categorical,
        'rmse': rmse,
        'mae': mae
    }, 'configs/quality_model.cbm')

    # Можно аналогично обучить модели для survival и reliability

if __name__ == '__main__':
    train()
