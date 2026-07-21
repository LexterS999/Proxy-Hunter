import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, model_path='configs/anomaly_model.joblib'):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self):
        try:
            self.model = joblib.load(self.model_path)
        except:
            self.model = None
            logger.warning("No anomaly model found, using default threshold")

    def train(self, features: List[Dict]):
        if len(features) < 10:
            logger.warning("Too few samples to train anomaly detector")
            return
        # Выбираем числовые признаки
        numeric_cols = [
            'avg_latency_24h', 'p90_latency_24h', 'latency_std_24h',
            'success_24h', 'count_24h', 'config_length'
        ]
        X = np.array([[f.get(c, 0) for c in numeric_cols] for f in features])
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(X)
        joblib.dump(self.model, self.model_path)
        logger.info("Anomaly detector trained and saved")

    def predict(self, feature: Dict) -> bool:
        if self.model is None:
            return False
        numeric_cols = [
            'avg_latency_24h', 'p90_latency_24h', 'latency_std_24h',
            'success_24h', 'count_24h', 'config_length'
        ]
        X = np.array([[feature.get(c, 0) for c in numeric_cols]])
        pred = self.model.predict(X)
        return pred[0] == -1  # -1 означает аномалию
