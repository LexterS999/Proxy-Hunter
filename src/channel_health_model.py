"""
Модели для оценки здоровья каналов: классификатор, прогнозирование времени жизни, ансамбль.
Использует логистическую регрессию, Prophet (если установлен), и набор правил.
"""

import logging
import numpy as np
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
import warnings

# Попытка импорта ML-библиотек
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    LogisticRegression = None
    StandardScaler = None

try:
    from prophet import Prophet
    PROPHET_AVAILABLE = True
except ImportError:
    PROPHET_AVAILABLE = False
    Prophet = None

from user_settings import (
    HEALTH_CLASSIFIER_ENABLED, LIFETIME_PREDICTOR_ENABLED,
    HEALTH_CLASSIFIER_FEATURES, LIFETIME_PREDICTOR_LOOKBACK,
    LIFETIME_PREDICTOR_FORECAST
)

logger = logging.getLogger(__name__)


class ChannelHealthClassifier:
    """
    Классификатор на основе логистической регрессии для оценки вероятности того,
    что канал является «здоровым».
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self.features = HEALTH_CLASSIFIER_FEATURES
        self._enabled = HEALTH_CLASSIFIER_ENABLED and SKLEARN_AVAILABLE
        self._trained = False

    def train(self, labelled_data: List[Dict]) -> None:
        """
        Обучает модель на размеченных данных.
        Ожидает список словарей с полями:
          - все признаки из self.features
          - 'label': 1 (здоров) или 0 (болен)
        """
        if not self._enabled:
            logger.debug("Health classifier disabled")
            return

        if not labelled_data or len(labelled_data) < 20:
            logger.warning("Not enough labelled data for classifier training")
            return

        X, y = self._extract_features(labelled_data)
        if X is None or len(X) < 10:
            return

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
        self.model.fit(X_scaled, y)
        self._trained = True
        logger.info(f"Health classifier trained on {len(X)} samples")

    def predict_health(self, channel_data: Dict) -> Tuple[float, float]:
        """
        Возвращает (вероятность здоровья, уверенность).
        Уверенность основана на близости к границе решения.
        """
        if not self._trained or not self._enabled:
            return 0.5, 0.0

        features = self._extract_single_features(channel_data)
        if features is None:
            return 0.5, 0.0

        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        prob = self.model.predict_proba(X_scaled)[0][1]

        # Уверенность: расстояние от границы 0.5
        confidence = 1.0 - 2.0 * abs(prob - 0.5)
        confidence = max(0.0, min(1.0, confidence))

        return prob, confidence

    def _extract_features(self, data_list: List[Dict]) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Извлекает признаки и метки для обучения."""
        X = []
        y = []
        for d in data_list:
            features = self._extract_single_features(d)
            if features is not None and 'label' in d:
                X.append(features)
                y.append(d['label'])
        if not X:
            return None, None
        return np.array(X), np.array(y)

    def _extract_single_features(self, data: Dict) -> Optional[List[float]]:
        """Извлекает признаки из одного словаря."""
        row = []
        for feat in self.features:
            val = data.get(feat, 0)
            if val is None:
                val = 0
            row.append(float(val))
        return row


class ChannelLifetimePredictor:
    """
    Прогнозирует оставшееся время жизни канала на основе исторических данных
    с использованием Prophet (если доступен) или простого экспоненциального сглаживания.
    """

    def __init__(self):
        self.models: Dict[str, Prophet] = {}
        self._enabled = LIFETIME_PREDICTOR_ENABLED and PROPHET_AVAILABLE
        self._fallback_models: Dict[str, Dict] = {}  # для простого прогноза

    def train_for_channel(self, channel_url: str, history: List[Dict]) -> None:
        """Обучает модель для конкретного канала на основе истории."""
        if not history or len(history) < 5:
            return

        if self._enabled:
            self._train_prophet(channel_url, history)
        else:
            self._train_fallback(channel_url, history)

    def predict_lifetime(self, channel_url: str, threshold: float = 30.0) -> Optional[float]:
        """
        Прогнозирует количество дней до падения ниже порога.
        Возвращает None, если модель не обучена или прогноз невозможен.
        """
        if channel_url in self.models and self._enabled:
            return self._predict_prophet(channel_url, threshold)
        elif channel_url in self._fallback_models:
            return self._predict_fallback(channel_url, threshold)
        return None

    def _train_prophet(self, channel_url: str, history: List[Dict]) -> None:
        """Обучает Prophet модель."""
        try:
            df = self._prepare_prophet_data(history)
            if df is None or len(df) < 5:
                return
            model = Prophet(
                changepoint_prior_scale=0.05,
                seasonality_prior_scale=10.0,
                yearly_seasonality=False,
                weekly_seasonality=True,
                daily_seasonality=False,
                interval_width=0.8
            )
            model.fit(df)
            self.models[channel_url] = model
        except Exception as e:
            logger.warning(f"Prophet training failed for {channel_url}: {e}")

    def _predict_prophet(self, channel_url: str, threshold: float) -> Optional[float]:
        """Прогнозирует с использованием Prophet."""
        model = self.models.get(channel_url)
        if not model:
            return None
        try:
            future = model.make_future_dataframe(periods=LIFETIME_PREDICTOR_FORECAST)
            forecast = model.predict(future)
            # Находим, когда прогноз yhat упадет ниже threshold
            below = forecast[forecast['yhat'] < threshold]
            if not below.empty:
                first_below = below.iloc[0]['ds']
                days = (first_below - datetime.now()).days
                return max(0, days)
            return LIFETIME_PREDICTOR_FORECAST  # > forecast horizon
        except Exception as e:
            logger.warning(f"Prophet prediction failed for {channel_url}: {e}")
            return None

    def _train_fallback(self, channel_url: str, history: List[Dict]) -> None:
        """Простой fallback: экспоненциальное сглаживание."""
        scores = [h.get('overall_score', 0) for h in history if h.get('overall_score') is not None]
        if len(scores) < 3:
            return
        # Сохраняем последние значения и средний интервал
        timestamps = [h.get('timestamp') for h in history if h.get('timestamp')]
        avg_interval = self._calc_avg_interval(timestamps)
        self._fallback_models[channel_url] = {
            'scores': scores,
            'avg_interval': avg_interval,
            'last_score': scores[-1] if scores else 0
        }

    def _predict_fallback(self, channel_url: str, threshold: float) -> Optional[float]:
        """Прогнозирует на основе экспоненциального сглаживания."""
        model = self._fallback_models.get(channel_url)
        if not model:
            return None
        scores = model['scores']
        avg_interval = model['avg_interval']
        last_score = model['last_score']

        if len(scores) < 3 or avg_interval <= 0:
            return None

        # Простая экстраполяция: линейный тренд
        x = np.arange(len(scores))
        slope = np.polyfit(x, scores, 1)[0]
        # Прогнозируем, когда достигнет threshold
        if slope >= 0:
            return LIFETIME_PREDICTOR_FORECAST  # не падает
        # Оценочное количество дней
        days_to_drop = (threshold - last_score) / slope
        days = days_to_drop * avg_interval
        return max(0, min(LIFETIME_PREDICTOR_FORECAST, days))

    @staticmethod
    def _prepare_prophet_data(history: List[Dict]) -> Optional['pd.DataFrame']:
        """Подготавливает DataFrame для Prophet."""
        import pandas as pd
        data = []
        for h in history:
            ts = h.get('timestamp')
            score = h.get('overall_score')
            if ts and score is not None:
                data.append({'ds': ts, 'y': score})
        if len(data) < 5:
            return None
        df = pd.DataFrame(data)
        df['ds'] = pd.to_datetime(df['ds'])
        return df

    @staticmethod
    def _calc_avg_interval(timestamps: List[str]) -> float:
        """Рассчитывает средний интервал между временными метками (в днях)."""
        if len(timestamps) < 2:
            return 1.0
        try:
            times = [datetime.fromisoformat(ts) for ts in timestamps if ts]
            if len(times) < 2:
                return 1.0
            intervals = [(times[i] - times[i-1]).total_seconds() / 86400 for i in range(1, len(times))]
            return sum(intervals) / len(intervals)
        except:
            return 1.0


class RulesEngine:
    """
    Набор детерминированных правил для оценки здоровья канала.
    """

    def evaluate(self, channel_data: Dict, history: List[Dict]) -> float:
        """
        Возвращает оценку в диапазоне [0, 1] на основе правил.
        """
        score = 0.5  # нейтральное

        # Правило 1: минимальное количество конфигов
        total = channel_data.get('total_configs', 0)
        if total < 3:
            score -= 0.2
        elif total < 10:
            score -= 0.1

        # Правило 2: доля валидных
        valid = channel_data.get('valid_configs', 0)
        if total > 0:
            valid_rate = valid / total
            if valid_rate < 0.05:
                score -= 0.3
            elif valid_rate < 0.2:
                score -= 0.1
            else:
                score += 0.1

        # Правило 3: успешность получения
        success = channel_data.get('success_count', 0)
        fails = channel_data.get('fail_count', 0)
        total_attempts = success + fails
        if total_attempts > 0:
            success_rate = success / total_attempts
            if success_rate < 0.3:
                score -= 0.2
            elif success_rate > 0.8:
                score += 0.2

        # Правило 4: тренд скора (если доступен)
        if 'score_trend' in channel_data:
            trend = channel_data['score_trend']
            if trend < -0.5:
                score -= 0.2
            elif trend < -0.2:
                score -= 0.1
            elif trend > 0.3:
                score += 0.2

        # Правило 5: волатильность
        if 'config_volatility' in channel_data:
            vol = channel_data['config_volatility']
            if vol > 0.8:
                score -= 0.15
            elif vol > 0.5:
                score -= 0.05

        # Правило 6: разнообразие протоколов
        protocol_counts = channel_data.get('protocol_counts', {})
        if protocol_counts:
            diversity = ChannelMetricsV2.calculate_protocol_diversity(protocol_counts)
            if diversity < 0.2:
                score -= 0.1
            elif diversity > 0.6:
                score += 0.1

        return max(0.0, min(1.0, score))


class EnsembleHealthModel:
    """
    Ансамблевая модель, объединяющая классификатор, прогнозирование времени жизни и правила.
    """

    def __init__(self):
        self.classifier = ChannelHealthClassifier()
        self.lifetime_predictor = ChannelLifetimePredictor()
        self.rules_engine = RulesEngine()
        self.weights = {
            'classifier': 0.5,
            'lifetime': 0.2,
            'rules': 0.3
        }

    def train_classifier(self, labelled_data: List[Dict]) -> None:
        """Обучает классификатор на размеченных данных."""
        self.classifier.train(labelled_data)

    def evaluate(self, channel_url: str, history: List[Dict], current_metrics: Dict) -> Dict:
        """
        Комплексная оценка канала.
        Возвращает словарь с health_score, confidence, days_left, recommendation и компонентами.
        """
        # 1. Классификатор
        prob, confidence = self.classifier.predict_health(current_metrics)
        classifier_score = prob

        # 2. Прогноз времени жизни
        self.lifetime_predictor.train_for_channel(channel_url, history)
        days_left = self.lifetime_predictor.predict_lifetime(channel_url, threshold=30.0)
        lifetime_score = min(1.0, (days_left / 30.0)) if days_left is not None else 0.5

        # 3. Правила
        rules_score = self.rules_engine.evaluate(current_metrics, history)

        # 4. Ансамбль
        final_score = (
            self.weights['classifier'] * classifier_score +
            self.weights['lifetime'] * lifetime_score +
            self.weights['rules'] * rules_score
        )
        health_score = final_score * 100

        # 5. Рекомендация
        if health_score < 30 and confidence > 0.7:
            recommendation = 'remove'
        elif health_score < 40:
            recommendation = 'watch'
        else:
            recommendation = 'keep'

        return {
            'health_score': round(health_score, 1),
            'confidence': round(confidence, 2),
            'days_left': days_left,
            'components': {
                'classifier': round(classifier_score, 3),
                'lifetime': round(lifetime_score, 3),
                'rules': round(rules_score, 3)
            },
            'recommendation': recommendation
        }
