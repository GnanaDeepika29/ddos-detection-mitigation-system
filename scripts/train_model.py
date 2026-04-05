#!/usr/bin/env python3
"""
Model Training Script for DDoS Detection System

Trains machine learning models for DDoS attack detection using historical data.
"""

import argparse
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelTrainer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.training_stats = {}

    def load_data(self, data_path: str) -> pd.DataFrame:
        logger.info(f"Loading data from {data_path}")
        if data_path.endswith('.parquet'):
            df = pd.read_parquet(data_path)
        elif data_path.endswith('.csv'):
            df = pd.read_csv(data_path)
        else:
            raise ValueError(f"Unsupported file format: {data_path}")
        logger.info(f"Loaded {len(df)} samples with {len(df.columns)} features")
        return df

    def preprocess_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        logger.info("Preprocessing data...")
        df = df.fillna(0)

        feature_columns = [
            'total_packets', 'total_bytes', 'total_flows',
            'packets_per_second', 'bytes_per_second', 'flows_per_second',
            'unique_src_ips', 'unique_dst_ips', 'entropy_src_ip',
            'entropy_dst_ip', 'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'avg_packet_size', 'syn_ratio', 'rst_ratio',
        ]
        self.feature_names = [f for f in feature_columns if f in df.columns]
        X = df[self.feature_names].values

        y = df['is_attack'].values if 'is_attack' in df.columns else None

        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        logger.info(f"Preprocessed {len(X_scaled)} samples with {len(self.feature_names)} features")
        return X_scaled, y

    def train_isolation_forest(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        from sklearn.ensemble import IsolationForest

        logger.info("Training Isolation Forest model...")
        contamination = self.config.get('contamination', 0.1)

        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False,
        )
        self.model.fit(X)

        raw = self.model.score_samples(X)
        scores = np.clip(-raw, 0, None)
        self.training_stats['anomaly_scores'] = {
            'mean': float(np.mean(scores)),
            'std': float(np.std(scores)),
            'min': float(np.min(scores)),
            'max': float(np.max(scores)),
            'p95_threshold': float(np.percentile(scores, 95)),
        }
        logger.info(f"Isolation Forest training complete.")

    def train_xgboost(self, X: np.ndarray, y: np.ndarray) -> None:
        import xgboost as xgb
        from sklearn.model_selection import train_test_split

        logger.info("Training XGBoost model...")
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model = xgb.XGBClassifier(
            n_estimators=self.config.get('n_estimators', 100),
            max_depth=self.config.get('max_depth', 6),
            learning_rate=self.config.get('learning_rate', 0.1),
            objective='binary:logistic',
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss',
        )
        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            early_stopping_rounds=10,
            verbose=False,
        )

        y_pred = self.model.predict(X_val)
        y_prob = self.model.predict_proba(X_val)[:, 1]

        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
        self.training_stats['metrics'] = {
            'accuracy': float(accuracy_score(y_val, y_pred)),
            'precision': float(precision_score(y_val, y_pred, zero_division=0)),
            'recall': float(recall_score(y_val, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_val, y_pred, zero_division=0)),
            'roc_auc': float(roc_auc_score(y_val, y_prob)),
        }
        logger.info(f"XGBoost training complete.")

    def save_model(self, output_path: str) -> None:
        import joblib

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        model_type = self.config.get('model_type', 'isolation_forest')

        if model_type == 'xgboost':
            self.model.save_model(str(output_path))
        else:
            joblib.dump(self.model, output_path)

        scaler_path = output_path.with_suffix('.scaler.pkl')
        joblib.dump({'scaler': self.scaler, 'feature_names': self.feature_names}, scaler_path)

        metadata = {
            'model_type': model_type,
            'feature_names': self.feature_names,
            'training_stats': self.training_stats,
            'config': self.config,
            'timestamp': datetime.now().isoformat(),
        }
        metadata_path = output_path.with_suffix('.meta.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Model saved to {output_path}")
        logger.info(f"Scaler saved to {scaler_path}")
        logger.info(f"Metadata saved to {metadata_path}")


def main():
    parser = argparse.ArgumentParser(description='Train DDoS detection models')
    parser.add_argument('--data', '-d', required=True, help='Path to training data (CSV or Parquet)')
    parser.add_argument('--output', '-o', required=True, help='Output path for model')
    parser.add_argument('--model-type', '-m', default='isolation_forest',
                        choices=['isolation_forest', 'xgboost'])
    parser.add_argument('--config', '-c', help='JSON hyperparameter config')
    args = parser.parse_args()

    config = {'model_type': args.model_type}
    if args.config:
        with open(args.config, 'r') as f:
            config.update(json.load(f))

    trainer = ModelTrainer(config)

    df = trainer.load_data(args.data)
    X, y = trainer.preprocess_data(df)

    if args.model_type == 'isolation_forest':
        trainer.train_isolation_forest(X, y)
    elif args.model_type == 'xgboost':
        if y is None:
            logger.error("XGBoost requires labeled data")
            sys.exit(1)
        trainer.train_xgboost(X, y)

    trainer.save_model(args.output)
    logger.info("Training completed successfully!")


if __name__ == '__main__':
    main()