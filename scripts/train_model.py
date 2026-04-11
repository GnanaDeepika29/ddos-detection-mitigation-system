#!/usr/bin/env python3
"""
Enhanced Model Training: Auto-processes all CICDDoS2019 CSVs from data/datasets/
Fast/memory-friendly with chunking + sampling.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
import os

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
        logger.info(f"Loading {data_path}")
        if data_path.endswith('.parquet'):
            df = pd.read_parquet(data_path)
        elif data_path.endswith('.csv'):
            df = pd.read_csv(data_path)
        else:
            raise ValueError(f"Unsupported: {data_path}")
        logger.info(f"Loaded {len(df)} rows x {len(df.columns)} cols")
        return df

    def preprocess_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        logger.info("Preprocessing...")
        df = df.fillna(0)

        features = [
            'total_packets', 'total_bytes', 'total_flows', 'packets_per_second', 
            'bytes_per_second', 'flows_per_second', 'unique_src_ips', 'unique_dst_ips', 
            'entropy_src_ip', 'entropy_dst_ip', 'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'avg_packet_size', 'syn_ratio', 'rst_ratio'
        ]
        self.feature_names = [f for f in features if f in df.columns]
        X = df[self.feature_names].values

        y = df['is_attack'].values if 'is_attack' in df.columns else None

        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        logger.info(f"X shape: {X_scaled.shape}, features: {len(self.feature_names)}")
        return X_scaled, y

    def train_isolation_forest(self, X: np.ndarray) -> None:
        from sklearn.ensemble import IsolationForest
        logger.info("Training IsolationForest...")
        self.model = IsolationForest(
            contamination=self.config.get('contamination', 0.1),
            random_state=42, n_estimators=100, max_samples='auto'
        )
        self.model.fit(X)
        scores = np.clip(-self.model.score_samples(X), 0, None)
        self.training_stats['anomaly_scores'] = {
            'mean': float(np.mean(scores)), 'std': float(np.std(scores)),
            'p95': float(np.percentile(scores, 95))
        }

    def train_xgboost(self, X: np.ndarray, y: np.ndarray) -> None:
        import xgboost as xgb
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
        logger.info("Training XGBoost...")
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        self.model = xgb.XGBClassifier(**{k: self.config.get(k, v) for k, v in dict(
            n_estimators=100, max_depth=6, learning_rate=0.1).items()})
        self.model.fit(X_train, y_train, eval_set=[(X_val, y_val)], 
                       early_stopping_rounds=10, verbose=False)
        
        y_pred = self.model.predict(X_val)
        y_proba = self.model.predict_proba(X_val)[:,1]
        self.training_stats['metrics'] = {
            'accuracy': float(accuracy_score(y_val, y_pred)),
            'f1': float(f1_score(y_val, y_pred)),
            'roc_auc': float(roc_auc_score(y_val, y_proba))
        }

    def save_model(self, output_path: str) -> None:
        import joblib
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        model_type = self.config.get('model_type', 'isolation_forest')
        
        if model_type == 'xgboost':
            self.model.save_model(str(output_path))
        else:
            joblib.dump(self.model, output_path)
        
        scaler_path = output_path.with_suffix('.scaler.pkl')
        joblib.dump({'scaler': self.scaler, 'features': self.feature_names}, scaler_path)
        
        meta = {
            'type': model_type, 'features': self.feature_names,
            'stats': self.training_stats, 'config': self.config,
            'trained': datetime.now().isoformat()
        }
        (output_path.with_suffix('.meta.json')).write_text(json.dumps(meta, indent=2))
        logger.info(f"✅ Saved: {output_path} + scaler/meta")

def auto_process_all_datasets(sample_frac: float = 0.05) -> str:
    """
    Process all 16 CICDDoS2019 CSVs → single parquet (chunked/memory-safe).
    """
    scripts_dir = Path(__file__).parent
    sys.path.insert(0, str(scripts_dir))
    from process_cicddos2019 import main as process_csvs
    
    datasets_dir = Path.cwd() / 'data/datasets'
    output = 'data/processed/training_data.parquet'
    Path(output).parent.mkdir(exist_ok=True)
    
    csvs = list(datasets_dir.glob('*.csv'))
    if not csvs:
        raise FileNotFoundError(f"No datasets in {datasets_dir}")
    
    logger.info(f"Processing {len(csvs)} files @ {sample_frac} frac")
    import subprocess
    subprocess.run([sys.executable, scripts_dir / 'process_cicddos2019.py', 
                    '--input', str(datasets_dir), '--output', output, 
                    '--sample-frac', str(sample_frac)], check=True)
    return output

def main():
    parser = argparse.ArgumentParser(description='Fast ML Training for DDoS')
    parser.add_argument('--auto', '-a', action='store_true', help='Process all datasets/ CSVs')
    parser.add_argument('--data', help='Or use custom data path')
    parser.add_argument('--output', '-o', required=True, help='Model path')
    parser.add_argument('--type', '-t', default='xgboost', choices=['xgboost', 'isolation_forest'])
    parser.add_argument('--sample-frac', type=float, default=float(os.getenv('TRAIN_SAMPLE_FRAC', 0.05)))
    parser.add_argument('--config', help='JSON config')
    args = parser.parse_args()

    config = {'model_type': args.type}
    if args.config:
        config.update(json.load(open(args.config)))

    trainer = ModelTrainer(config)
    
    data_path = auto_process_all_datasets(args.sample_frac) if args.auto else args.data
    if not data_path:
        parser.error('Use --auto or --data')

    df = trainer.load_data(data_path)
    X, y = trainer.preprocess_data(df)

    if args.type == 'isolation_forest':
        trainer.train_isolation_forest(X)
    else:
        trainer.train_xgboost(X, y)

    trainer.save_model(args.output)
    print(f"✅ Ready: python scripts/run-local.sh  (Grafana:3000)")

if __name__ == '__main__':
    main()

