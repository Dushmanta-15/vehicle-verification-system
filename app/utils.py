#user_utils
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from OpenSSL import crypto
import base64
import qrcode
import json
import cv2
import numpy as np
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import Name, NameAttribute, DNSName
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
import qrcode
import base64
import json
import io

import hashlib
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

from sqlalchemy import func, desc
from app.models.user import User
from app.models.vehicle import Vehicle
from app import db
import logging
logger = logging.getLogger(__name__)

class SimpleBlock:
    def __init__(self, index: int, transactions: List[Dict], previous_hash: str):
        self.index = index
        self.timestamp = datetime.utcnow().isoformat()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the block"""
        block_data = {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()
    
    def mine_block(self, difficulty: int = 2):
        """Simple proof of work mining"""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")
    
    def to_dict(self) -> Dict:
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }

class SimpleBlockchain:
    def __init__(self, storage_path: str = "blockchain_data"):
        self.storage_path = storage_path
        self.chain_file = os.path.join(storage_path, "blockchain.json")
        self.pending_transactions = []
        
        # Create storage directory
        os.makedirs(storage_path, exist_ok=True)
        
        # Load existing chain or create genesis block
        self.chain = self.load_chain()
        if not self.chain:
            self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = SimpleBlock(0, [], "0")
        genesis_block.mine_block()
        self.chain = [genesis_block]
        self.save_chain()
    
    def get_latest_block(self) -> SimpleBlock:
        return self.chain[-1]
    
    def add_transaction(self, transaction: Dict):
        """Add a transaction to pending transactions"""
        transaction['timestamp'] = datetime.utcnow().isoformat()
        transaction['tx_id'] = hashlib.sha256(
            json.dumps(transaction, sort_keys=True).encode()
        ).hexdigest()
        self.pending_transactions.append(transaction)
    
    def mine_pending_transactions(self) -> str:
        """Mine a new block with pending transactions"""
        if not self.pending_transactions:
            return None
        
        new_block = SimpleBlock(
            len(self.chain),
            self.pending_transactions.copy(),
            self.get_latest_block().hash
        )
        new_block.mine_block()
        
        self.chain.append(new_block)
        self.pending_transactions = []
        self.save_chain()
        
        return new_block.hash
    
    def verify_integrity(self) -> bool:
        """Verify the entire blockchain integrity"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if current block's hash is valid
            if current_block.hash != current_block.calculate_hash():
                return False
            
            # Check if current block points to previous block
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def get_transaction_history(self, data_type: str = None) -> List[Dict]:
        """Get all transactions, optionally filtered by type"""
        all_transactions = []
        for block in self.chain:
            for tx in block.transactions:
                if data_type is None or tx.get('type') == data_type:
                    tx['block_index'] = block.index
                    tx['block_hash'] = block.hash
                    all_transactions.append(tx)
        return all_transactions
    
    def find_transaction(self, tx_id: str) -> Optional[Dict]:
        """Find a specific transaction by ID"""
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('tx_id') == tx_id:
                    return {
                        **tx,
                        'block_index': block.index,
                        'block_hash': block.hash
                    }
        return None
    
    def save_chain(self):
        """Save blockchain to file"""
        chain_data = [block.to_dict() for block in self.chain]
        with open(self.chain_file, 'w') as f:
            json.dump(chain_data, f, indent=2)
    
    def load_chain(self) -> List[SimpleBlock]:
        """Load blockchain from file"""
        if not os.path.exists(self.chain_file):
            return []
        
        try:
            with open(self.chain_file, 'r') as f:
                chain_data = json.load(f)
            
            chain = []
            for block_data in chain_data:
                block = SimpleBlock(
                    block_data['index'],
                    block_data['transactions'],
                    block_data['previous_hash']
                )
                block.timestamp = block_data['timestamp']
                block.nonce = block_data['nonce']
                block.hash = block_data['hash']
                chain.append(block)
            
            return chain
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            return []

# Integration with your vehicle verification system
class VehicleBlockchainManager:
    def __init__(self, storage_path: str = "vehicle_blockchain"):
        self.blockchain = SimpleBlockchain(storage_path)
    
    def log_verification_attempt(self, verification_attempt):
        """Log verification attempt to blockchain"""
        transaction = {
            'type': 'verification_attempt',
            'data': {
                'verification_id': verification_attempt.id,
                'user_id': verification_attempt.user_id,
                'vehicle_id': getattr(verification_attempt, 'vehicle_id', None),
                'verification_type': verification_attempt.verification_type,
                'is_successful': verification_attempt.is_successful,
                'ip_address': verification_attempt.ip_address,
                'failure_reason': verification_attempt.failure_reason
            }
        }
        
        self.blockchain.add_transaction(transaction)
        block_hash = self.blockchain.mine_pending_transactions()
        
        return transaction.get('tx_id'), block_hash
    
    def log_vehicle_registration(self, vehicle):
        """Log vehicle registration to blockchain"""
        transaction = {
            'type': 'vehicle_registration',
            'data': {
                'vehicle_id': vehicle.id,
                'vehicle_number': vehicle.vehicle_number,
                'owner_name': vehicle.owner_name,
                'user_id': vehicle.user_id,
                'model': getattr(vehicle, 'model', None),
                'year': getattr(vehicle, 'year', None)
            }
        }
        
        self.blockchain.add_transaction(transaction)
        block_hash = self.blockchain.mine_pending_transactions()
        
        return transaction.get('tx_id'), block_hash
    
    def log_certificate_issuance(self, certificate):
        """Log certificate issuance to blockchain"""
        transaction = {
            'type': 'certificate_issuance',
            'data': {
                'certificate_id': certificate.id,
                'vehicle_id': certificate.vehicle_id,
                'issued_at': certificate.issued_at.isoformat(),
                'valid_until': certificate.valid_until.isoformat(),
                'is_active': certificate.is_active
            }
        }
        
        self.blockchain.add_transaction(transaction)
        block_hash = self.blockchain.mine_pending_transactions()
        
        return transaction.get('tx_id'), block_hash
    
    def verify_system_integrity(self) -> Dict:
        """Verify entire system integrity"""
        is_valid = self.blockchain.verify_integrity()
        
        # Get statistics
        verification_txs = self.blockchain.get_transaction_history('verification_attempt')
        vehicle_txs = self.blockchain.get_transaction_history('vehicle_registration')
        certificate_txs = self.blockchain.get_transaction_history('certificate_issuance')
        
        return {
            'blockchain_valid': is_valid,
            'total_blocks': len(self.blockchain.chain),
            'total_transactions': len(verification_txs) + len(vehicle_txs) + len(certificate_txs),
            'verification_attempts': len(verification_txs),
            'vehicle_registrations': len(vehicle_txs),
            'certificate_issuances': len(certificate_txs),
            'last_block_hash': self.blockchain.get_latest_block().hash
        }
    
    def get_audit_trail(self, entity_type: str, entity_id: int) -> List[Dict]:
        """Get complete audit trail for a specific entity"""
        all_transactions = self.blockchain.get_transaction_history()
        
        entity_transactions = []
        for tx in all_transactions:
            data = tx.get('data', {})
            
            # Check if transaction relates to the entity
            if (entity_type == 'user' and data.get('user_id') == entity_id) or \
               (entity_type == 'vehicle' and data.get('vehicle_id') == entity_id) or \
               (entity_type == 'verification' and data.get('verification_id') == entity_id):
                entity_transactions.append(tx)
        
        return sorted(entity_transactions, key=lambda x: x['timestamp'])

if __name__ == "__main__":
    # Test the blockchain
    blockchain_manager = VehicleBlockchainManager()
    
    # Test transaction
    test_transaction = {
        'type': 'test',
        'data': {'message': 'Testing blockchain functionality'}
    }
    
    blockchain_manager.blockchain.add_transaction(test_transaction)
    block_hash = blockchain_manager.blockchain.mine_pending_transactions()
    
    print(f"Test transaction added to block: {block_hash}")
    print(f"Blockchain integrity: {blockchain_manager.blockchain.verify_integrity()}")
    print(f"Total blocks: {len(blockchain_manager.blockchain.chain)}")

class AnomalyDetection:
    """
    Implements various anomaly detection algorithms for the Vehicle Verification System.
    This class provides methods to detect unusual activities or suspicious patterns
    related to user registrations, vehicle registrations, and system usage.
    """
    
    @staticmethod
    def detect_registration_spikes(days=None, minutes=None, hours=None, threshold_multiplier=3.0, force_refresh=False):
        """
        Detects unusual spikes in registration activity using statistical methods.
        
        Args:
            days (int, optional): Number of days to look back for the recent period
            minutes (int, optional): Number of minutes to look back (overrides days if provided)
            hours (int, optional): Number of hours to look back (overrides minutes and days if provided)
            threshold_multiplier (float): Multiplier for standard deviation to determine threshold
            force_refresh (bool): Whether to force a fresh database query
            
        Returns:
            dict: Contains anomaly status and details
        """
        try:
            # Calculate the date/time for comparison
            today = datetime.utcnow().date()
            now = datetime.utcnow()
            
            # Choose time window based on provided parameters (priority: hours > minutes > days)
            if hours is not None:
                comparison_date = now - timedelta(hours=hours)
                time_period = f"{hours} hour(s)"
            elif minutes is not None:
                comparison_date = now - timedelta(minutes=minutes)
                time_period = f"{minutes} minute(s)"
            else:
                # Default to days if neither hours nor minutes provided
                days = 1 if days is None else days
                comparison_date = today - timedelta(days=days)
                time_period = f"{days} day(s)"
            
            # For baseline, still use past 30 days data
            end_date = today - timedelta(days=1)  # exclude today for baseline
            start_date = end_date - timedelta(days=30)
            
            # User registrations - Force database query by using all() to avoid caching
            user_history = db.session.query(
                func.date(User.created_at).label('date'),
                func.count(User.id).label('count')
            ).filter(
                func.date(User.created_at) >= start_date,
                func.date(User.created_at) <= end_date
            ).group_by('date').all()
            
            # Vehicle registrations - Force database query by using all() to avoid caching
            vehicle_history = db.session.query(
                func.date(Vehicle.created_at).label('date'),
                func.count(Vehicle.id).label('count')
            ).filter(
                func.date(Vehicle.created_at) >= start_date,
                func.date(Vehicle.created_at) <= end_date
            ).group_by('date').all()
            
            # Calculate baseline statistics from actual database counts, not cached values
            user_counts = [count for _, count in user_history] if user_history else [0]
            vehicle_counts = [count for _, count in vehicle_history] if vehicle_history else [0]
            
            user_mean = np.mean(user_counts) if user_counts else 0
            user_std = np.std(user_counts) if len(user_counts) > 1 else 1
            vehicle_mean = np.mean(vehicle_counts) if vehicle_counts else 0
            vehicle_std = np.std(vehicle_counts) if len(vehicle_counts) > 1 else 1
            
            # Get recent activity based on the selected time period
            if hours is not None or minutes is not None:
                # Use datetime comparison for hours or minutes
                recent_users = db.session.query(func.count(User.id)).filter(
                    User.created_at >= comparison_date
                ).scalar() or 0
                
                recent_vehicles = db.session.query(func.count(Vehicle.id)).filter(
                    Vehicle.created_at >= comparison_date
                ).scalar() or 0
            else:
                # Use date comparison for days
                recent_users = db.session.query(func.count(User.id)).filter(
                    func.date(User.created_at) >= comparison_date
                ).scalar() or 0
                
                recent_vehicles = db.session.query(func.count(Vehicle.id)).filter(
                    func.date(Vehicle.created_at) >= comparison_date
                ).scalar() or 0
            
            # Always get fresh count for today
            users_today = db.session.query(func.count(User.id)).filter(
                func.date(User.created_at) == today
            ).scalar() or 0
            
            vehicles_today = db.session.query(func.count(Vehicle.id)).filter(
                func.date(Vehicle.created_at) == today
            ).scalar() or 0
            
            # Determine thresholds based on the time period
            if hours is not None:
                # Scale for hours
                hours_in_day = 24
                time_factor = hours / hours_in_day
                user_threshold = max(1, (user_mean * time_factor) + (user_std * threshold_multiplier * time_factor))
                vehicle_threshold = max(1, (vehicle_mean * time_factor) + (vehicle_std * threshold_multiplier * time_factor))
            elif minutes is not None:
                # Scale for minutes
                minutes_in_day = 1440  # 24 hours * 60 minutes
                time_factor = minutes / minutes_in_day
                user_threshold = max(1, (user_mean * time_factor) + (user_std * threshold_multiplier * time_factor))
                vehicle_threshold = max(1, (vehicle_mean * time_factor) + (vehicle_std * threshold_multiplier * time_factor))
            else:
                # No scaling needed for days
                user_threshold = max(1, user_mean + (user_std * threshold_multiplier))
                vehicle_threshold = max(1, vehicle_mean + (vehicle_std * threshold_multiplier))
            
            # Check if current counts exceed thresholds
            user_anomaly = recent_users > user_threshold
            vehicle_anomaly = recent_vehicles > vehicle_threshold
            
            # Log values for debugging
            logger.info(f"Anomaly Detection ({time_period}) - Recent users: {recent_users}, threshold: {user_threshold}")
            logger.info(f"Anomaly Detection ({time_period}) - Recent vehicles: {recent_vehicles}, threshold: {vehicle_threshold}")
            logger.info(f"Anomaly Detection - Users today: {users_today}")
            logger.info(f"Anomaly Detection - Vehicles today: {vehicles_today}")
            
            # Force refresh database session to avoid cached values
            db.session.commit()
            
            return {
                'has_anomaly': user_anomaly or vehicle_anomaly,
                'detection_method': 'statistical',
                'user_anomaly': {
                    'is_anomaly': user_anomaly,
                    'recent_count': recent_users,
                    'today_count': users_today,
                    'threshold': user_threshold,
                    'baseline_mean': user_mean,
                    'baseline_std': user_std,
                    'time_period': time_period
                },
                'vehicle_anomaly': {
                    'is_anomaly': vehicle_anomaly,
                    'recent_count': recent_vehicles,
                    'today_count': vehicles_today,
                    'threshold': vehicle_threshold,
                    'baseline_mean': vehicle_mean,
                    'baseline_std': vehicle_std,
                    'time_period': time_period
                }
            }
            
        except Exception as e:
            logger.error(f"Error in detect_registration_spikes: {str(e)}")
            return {'has_anomaly': False, 'detection_method': 'statistical', 'error': str(e)}
    
   # Update the detect_ml_anomalies method in AnomalyDetection class

    @staticmethod
    def detect_ml_anomalies(days=30, contamination=0.05):
        """
        Detects anomalies using Isolation Forest, a machine learning technique.
        
        Args:
            days (int): Number of days of historical data to analyze
            contamination (float): Expected proportion of anomalies in the dataset
            
        Returns:
            dict: Contains anomaly status and details
        """
        try:
            # Import required ML libraries
            from sklearn.ensemble import IsolationForest
            import pandas as pd
            from app.models.request_log import RequestLog
            
            # Calculate the date range for analysis
            today = datetime.utcnow().date()
            start_date = today - timedelta(days=days)
            
            # Get user registration data by day
            user_registrations = db.session.query(
                func.date(User.created_at).label('date'),
                func.count(User.id).label('count')
            ).filter(
                func.date(User.created_at) >= start_date
            ).group_by('date').all()
            
            # Get vehicle registration data by day
            vehicle_registrations = db.session.query(
                func.date(Vehicle.created_at).label('date'),
                func.count(Vehicle.id).label('count')
            ).filter(
                func.date(Vehicle.created_at) >= start_date
            ).group_by('date').all()
            
            # Get verification data by day
            from app.models.verification_attempt import VerificationAttempt
            from sqlalchemy import case
            
            verification_data = db.session.query(
                func.date(VerificationAttempt.created_at).label('date'),
                func.count(VerificationAttempt.id).label('total'),
                func.sum(case([(VerificationAttempt.is_successful == True, 1)], else_=0)).label('successful'),
                func.sum(case([(VerificationAttempt.is_successful == False, 1)], else_=0)).label('failed')
            ).filter(
                func.date(VerificationAttempt.created_at) >= start_date
            ).group_by('date').all()
            
            # Create a set of all dates
            all_dates = set()
            for item in user_registrations + vehicle_registrations + verification_data:
                all_dates.add(item.date)
            
            # Sort dates
            all_dates = sorted(list(all_dates))
            
            # Create a DataFrame with all dates
            data = []
            for date in all_dates:
                # Find corresponding data for this date
                user_count = next((item.count for item in user_registrations if item.date == date), 0)
                vehicle_count = next((item.count for item in vehicle_registrations if item.date == date), 0)
                
                # Get verification data
                verification_item = next((item for item in verification_data if item.date == date), None)
                total_verifications = verification_item.total if verification_item else 0
                successful_verifications = verification_item.successful if verification_item else 0
                failed_verifications = verification_item.failed if verification_item else 0
                
                # Calculate success rate
                success_rate = 0
                if total_verifications > 0:
                    success_rate = (successful_verifications / total_verifications) * 100
                
                # Add to data list
                data.append({
                    'date': date,
                    'user_count': user_count,
                    'vehicle_count': vehicle_count,
                    'total_verifications': total_verifications,
                    'successful_verifications': successful_verifications,
                    'failed_verifications': failed_verifications,
                    'success_rate': success_rate
                })
            
            # Create DataFrame
            df = pd.DataFrame(data)
            
            # Check if we have enough data for ML
            if len(df) < 5:
                logger.warning("Not enough data for ML anomaly detection. Need at least 5 days of data.")
                
                # CHANGE: Even if we don't have enough data for ML, check for recent anomalies
                # Get current anomalies count from RequestLog
                current_hour = datetime.utcnow() - timedelta(hours=1)
                recent_anomalous_requests = RequestLog.query.filter(
                    RequestLog.has_anomaly == True,
                    RequestLog.created_at >= current_hour
                ).count()
                
                # Get current failed verifications
                recent_failed_verifications = VerificationAttempt.query.filter(
                    VerificationAttempt.is_successful == False,
                    VerificationAttempt.created_at >= current_hour
                ).count()
                
                total_recent_anomalies = recent_anomalous_requests + recent_failed_verifications
                
                return {
                    'has_anomaly': total_recent_anomalies > 0,
                    'detection_method': 'hybrid',
                    'error': 'Not enough data for ML analysis (need at least 5 days), using recent anomalies instead',
                    'model_info': {
                        'algorithm': 'Isolation Forest + Recent Activity',
                        'days_analyzed': days
                    },
                    'total_anomalies_found': total_recent_anomalies,
                    'anomaly_details': [{
                        'date': datetime.utcnow().strftime('%Y-%m-%d'),
                        'unusual_metrics': [{
                            'metric': 'recent_anomalous_requests',
                            'value': recent_anomalous_requests,
                            'normal_range': '0 to 0'
                        }, {
                            'metric': 'recent_failed_verifications',
                            'value': recent_failed_verifications,
                            'normal_range': '0 to 0'
                        }]
                    }] if total_recent_anomalies > 0 else []
                }
            
            # Prepare features for anomaly detection
            features = ['user_count', 'vehicle_count', 'total_verifications', 'success_rate']
            X = df[features].values
            
            # Create and train Isolation Forest model
            model = IsolationForest(
                contamination=contamination,  # Expected proportion of anomalies
                random_state=42,              # For reproducibility
                n_estimators=100              # Number of trees
            )
            
            # Fit the model and predict
            # -1 for anomalies, 1 for normal
            predictions = model.fit_predict(X)
            
            # Add predictions to DataFrame
            df['anomaly'] = predictions
            
            # Find anomalous dates
            anomalous_days = df[df['anomaly'] == -1]
            
            # Check for recent anomalies (last 3 days)
            recent_date = today - timedelta(days=3)
            recent_anomalies = anomalous_days[anomalous_days['date'] >= recent_date]
            
            # CHANGE: Also check for current anomalies in the system
            current_hour = datetime.utcnow() - timedelta(hours=1)
            recent_anomalous_requests = RequestLog.query.filter(
                RequestLog.has_anomaly == True,
                RequestLog.created_at >= current_hour
            ).count()
            
            recent_failed_verifications = VerificationAttempt.query.filter(
                VerificationAttempt.is_successful == False,
                VerificationAttempt.created_at >= current_hour
            ).count()
            
            total_recent_anomalies = recent_anomalous_requests + recent_failed_verifications + len(recent_anomalies)
            has_recent_anomaly = total_recent_anomalies > 0
            
            # Prepare anomaly details
            anomaly_details = []
            
            # Add ML-detected anomalies
            for _, row in anomalous_days.iterrows():
                # Determine which metrics contributed to the anomaly
                normal_days = df[df['anomaly'] == 1]
                unusual_metrics = []
                
                for feature in features:
                    feature_mean = normal_days[feature].mean()
                    feature_std = normal_days[feature].std() or 1  # Use 1 if std is 0
                    
                    # If value is more than 2 std away from mean, consider it contributing to anomaly
                    if abs(row[feature] - feature_mean) > 2 * feature_std:
                        unusual_metrics.append({
                            'metric': feature,
                            'value': row[feature],
                            'normal_range': f"{feature_mean - 2*feature_std:.2f} to {feature_mean + 2*feature_std:.2f}"
                        })
                
                anomaly_details.append({
                    'date': row['date'].strftime('%Y-%m-%d'),
                    'unusual_metrics': unusual_metrics
                })
            
            # If there are current anomalies but no ML-detected ones, add them to the details
            if recent_anomalous_requests > 0 or recent_failed_verifications > 0:
                current_anomalies = {
                    'date': datetime.utcnow().strftime('%Y-%m-%d'),
                    'unusual_metrics': []
                }
                
                if recent_anomalous_requests > 0:
                    current_anomalies['unusual_metrics'].append({
                        'metric': 'recent_anomalous_requests',
                        'value': recent_anomalous_requests,
                        'normal_range': '0 to 0'
                    })
                    
                if recent_failed_verifications > 0:
                    current_anomalies['unusual_metrics'].append({
                        'metric': 'recent_failed_verifications',
                        'value': recent_failed_verifications,
                        'normal_range': '0 to 0'
                    })
                    
                anomaly_details.append(current_anomalies)
            
            return {
                'has_anomaly': has_recent_anomaly,
                'detection_method': 'hybrid',
                'anomaly_details': anomaly_details,
                'model_info': {
                    'algorithm': 'Isolation Forest',
                    'contamination': contamination,
                    'days_analyzed': days
                },
                'total_anomalies_found': total_recent_anomalies,
                'ml_anomalies_found': len(anomalous_days),
                'recent_anomalies_found': len(recent_anomalies)
            }
                
        except Exception as e:
            import traceback
            logger.error(f"Error in ML anomaly detection: {str(e)}")
            logger.error(traceback.format_exc())
            
            # CHANGE: Even if ML fails, try to get current anomalies
            try:
                from app.models.request_log import RequestLog
                from app.models.verification_attempt import VerificationAttempt
                
                current_hour = datetime.utcnow() - timedelta(hours=1)
                recent_anomalous_requests = RequestLog.query.filter(
                    RequestLog.has_anomaly == True,
                    RequestLog.created_at >= current_hour
                ).count()
                
                recent_failed_verifications = VerificationAttempt.query.filter(
                    VerificationAttempt.is_successful == False,
                    VerificationAttempt.created_at >= current_hour
                ).count()
                
                total_recent_anomalies = recent_anomalous_requests + recent_failed_verifications
                
                return {
                    'has_anomaly': total_recent_anomalies > 0,
                    'detection_method': 'fallback',
                    'error': str(e),
                    'model_info': {
                        'algorithm': 'Recent Activity Fallback',
                        'days_analyzed': 0
                    },
                    'total_anomalies_found': total_recent_anomalies,
                    'anomaly_details': [{
                        'date': datetime.utcnow().strftime('%Y-%m-%d'),
                        'unusual_metrics': [{
                            'metric': 'ML Error',
                            'value': str(e),
                            'normal_range': 'N/A'
                        }]
                    }] if total_recent_anomalies > 0 else []
                }
            except:
                # If all else fails
                return {
                    'has_anomaly': False,
                    'detection_method': 'machine_learning',
                    'error': str(e),
                    'traceback': traceback.format_exc()
                }
        
    @staticmethod
    def get_consolidated_anomalies(hours=1):
        """
        Combines results from both statistical and ML-based anomaly detection
        
        Args:
            hours (int): Hours to look back for statistical detection
            
        Returns:
            dict: Combined anomaly results
        """
        # Get statistical anomalies
        statistical_anomalies = AnomalyDetection.detect_registration_spikes(hours=hours)
        
        # Get ML-based anomalies
        try:
            ml_anomalies = AnomalyDetection.detect_ml_anomalies()
        except Exception as e:
            logger.error(f"Error in ML anomaly detection during consolidation: {str(e)}")
            ml_anomalies = {'has_anomaly': False, 'detection_method': 'machine_learning', 'error': str(e)}
        
        # Combine results
        has_anomaly = (
            statistical_anomalies.get('has_anomaly', False) or 
            ml_anomalies.get('has_anomaly', False)
        )
        
        return {
            'has_anomaly': has_anomaly,
            'statistical_analysis': statistical_anomalies,
            'ml_analysis': ml_anomalies,
            'detection_methods_used': ['Statistical threshold analysis', 'Isolation Forest (Machine Learning)']
        }
    
    @staticmethod
    def detect_multiple_registrations(user_id, threshold=3, time_window_hours=24, time_window_minutes=None):
        """
        Detects if a user has registered an unusual number of vehicles in a short time.
        
        Args:
            user_id (int): User ID to check
            threshold (int): Number of registrations that trigger an anomaly
            time_window_hours (int): Time window in hours to consider
            time_window_minutes (int, optional): Time window in minutes (overrides hours if provided)
            
        Returns:
            dict: Contains anomaly status and details
        """
        try:
            # Calculate the time threshold
            if time_window_minutes is not None:
                time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
            else:
                time_threshold = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            # Count recent vehicle registrations by this user
            recent_registrations = Vehicle.query.filter(
                Vehicle.user_id == user_id,
                Vehicle.created_at >= time_threshold
            ).count()
            
            is_anomaly = recent_registrations >= threshold
            
            time_window_info = {
                'time_window_minutes': time_window_minutes
            } if time_window_minutes is not None else {
                'time_window_hours': time_window_hours
            }
            
            if is_anomaly:
                # Get the vehicles for details
                vehicles = Vehicle.query.filter(
                    Vehicle.user_id == user_id,
                    Vehicle.created_at >= time_threshold
                ).order_by(Vehicle.created_at.desc()).all()
                
                return {
                    'is_anomaly': True,
                    'count': recent_registrations,
                    'threshold': threshold,
                    **time_window_info,
                    'vehicles': [
                        {
                            'id': v.id,
                            'vehicle_number': v.vehicle_number,
                            'created_at': v.created_at
                        } for v in vehicles
                    ]
                }
            
            return {
                'is_anomaly': False,
                'count': recent_registrations,
                'threshold': threshold,
                **time_window_info
            }
            
        except Exception as e:
            logger.error(f"Error in detect_multiple_registrations: {str(e)}")
            return {'is_anomaly': False, 'error': str(e)}
    
    @staticmethod
    def detect_verification_failures(threshold=3, time_window_hours=1, time_window_minutes=None):
        """
        Detects an unusual number of verification failures in the system.
        
        Args:
            threshold (int): Number of failures that trigger an anomaly
            time_window_hours (int): Time window in hours to consider
            time_window_minutes (int, optional): Time window in minutes (overrides hours if provided)
            
        Returns:
            dict: Contains anomaly status and details
        """
        try:
            from app.models.verification_attempt import VerificationAttempt
            
            # Calculate the time threshold
            if time_window_minutes is not None:
                time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
            else:
                time_threshold = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            # Count recent verification failures
            recent_failures = VerificationAttempt.query.filter(
                VerificationAttempt.is_successful == False,
                VerificationAttempt.created_at >= time_threshold
            ).count()
            
            # Get total verification attempts in this time window
            total_attempts = VerificationAttempt.query.filter(
                VerificationAttempt.created_at >= time_threshold
            ).count()
            
            # Calculate failure rate if there were any attempts
            failure_rate = 0
            if total_attempts > 0:
                failure_rate = (recent_failures / total_attempts) * 100
            
            is_anomaly = recent_failures >= threshold
            
            time_window_info = {
                'time_window_minutes': time_window_minutes
            } if time_window_minutes is not None else {
                'time_window_hours': time_window_hours
            }
            
            if is_anomaly:
                # Get the failure details
                failures = VerificationAttempt.query.filter(
                    VerificationAttempt.is_successful == False,
                    VerificationAttempt.created_at >= time_threshold
                ).order_by(VerificationAttempt.created_at.desc()).all()
                
                return {
                    'is_anomaly': True,
                    'count': recent_failures,
                    'threshold': threshold,
                    **time_window_info,
                    'failure_rate': failure_rate,
                    'total_attempts': total_attempts,
                    'failures': [
                        {
                            'id': f.id,
                            'verification_type': f.verification_type,
                            'failure_reason': f.failure_reason,
                            'created_at': f.created_at
                        } for f in failures
                    ]
                }
            
            return {
                'is_anomaly': False,
                'count': recent_failures,
                'threshold': threshold,
                **time_window_info,
                'failure_rate': failure_rate,
                'total_attempts': total_attempts
            }
            
        except Exception as e:
            logger.error(f"Error in detect_verification_failures: {str(e)}")
            return {'is_anomaly': False, 'error': str(e)}
    
    @staticmethod
    def detect_unusual_access_patterns(ip_address, threshold=10, time_window_minutes=5):
        """
        Detects unusual access patterns such as rapid consecutive requests
        from the same IP address.
        
        Args:
            ip_address (str): IP address to check
            threshold (int): Number of requests that trigger an anomaly
            time_window_minutes (int): Time window in minutes to consider
            
        Returns:
            dict: Contains anomaly status and details
        """
        try:
            from app.models.request_log import RequestLog
            
            # Calculate the time threshold
            time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
            
            # Count recent requests from this IP
            request_count = RequestLog.query.filter(
                RequestLog.ip_address == ip_address,
                RequestLog.created_at >= time_threshold
            ).count()
            
            # Get average requests per minute across all IPs for comparison
            all_ips_count = RequestLog.query.filter(
                RequestLog.created_at >= time_threshold
            ).count()
            
            # Calculate requests per minute for this IP
            requests_per_minute = request_count / time_window_minutes if time_window_minutes > 0 else 0
            
            # Determine if there's an anomaly
            is_anomaly = request_count >= threshold
            
            if is_anomaly:
                # Get the request details
                requests = RequestLog.query.filter(
                    RequestLog.ip_address == ip_address,
                    RequestLog.created_at >= time_threshold
                ).order_by(RequestLog.created_at.desc()).all()
                
                # Look for patterns in endpoints
                endpoints = {}
                methods = {}
                response_times = []
                
                for req in requests:
                    # Count endpoint occurrences
                    if req.endpoint in endpoints:
                        endpoints[req.endpoint] += 1
                    else:
                        endpoints[req.endpoint] = 1
                        
                    # Count HTTP method occurrences
                    if req.method in methods:
                        methods[req.method] += 1
                    else:
                        methods[req.method] = 1
                        
                    # Collect response times
                    if req.response_time_ms:
                        response_times.append(req.response_time_ms)
                
                # Calculate average response time
                avg_response_time = sum(response_times) / len(response_times) if response_times else 0
                
                # Sort endpoints and methods by count (most frequent first)
                sorted_endpoints = sorted(endpoints.items(), key=lambda x: x[1], reverse=True)
                sorted_methods = sorted(methods.items(), key=lambda x: x[1], reverse=True)
                
                return {
                    'is_anomaly': True,
                    'ip_address': ip_address,
                    'request_count': request_count,
                    'threshold': threshold,
                    'time_window_minutes': time_window_minutes,
                    'requests_per_minute': requests_per_minute,
                    'most_frequent_endpoints': dict(sorted_endpoints[:5]),  # Top 5 endpoints
                    'http_methods': dict(sorted_methods),
                    'avg_response_time': avg_response_time,
                    'details': [
                        {
                            'endpoint': r.endpoint,
                            'method': r.method,
                            'status_code': r.status_code,
                            'response_time_ms': r.response_time_ms,
                            'created_at': r.created_at
                        } for r in requests[:10]  # Limit to 10 most recent for brevity
                    ]
                }
            
            return {
                'is_anomaly': False,
                'ip_address': ip_address,
                'request_count': request_count,
                'threshold': threshold,
                'requests_per_minute': requests_per_minute
            }
            
        except Exception as e:
            logger.error(f"Error in detect_unusual_access_patterns: {str(e)}")
            return {'is_anomaly': False, 'error': str(e)}

class CryptoUtils:
    @staticmethod
    def generate_key_pair():
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def generate_certificate(user_data, private_key_pem):
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        # Create certificate builder
        builder = x509.CertificateBuilder()

        # Set subject details
        subject = Name([
            NameAttribute(NameOID.COMMON_NAME, user_data['username']),
            NameAttribute(NameOID.EMAIL_ADDRESS, user_data['email'])
        ])

        # Set issuer (self-signed for this example)
        issuer = subject

        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())

        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

        # Sign certificate
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )

        # Serialize certificate
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

        return cert_pem

    @staticmethod
    def get_certificate_info(certificate_pem):
        try:
            # Load certificate
            cert = x509.load_pem_x509_certificate(certificate_pem)

            # Extract information
            info = {
                'subject': {
                    'common_name': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                    'email': cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value
                },
                'issuer': {
                    'common_name': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                    'organization': 'Vehicle Verification System'
                },
                'validity': {
                    'not_before': cert.not_valid_before,
                    'not_after': cert.not_valid_after
                },
                'serial_number': cert.serial_number
            }
            return info
        except Exception as e:
            print(f"Error getting certificate info: {str(e)}")
            raise

    @staticmethod
    def encrypt_vehicle_data(data, public_key_pem):
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem
        )

        # Convert data to JSON string and encode to bytes
        data_bytes = json.dumps(data).encode()

        # Encrypt the data
        ciphertext = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(ciphertext).decode()

    @staticmethod
    def decrypt_vehicle_data(encrypted_data, private_key_pem):
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        # Decode from base64 and decrypt
        ciphertext = base64.b64decode(encrypted_data)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Parse JSON string
        return json.loads(plaintext.decode())

    @staticmethod
    def sign_data(data, private_key_pem):
        try:
            print("\nStarting data signing...")
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )

            # For consistency, convert dict to JSON string
            data_to_sign = json.dumps(data) if isinstance(data, dict) else data
            print(f"Data to sign (first 100 chars): {str(data_to_sign)[:100]}")

            # Create signature
            signature = private_key.sign(
                data_to_sign.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            signed = base64.b64encode(signature).decode()
            print(f"Signature generated (first 50 chars): {signed[:50]}")
            return signed
        except Exception as e:
            print(f"Error in sign_data: {str(e)}")
            raise

    @staticmethod
    def verify_signature(encrypted_data, signature, public_key_pem):
        try:
            print("\nStarting signature verification...")
            print(f"Encrypted data (first 50 chars): {encrypted_data[:50]}")
            print(f"Signature (first 50 chars): {signature[:50]}")

            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem)

            try:
                # Verify signature using the encrypted data directly
                public_key.verify(
                    base64.b64decode(signature),
                    encrypted_data.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Signature verification successful!")
                return True
            except Exception as e:
                print(f"Signature verification failed: {str(e)}")
                return False
        except Exception as e:
            print(f"Error in verify_signature: {str(e)}")
            return False

    @staticmethod
    def generate_qr_code(data):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(json.dumps(data))
        qr.make(fit=True)

        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return qr_base64
    @staticmethod
    def verify_certificate(certificate_pem):
        try:
            # Load certificate
            cert = x509.load_pem_x509_certificate(certificate_pem)

            # Check validity period
            current_time = datetime.utcnow()

            if current_time < cert.not_valid_before:
                return False, "Certificate is not yet valid"
            if current_time > cert.not_valid_after:
                return False, "Certificate has expired"
            # Additional validations can be added here
            return True, "Certificate is valid"
        except Exception as e:
            print(f"Certificate verification error: {str(e)}")
            return False, f"Invalid certificate format: {str(e)}"


import face_recognition
import numpy as np
import cv2
from typing import Optional

class FaceAuth:
    def __init__(self):
        """Initialize FaceAuth with face recognition"""
        self.threshold = 0.5  # Adjust this value between 0.4-0.6 for stricter/looser matching

    def _process_image_bytes(self, image_bytes: bytes) -> Optional[np.ndarray]:
        """Convert image bytes to numpy array and detect face."""
        try:
            # Convert bytes to numpy array
            nparr = np.frombuffer(image_bytes, np.uint8)
            # Decode image
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if image is None:
                print("Failed to decode image")
                return None
                
            # Convert BGR to RGB (face_recognition expects RGB)
            rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            return rgb_image
        except Exception as e:
            print(f"Error processing image: {str(e)}")
            return None

    def process_face_image(self, image_bytes: bytes) -> Optional[bytes]:
        """Process face image during registration."""
        try:
            # Process image
            image = self._process_image_bytes(image_bytes)
            if image is None:
                return None

            # Detect face locations
            face_locations = face_recognition.face_locations(image, model="hog")
            
            if not face_locations:
                print("No face detected in image")
                return None
            
            if len(face_locations) > 1:
                print("Multiple faces detected. Please provide an image with only one face.")
                return None

            # Get face encoding
            face_encodings = face_recognition.face_encodings(image, face_locations)
            if not face_encodings:
                print("Could not encode face")
                return None

            # Convert encoding to bytes for storage
            return face_encodings[0].tobytes()

        except Exception as e:
            print(f"Error during face processing: {str(e)}")
            return None

    def verify_face(self, login_image_bytes: bytes, stored_encoding_bytes: bytes) -> bool:
        """Verify face during login."""
        try:
            # Process login image
            login_image = self._process_image_bytes(login_image_bytes)
            if login_image is None:
                print("Failed to process login image")
                return False

            # Detect face in login image
            face_locations = face_recognition.face_locations(login_image, model="hog")
            
            if not face_locations:
                print("No face detected in login image")
                return False
            
            if len(face_locations) > 1:
                print("Multiple faces detected in login image")
                return False

            # Get face encoding from login image
            login_encodings = face_recognition.face_encodings(login_image, face_locations)
            if not login_encodings:
                print("Could not encode login face")
                return False

            # Convert stored encoding bytes back to numpy array
            stored_encoding = np.frombuffer(stored_encoding_bytes, dtype=np.float64)

            # Compare faces
            matches = face_recognition.compare_faces(
                [stored_encoding], 
                login_encodings[0],
                tolerance=self.threshold
            )

            # Get face distance for logging
            face_distances = face_recognition.face_distance(
                [stored_encoding], 
                login_encodings[0]
            )
            print(f"Face distance: {face_distances[0]:.4f} (threshold: {self.threshold})")

            return matches[0]

        except Exception as e:
            print(f"Error during face verification: {str(e)}")
            return False

    def check_face_quality(self, image_bytes: bytes) -> dict:
        """Check quality of face image before processing."""
        try:
            image = self._process_image_bytes(image_bytes)
            if image is None:
                return {"valid": False, "message": "Failed to process image"}

            # Check image size
            height, width = image.shape[:2]
            if width < 200 or height < 200:
                return {"valid": False, "message": "Image resolution too low"}

            # Detect faces
            face_locations = face_recognition.face_locations(image, model="hog")
            
            if not face_locations:
                return {"valid": False, "message": "No face detected"}
            
            if len(face_locations) > 1:
                return {"valid": False, "message": "Multiple faces detected"}

            # Get face size relative to image
            top, right, bottom, left = face_locations[0]
            face_height = bottom - top
            face_width = right - left
            
            if face_height < height * 0.2 or face_width < width * 0.2:
                return {"valid": False, "message": "Face too small in image"}

            return {"valid": True, "message": "Face image quality acceptable"}

        except Exception as e:
            return {"valid": False, "message": f"Error checking image: {str(e)}"}