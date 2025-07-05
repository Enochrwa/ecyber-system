import time
import threading
import numpy as np
import pandas as pd
from collections import defaultdict
from pyflowmeter.sniffer import create_sniffer
import tempfile
import os
import json
from scapy.all import *

# Your exact feature names - maintaining compatibility with your trained models
REQUIRED_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Length of Fwd Packets',
    'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Bwd Segment Size',
    'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

class PyFlowMeterAnalyzer:
    """
    Enhanced network flow analyzer using pyflowmeter with real-time processing
    Compatible with your existing ML models
    """
    
    def __init__(self, flow_timeout=120, buffer_size=1000):
        self.flow_timeout = flow_timeout
        self.buffer_size = buffer_size
        self.packet_buffer = []
        self.feature_callback = None
        self.running = False
        self.lock = threading.Lock()
        
        # Statistics
        self.flows_processed = 0
        self.packets_processed = 0
        
        # Temporary file for batch processing
        self.temp_dir = tempfile.mkdtemp()
        self.batch_counter = 0
    
    def set_feature_callback(self, callback_func):
        """
        Set callback function to handle extracted features
        callback_func should accept a dictionary of features
        """
        self.feature_callback = callback_func
    
    def _process_packet_buffer(self):
        """Process accumulated packets using pyflowmeter"""
        if len(self.packet_buffer) == 0:
            return
        
        try:
            # Create temporary pcap file
            self.batch_counter += 1
            temp_pcap = os.path.join(self.temp_dir, f"batch_{self.batch_counter}.pcap")
            temp_csv = os.path.join(self.temp_dir, f"flows_{self.batch_counter}.csv")
            
            # Write packets to pcap file
            wrpcap(temp_pcap, self.packet_buffer)
            
            # Use pyflowmeter to extract flows
            sniffer = create_sniffer(
                input_file=temp_pcap,
                to_csv=True,
                output_file=temp_csv,
                verbose=False
            )
            
            # Start processing
            sniffer.start()
            sniffer.join()
            
            # Read and process the generated CSV
            if os.path.exists(temp_csv):
                self._process_csv_flows(temp_csv)
            
            # Cleanup temporary files
            self._cleanup_temp_files(temp_pcap, temp_csv)
            
            # Clear buffer
            with self.lock:
                self.packet_buffer.clear()
                
        except Exception as e:
            print(f"Error processing packet buffer: {e}")
    
    def _process_csv_flows(self, csv_file):
        """Process flows from CSV and extract required features"""
        try:
            df = pd.read_csv(csv_file)
            
            for _, row in df.iterrows():
                features = self._map_features(row)
                if features and self.feature_callback:
                    self.feature_callback(features)
                    self.flows_processed += 1
                    
        except Exception as e:
            print(f"Error processing CSV flows: {e}")
    
    def _map_features(self, flow_row):
        """
        Map pyflowmeter features to your required feature names
        This ensures compatibility with your trained ML models
        """
        try:
            # Feature mapping from pyflowmeter output to your required names
            feature_mapping = {
                # Direct mappings where names match
                'Destination Port': 'dst_port',
                'Flow Duration': 'flow_duration',
                'Total Length of Fwd Packets': 'tot_fwd_pkts',
                'Fwd Packet Length Min': 'fwd_pkt_len_min',
                'Bwd Packet Length Max': 'bwd_pkt_len_max',
                'Bwd Packet Length Min': 'bwd_pkt_len_min',
                'Bwd Packet Length Mean': 'bwd_pkt_len_mean',
                'Bwd Packet Length Std': 'bwd_pkt_len_std',
                'Flow IAT Mean': 'flow_iat_mean',
                'Flow IAT Std': 'flow_iat_std',
                'Flow IAT Max': 'flow_iat_max',
                'Fwd IAT Total': 'fwd_iat_tot',
                'Fwd IAT Mean': 'fwd_iat_mean',
                'Fwd IAT Std': 'fwd_iat_std',
                'Fwd IAT Max': 'fwd_iat_max',
                'Bwd IAT Total': 'bwd_iat_tot',
                'Bwd IAT Mean': 'bwd_iat_mean',
                'Bwd IAT Std': 'bwd_iat_std',
                'Bwd IAT Max': 'bwd_iat_max',
                'Bwd Packets/s': 'bwd_pkts_s',
                'Min Packet Length': 'pkt_len_min',
                'Max Packet Length': 'pkt_len_max',
                'Packet Length Mean': 'pkt_len_mean',
                'Packet Length Std': 'pkt_len_std',
                'Packet Length Variance': 'pkt_len_var',
                'FIN Flag Count': 'fin_flag_cnt',
                'SYN Flag Count': 'syn_flag_cnt',
                'PSH Flag Count': 'psh_flag_cnt',
                'ACK Flag Count': 'ack_flag_cnt',
                'URG Flag Count': 'urg_flag_cnt',
                'Down/Up Ratio': 'down_up_ratio',
                'Average Packet Size': 'pkt_size_avg',
                'Avg Bwd Segment Size': 'bwd_seg_size_avg',
                'Subflow Fwd Bytes': 'subflow_fwd_byts',
                'Init_Win_bytes_forward': 'init_fwd_win_byts',
                'Init_Win_bytes_backward': 'init_bwd_win_byts',
                'Idle Mean': 'idle_mean',
                'Idle Std': 'idle_std',
                'Idle Max': 'idle_max',
                'Idle Min': 'idle_min'
            }
            
            features = {}
            
            # Extract features with proper mapping and type conversion
            for required_feature in REQUIRED_FEATURES:
                if required_feature in feature_mapping:
                    column_name = feature_mapping[required_feature]
                    if column_name in flow_row:
                        value = flow_row[column_name]
                        # Handle different data types and NaN values
                        if pd.isna(value):
                            features[required_feature] = 0.0
                        elif required_feature == 'Destination Port':
                            features[required_feature] = int(float(value))
                        else:
                            features[required_feature] = float(value)
                    else:
                        features[required_feature] = 0.0
                else:
                    # Handle features that might need special calculation or have different names
                    features[required_feature] = self._calculate_missing_feature(required_feature, flow_row)
            
            return features
            
        except Exception as e:
            print(f"Error mapping features: {e}")
            return None
    
    def _calculate_missing_feature(self, feature_name, flow_row):
        """Calculate features that might not be directly available"""
        try:
            # Handle special cases where feature names don't match exactly
            if feature_name == 'Total Length of Fwd Packets':
                return float(flow_row.get('totlen_fwd_pkts', 0))
            elif feature_name == 'Down/Up Ratio':
                fwd_pkts = float(flow_row.get('tot_fwd_pkts', 1))
                bwd_pkts = float(flow_row.get('tot_bwd_pkts', 0))
                return bwd_pkts / fwd_pkts if fwd_pkts > 0 else 0.0
            elif feature_name == 'Average Packet Size':
                return float(flow_row.get('pkt_len_mean', 0))
            elif feature_name == 'Avg Bwd Segment Size':
                return float(flow_row.get('bwd_pkt_len_mean', 0))
            else:
                return 0.0
        except:
            return 0.0
    
    def _cleanup_temp_files(self, *files):
        """Clean up temporary files"""
        for file_path in files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
    
    def process_packet(self, packet):
        """Add packet to buffer for batch processing"""
        with self.lock:
            self.packet_buffer.append(packet)
            self.packets_processed += 1
            
            # Process buffer when it reaches the buffer size
            if len(self.packet_buffer) >= self.buffer_size:
                threading.Thread(target=self._process_packet_buffer, daemon=True).start()
    
    def start_live_capture(self, interface=None, filter_expr=None):
        """Start live packet capture and processing"""
        def packet_handler(packet):
            if self.running:
                self.process_packet(packet)
        
        self.running = True
        print(f"Starting live capture on interface: {interface or 'all interfaces'}")
        
        try:
            sniff(
                iface=interface,
                filter=filter_expr,
                prn=packet_handler,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("Capture interrupted by user")
        finally:
            self.stop()
    
    def process_pcap_file(self, pcap_file):
        """Process a pcap file directly"""
        try:
            temp_csv = os.path.join(self.temp_dir, f"flows_from_pcap.csv")
            
            # Use pyflowmeter to process the entire pcap file
            sniffer = create_sniffer(
                input_file=pcap_file,
                to_csv=True,
                output_file=temp_csv,
                verbose=True
            )
            
            sniffer.start()
            sniffer.join()
            
            # Process the generated flows
            if os.path.exists(temp_csv):
                self._process_csv_flows(temp_csv)
                self._cleanup_temp_files(temp_csv)
            
            print(f"Processed {self.flows_processed} flows from {pcap_file}")
            
        except Exception as e:
            print(f"Error processing pcap file: {e}")
    
    def flush_buffer(self):
        """Process any remaining packets in buffer"""
        if len(self.packet_buffer) > 0:
            self._process_packet_buffer()
    
    def stop(self):
        """Stop the analyzer and clean up"""
        self.running = False
        self.flush_buffer()
        
        # Clean up temporary directory
        try:
            import shutil
            shutil.rmtree(self.temp_dir)
        except:
            pass
        
        print(f"Analyzer stopped. Processed {self.packets_processed} packets, {self.flows_processed} flows")
    
    def get_stats(self):
        """Get processing statistics"""
        return {
            'packets_processed': self.packets_processed,
            'flows_processed': self.flows_processed,
            'buffer_size': len(self.packet_buffer),
            'running': self.running
        }

# Example usage and integration with ML models
class MLFlowProcessor:
    """
    Example class showing how to integrate with your ML models
    """
    
    def __init__(self, model=None):
        self.model = model
        self.feature_scaler = None  # Add your feature scaler if needed
        self.predictions = []
        
    def process_features(self, features):
        """
        Process extracted features with your ML model
        This is called by the analyzer for each flow
        """
        try:
            # Convert features to the format expected by your model
            feature_vector = [features[feature_name] for feature_name in REQUIRED_FEATURES]
            feature_array = np.array(feature_vector).reshape(1, -1)
            
            # Apply scaling if needed
            if self.feature_scaler:
                feature_array = self.feature_scaler.transform(feature_array)
            
            # Make prediction if model is available
            if self.model:
                prediction = self.model.predict(feature_array)[0]
                prediction_proba = self.model.predict_proba(feature_array)[0] if hasattr(self.model, 'predict_proba') else None
                
                result = {
                    'features': features,
                    'prediction': prediction,
                    'probability': prediction_proba,
                    'timestamp': time.time()
                }
                
                self.predictions.append(result)
                self._handle_prediction(result)
            else:
                # Just log the features if no model available
                print(f"Extracted features: {len(features)} features")
                
        except Exception as e:
            print(f"Error processing features with ML model: {e}")
    
    def _handle_prediction(self, result):
        """Handle prediction results (customize as needed)"""
        prediction = result['prediction']
        probability = result['probability']
        
        # Example: Alert on suspicious traffic
        if prediction == 1:  # Assuming 1 = malicious
            confidence = max(probability) if probability is not None else "Unknown"
            print(f"⚠️  ALERT: Suspicious flow detected! Confidence: {confidence}")
        
        # You can add more sophisticated handling here:
        # - Send alerts to SIEM
        # - Log to database
        # - Update dashboard
        # - Trigger automated responses

# Main execution example
def main():
    """Example of how to use the updated analyzer"""
    
    # Initialize the analyzer
    analyzer = PyFlowMeterAnalyzer(buffer_size=100)
    
    # Initialize ML processor (replace with your actual model)
    ml_processor = MLFlowProcessor(model=None)  # Load your trained model here
    
    # Set the callback to process features with your ML model
    analyzer.set_feature_callback(ml_processor.process_features)
    
    # Example 1: Process a pcap file
    # analyzer.process_pcap_file("path/to/your/file.pcap")
    
    # Example 2: Start live capture (requires root privileges)
    try:
        # analyzer.start_live_capture(interface="eth0", filter_expr="tcp or udp")
        print("Live capture example (uncomment above line to use)")
    except KeyboardInterrupt:
        print("Stopping analyzer...")
    finally:
        analyzer.stop()

if __name__ == "__main__":
    main()