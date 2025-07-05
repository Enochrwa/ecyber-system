import time
import threading
import csv
import json
from datetime import datetime
from collections import defaultdict
import numpy as np
from scapy.all import *
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Exact 40 features from CICIDS2017 dataset in exact order
CICIDS2017_FEATURES = [
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

class CICFlow:
    """Enhanced CICFlowMeter-compatible flow implementation for live packet analysis"""
    
    def __init__(self, first_packet):
        self.packets = []
        self.fwd_packets = []
        self.bwd_packets = []
        
        # Timing - microsecond precision like CICFlowMeter
        self.start_time = float(first_packet.time)
        self.last_seen = float(first_packet.time)
        self.flow_iat = []
        self.fwd_iat = []
        self.bwd_iat = []
        
        # Packet lengths (total packet size including all headers)
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        
        # Payload byte counters (actual data, excluding headers)
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
        
        # TCP flags counters
        self.fin_flag_count = 0
        self.syn_flag_count = 0  
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        
        # Initial window sizes
        self.fwd_init_win_bytes = 0
        self.bwd_init_win_bytes = 0
        self.fwd_init_win_set = False
        self.bwd_init_win_set = False
        
        # Flow state
        self.is_terminated = False
        self.termination_reason = None
        
        # Idle detection (gaps > 1 second)
        self.idle_times = []
        self.last_activity_time = float(first_packet.time)
        
        # Minimum packets for feature extraction
        self.MIN_PACKETS_FOR_FEATURES = 4
        
        # Extract flow 5-tuple
        self._extract_flow_info(first_packet)
        self.add_packet(first_packet)

    def _extract_flow_info(self, packet):
        """Extract 5-tuple flow information supporting multiple protocols"""
        try:
            if packet.haslayer(IP):
                self.src_ip = packet[IP].src
                self.dst_ip = packet[IP].dst
                self.protocol = packet[IP].proto
                
                if packet.haslayer(TCP):
                    self.src_port = packet[TCP].sport
                    self.dst_port = packet[TCP].dport
                    self.protocol_name = "TCP"
                elif packet.haslayer(UDP):
                    self.src_port = packet[UDP].sport
                    self.dst_port = packet[UDP].dport
                    self.protocol_name = "UDP"
                elif packet.haslayer(ICMP):
                    self.src_port = 0
                    self.dst_port = packet[ICMP].type
                    self.protocol_name = "ICMP"
                else:
                    self.src_port = 0
                    self.dst_port = 0
                    self.protocol_name = f"PROTO_{self.protocol}"
            elif packet.haslayer(IPv6):
                self.src_ip = packet[IPv6].src
                self.dst_ip = packet[IPv6].dst
                self.protocol = packet[IPv6].nh
                self.protocol_name = "IPv6"
                
                if packet.haslayer(TCP):
                    self.src_port = packet[TCP].sport
                    self.dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    self.src_port = packet[UDP].sport
                    self.dst_port = packet[UDP].dport
                else:
                    self.src_port = 0
                    self.dst_port = 0
            else:
                # Fallback for other protocols
                self.src_ip = packet.src if hasattr(packet, 'src') else '0.0.0.0'
                self.dst_ip = packet.dst if hasattr(packet, 'dst') else '0.0.0.0'
                self.protocol = packet.type if hasattr(packet, 'type') else 0
                self.src_port = 0
                self.dst_port = 0
                self.protocol_name = "OTHER"
        except Exception as e:
            logger.warning(f"Error extracting flow info: {e}")
            self._set_default_flow_info()

    def _set_default_flow_info(self):
        """Set default flow information in case of errors"""
        self.src_ip = '0.0.0.0'
        self.dst_ip = '0.0.0.0'
        self.protocol = 0
        self.src_port = 0
        self.dst_port = 0
        self.protocol_name = "UNKNOWN"

    def _is_forward_packet(self, packet):
        """Determine packet direction based on initial flow direction"""
        try:
            if packet.haslayer(IP):
                return (packet[IP].src == self.src_ip and packet[IP].dst == self.dst_ip)
            elif packet.haslayer(IPv6):
                return (packet[IPv6].src == self.src_ip and packet[IPv6].dst == self.dst_ip)
            return packet.src == self.src_ip if hasattr(packet, 'src') else True
        except:
            return True

    def _calculate_payload_bytes(self, packet):
        """Calculate actual payload bytes excluding all headers"""
        try:
            total_len = len(packet)
            header_len = 0
            
            # Ethernet header
            if packet.haslayer(Ether):
                header_len += 14
            
            # IP header
            if packet.haslayer(IP):
                header_len += packet[IP].ihl * 4
            elif packet.haslayer(IPv6):
                header_len += 40  # IPv6 header is fixed 40 bytes
            
            # Transport layer headers
            if packet.haslayer(TCP):
                header_len += packet[TCP].dataofs * 4
            elif packet.haslayer(UDP):
                header_len += 8
            elif packet.haslayer(ICMP):
                header_len += 8
            
            payload_bytes = max(0, total_len - header_len)
            return payload_bytes
        except:
            return 0

    def _should_terminate_flow(self, packet):
        """Enhanced flow termination detection"""
        try:
            if packet.haslayer(TCP):
                tcp_flags = packet[TCP].flags
                
                # RST terminates immediately
                if tcp_flags.RST:
                    self.termination_reason = "RST"
                    return True
                
                # FIN termination (both directions)
                if tcp_flags.FIN:
                    fwd_fin_count = sum(1 for p in self.fwd_packets 
                                      if p.haslayer(TCP) and p[TCP].flags.FIN)
                    bwd_fin_count = sum(1 for p in self.bwd_packets 
                                      if p.haslayer(TCP) and p[TCP].flags.FIN)
                    
                    if fwd_fin_count > 0 and bwd_fin_count > 0:
                        self.termination_reason = "FIN-FIN"
                        return True
            
            # Timeout-based termination for inactive flows
            current_time = float(packet.time)
            if current_time - self.last_activity_time > 120:  # 2 minutes timeout
                self.termination_reason = "TIMEOUT"
                return True
                
            return False
        except:
            return False

    def add_packet(self, packet):
        """Add packet to flow and update all statistics"""
        if self.is_terminated:
            return False
            
        try:
            current_time = float(packet.time)
            packet_len = len(packet)
            
            self.packets.append(packet)
            self.packet_lengths.append(packet_len)
            
            # Flow Inter-Arrival Time (IAT)
            if len(self.packets) > 1:
                iat = current_time - self.last_seen
                self.flow_iat.append(iat * 1000000)  # Convert to microseconds
                
                # Idle time detection (gaps > 1 second)
                if iat > 1.0:
                    self.idle_times.append(iat * 1000000)  # microseconds
            
            # Direction-specific processing
            is_forward = self._is_forward_packet(packet)
            
            if is_forward:
                self.fwd_packets.append(packet)
                self.fwd_packet_lengths.append(packet_len)
                
                # Forward IAT calculation
                if len(self.fwd_packets) > 1:
                    prev_fwd_time = float(self.fwd_packets[-2].time)
                    fwd_iat = (current_time - prev_fwd_time) * 1000000
                    self.fwd_iat.append(fwd_iat)
                
                # Forward payload bytes
                payload_bytes = self._calculate_payload_bytes(packet)
                self.total_fwd_bytes += payload_bytes
                
                # Initial window size (first SYN packet)
                if (packet.haslayer(TCP) and packet[TCP].flags.SYN and 
                    not self.fwd_init_win_set):
                    self.fwd_init_win_bytes = packet[TCP].window
                    self.fwd_init_win_set = True
            else:
                self.bwd_packets.append(packet)
                self.bwd_packet_lengths.append(packet_len)
                
                # Backward IAT calculation
                if len(self.bwd_packets) > 1:
                    prev_bwd_time = float(self.bwd_packets[-2].time)
                    bwd_iat = (current_time - prev_bwd_time) * 1000000
                    self.bwd_iat.append(bwd_iat)
                
                # Backward payload bytes
                payload_bytes = self._calculate_payload_bytes(packet)
                self.total_bwd_bytes += payload_bytes
                
                # Initial window size (first SYN packet)
                if (packet.haslayer(TCP) and packet[TCP].flags.SYN and 
                    not self.bwd_init_win_set):
                    self.bwd_init_win_bytes = packet[TCP].window
                    self.bwd_init_win_set = True
            
            # TCP flags counting
            if packet.haslayer(TCP):
                tcp_flags = packet[TCP].flags
                if tcp_flags.FIN: self.fin_flag_count += 1
                if tcp_flags.SYN: self.syn_flag_count += 1
                if tcp_flags.PSH: self.psh_flag_count += 1
                if tcp_flags.ACK: self.ack_flag_count += 1
                if tcp_flags.URG: self.urg_flag_count += 1
            
            self.last_seen = current_time
            self.last_activity_time = current_time
            
            # Check for flow termination
            if self._should_terminate_flow(packet):
                self.is_terminated = True
                
            return True
        except Exception as e:
            logger.error(f"Error adding packet to flow: {e}")
            return False

    def has_enough_packets_for_features(self):
        """Check if flow has enough packets for reliable feature extraction"""
        return len(self.packets) >= self.MIN_PACKETS_FOR_FEATURES

    def extract_cicids2017_features(self):
        """Extract exact CICIDS2017 40 features in correct order with enhanced calculations"""
        if not self.packets or not self.has_enough_packets_for_features():
            return None
        
        try:
            # Flow duration in seconds
            flow_duration = max(self.last_seen - self.start_time, 0.000001)  # Prevent division by zero
            
            # Packet length statistics
            packet_lengths = np.array(self.packet_lengths, dtype=float)
            min_packet_length = float(np.min(packet_lengths))
            max_packet_length = float(np.max(packet_lengths))
            packet_length_mean = float(np.mean(packet_lengths))
            packet_length_std = float(np.std(packet_lengths, ddof=0))
            packet_length_variance = float(np.var(packet_lengths, ddof=0))
            
            # Forward packet statistics
            fwd_packet_lengths = np.array(self.fwd_packet_lengths, dtype=float)
            total_length_fwd_packets = float(np.sum(fwd_packet_lengths)) if len(fwd_packet_lengths) > 0 else 0.0
            fwd_packet_length_min = float(np.min(fwd_packet_lengths)) if len(fwd_packet_lengths) > 0 else 0.0
            
            # Backward packet statistics  
            bwd_packet_lengths = np.array(self.bwd_packet_lengths, dtype=float)
            bwd_packet_length_max = float(np.max(bwd_packet_lengths)) if len(bwd_packet_lengths) > 0 else 0.0
            bwd_packet_length_min = float(np.min(bwd_packet_lengths)) if len(bwd_packet_lengths) > 0 else 0.0
            bwd_packet_length_mean = float(np.mean(bwd_packet_lengths)) if len(bwd_packet_lengths) > 0 else 0.0
            bwd_packet_length_std = float(np.std(bwd_packet_lengths, ddof=0)) if len(bwd_packet_lengths) > 0 else 0.0
            
            # Flow IAT statistics
            flow_iat = np.array(self.flow_iat, dtype=float)
            flow_iat_mean = float(np.mean(flow_iat)) if len(flow_iat) > 0 else 0.0
            flow_iat_std = float(np.std(flow_iat, ddof=0)) if len(flow_iat) > 0 else 0.0
            flow_iat_max = float(np.max(flow_iat)) if len(flow_iat) > 0 else 0.0
            
            # Forward IAT statistics
            fwd_iat = np.array(self.fwd_iat, dtype=float)
            fwd_iat_total = float(np.sum(fwd_iat)) if len(fwd_iat) > 0 else 0.0
            fwd_iat_mean = float(np.mean(fwd_iat)) if len(fwd_iat) > 0 else 0.0
            fwd_iat_std = float(np.std(fwd_iat, ddof=0)) if len(fwd_iat) > 0 else 0.0
            fwd_iat_max = float(np.max(fwd_iat)) if len(fwd_iat) > 0 else 0.0
            
            # Backward IAT statistics
            bwd_iat = np.array(self.bwd_iat, dtype=float)
            bwd_iat_total = float(np.sum(bwd_iat)) if len(bwd_iat) > 0 else 0.0
            bwd_iat_mean = float(np.mean(bwd_iat)) if len(bwd_iat) > 0 else 0.0
            bwd_iat_std = float(np.std(bwd_iat, ddof=0)) if len(bwd_iat) > 0 else 0.0
            bwd_iat_max = float(np.max(bwd_iat)) if len(bwd_iat) > 0 else 0.0
            
            # Rate calculations
            bwd_packets_s = float(len(self.bwd_packets)) / flow_duration
            
            # Ratios
            down_up_ratio = (float(len(self.bwd_packets)) / float(len(self.fwd_packets)) 
                           if len(self.fwd_packets) > 0 else 0.0)
            
            # Average sizes
            average_packet_size = packet_length_mean
            avg_bwd_segment_size = bwd_packet_length_mean
            
            # Subflow bytes (payload bytes)
            subflow_fwd_bytes = float(self.total_fwd_bytes)
            
            # Idle time statistics (in microseconds)
            idle_times = np.array(self.idle_times, dtype=float)
            idle_mean = float(np.mean(idle_times)) if len(idle_times) > 0 else 0.0
            idle_std = float(np.std(idle_times, ddof=0)) if len(idle_times) > 0 else 0.0
            idle_max = float(np.max(idle_times)) if len(idle_times) > 0 else 0.0  
            idle_min = float(np.min(idle_times)) if len(idle_times) > 0 else 0.0
            
            # Return features in exact order as CICIDS2017_FEATURES list
            features = [
                int(self.dst_port),                    # Destination Port
                flow_duration,                         # Flow Duration
                total_length_fwd_packets,              # Total Length of Fwd Packets
                fwd_packet_length_min,                 # Fwd Packet Length Min
                bwd_packet_length_max,                 # Bwd Packet Length Max
                bwd_packet_length_min,                 # Bwd Packet Length Min
                bwd_packet_length_mean,                # Bwd Packet Length Mean
                bwd_packet_length_std,                 # Bwd Packet Length Std
                flow_iat_mean,                         # Flow IAT Mean
                flow_iat_std,                          # Flow IAT Std
                flow_iat_max,                          # Flow IAT Max
                fwd_iat_total,                         # Fwd IAT Total
                fwd_iat_mean,                          # Fwd IAT Mean
                fwd_iat_std,                           # Fwd IAT Std
                fwd_iat_max,                           # Fwd IAT Max
                bwd_iat_total,                         # Bwd IAT Total
                bwd_iat_mean,                          # Bwd IAT Mean
                bwd_iat_std,                           # Bwd IAT Std
                bwd_iat_max,                           # Bwd IAT Max
                bwd_packets_s,                         # Bwd Packets/s
                min_packet_length,                     # Min Packet Length
                max_packet_length,                     # Max Packet Length
                packet_length_mean,                    # Packet Length Mean
                packet_length_std,                     # Packet Length Std
                packet_length_variance,                # Packet Length Variance
                int(self.fin_flag_count),              # FIN Flag Count
                int(self.syn_flag_count),              # SYN Flag Count
                int(self.psh_flag_count),              # PSH Flag Count
                int(self.ack_flag_count),              # ACK Flag Count
                int(self.urg_flag_count),              # URG Flag Count
                down_up_ratio,                         # Down/Up Ratio
                average_packet_size,                   # Average Packet Size
                avg_bwd_segment_size,                  # Avg Bwd Segment Size
                subflow_fwd_bytes,                     # Subflow Fwd Bytes
                int(self.fwd_init_win_bytes),          # Init_Win_bytes_forward
                int(self.bwd_init_win_bytes),          # Init_Win_bytes_backward
                idle_mean,                             # Idle Mean
                idle_std,                              # Idle Std
                idle_max,                              # Idle Max
                idle_min                               # Idle Min
            ]
            
            return features
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None


class LiveFeatureExtractor:
    """Production-ready live feature extractor for packet sniffing integration"""
    
    def __init__(self, flow_timeout=120, cleanup_interval=60):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()
        self.lock = threading.Lock()
        self.feature_results = []
        
        # Statistics
        self.total_packets = 0
        self.active_flows = 0
        self.completed_flows = 0
        
        logger.info("LiveFeatureExtractor initialized")

    def _get_flow_key(self, packet):
        """Generate normalized bidirectional flow key"""
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                protocol = packet[IPv6].nh
            else:
                return None
            
            src_port = 0
            dst_port = 0
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                src_port = 0
                dst_port = packet[ICMP].type
            
            # Create normalized bidirectional key
            if (src_ip, src_port) < (dst_ip, dst_port):
                return (src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                return (dst_ip, src_ip, dst_port, src_port, protocol)
        except Exception as e:
            logger.warning(f"Error generating flow key: {e}")
            return None

    def _cleanup_old_flows(self):
        """Remove old inactive flows to prevent memory leaks"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        with self.lock:
            flows_to_remove = []
            for flow_key, flow in self.flows.items():
                if current_time - flow.last_activity_time > self.flow_timeout:
                    flows_to_remove.append(flow_key)
            
            for flow_key in flows_to_remove:
                del self.flows[flow_key]
                self.completed_flows += 1
            
            self.last_cleanup = current_time
            if flows_to_remove:
                logger.info(f"Cleaned up {len(flows_to_remove)} old flows")

    def extract_features(self, packet):
        """
        Main method to extract features from a packet.
        This method should be called from your packet_handler.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Contains features and metadata if flow has enough packets, None otherwise
                 Format: {
                     'features': [40 feature values],
                     'flow_key': flow identifier,
                     'metadata': {flow information},
                     'is_complete': boolean indicating if flow is terminated
                 }
        """
        try:
            self.total_packets += 1
            
            # Periodic cleanup
            self._cleanup_old_flows()
            
            flow_key = self._get_flow_key(packet)
            if not flow_key:
                return None
            
            with self.lock:
                # Create new flow or add to existing
                if flow_key not in self.flows:
                    self.flows[flow_key] = CICFlow(packet)
                    self.active_flows += 1
                else:
                    success = self.flows[flow_key].add_packet(packet)
                    if not success:
                        return None
                
                flow = self.flows[flow_key]
                
                # Extract features if flow has enough packets
                if flow.has_enough_packets_for_features():
                    features = flow.extract_cicids2017_features()
                    
                    if features is not None:
                        result = {
                            'features': features,
                            'flow_key': flow_key,
                            'metadata': {
                                'src_ip': flow.src_ip,
                                'dst_ip': flow.dst_ip,
                                'src_port': flow.src_port,
                                'dst_port': flow.dst_port,
                                'protocol': flow.protocol,
                                'protocol_name': flow.protocol_name,
                                'packet_count': len(flow.packets),
                                'fwd_packets': len(flow.fwd_packets),
                                'bwd_packets': len(flow.bwd_packets),
                                'duration': flow.last_seen - flow.start_time,
                                'start_time': flow.start_time,
                                'last_seen': flow.last_seen,
                                'termination_reason': flow.termination_reason
                            },
                            'is_complete': flow.is_terminated
                        }
                        
                        # Remove completed flows
                        if flow.is_terminated:
                            del self.flows[flow_key]
                            self.active_flows -= 1
                            self.completed_flows += 1
                        
                        return result
                
                return None
        except Exception as e:
            logger.error(f"Error in extract_features: {e}")
            return None

    def get_statistics(self):
        """Get current statistics"""
        with self.lock:
            return {
                'total_packets': self.total_packets,
                'active_flows': len(self.flows),
                'completed_flows': self.completed_flows,
                'flows_in_memory': len(self.flows)
            }

    def save_features_to_csv(self, feature_results, filename):
        """
        Save extracted features to CSV file.
        
        Args:
            feature_results (list): List of feature extraction results
            filename (str): Output CSV filename
        """
        try:
            with open(filename, 'w', newline='') as csvfile:
                # Create header
                header = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
                         'protocol_name', 'packet_count', 'fwd_packets', 'bwd_packets', 
                         'duration', 'start_time', 'is_complete'] + CICIDS2017_FEATURES
                writer = csv.writer(csvfile)
                writer.writerow(header)
                
                # Write data
                for result in feature_results:
                    metadata = result['metadata']
                    features = result['features']
                    row = [
                        metadata['src_ip'],
                        metadata['dst_ip'],
                        metadata['src_port'],
                        metadata['dst_port'],
                        metadata['protocol'],
                        metadata['protocol_name'],
                        metadata['packet_count'],
                        metadata['fwd_packets'],
                        metadata['bwd_packets'],
                        metadata['duration'],
                        metadata['start_time'],
                        result['is_complete']
                    ] + features
                    writer.writerow(row)
            
            logger.info(f"Features saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving features to CSV: {e}")


# Example usage for integration with external packet handler
def example_packet_handler_integration():
    """Example showing how to integrate with external packet handler"""
    
    # Initialize the feature extractor
    extractor = LiveFeatureExtractor()
    feature_results = []
    
    def packet_handler(packet):
        """Your packet handler function - call this from your sniffing code"""
        result = extractor.extract_features(packet)
        
        if result:
            features = result['features']
            metadata = result['metadata']
            
            # Log important flows (for testing port scans, floods, etc.)
            if (metadata['packet_count'] > 10 or 
                metadata['dst_port'] in [22, 80, 443, 21, 23] or
                result['is_complete']):
                logger.info(f"Flow: {metadata['src_ip']}:{metadata['src_port']} -> "
                           f"{metadata['dst_ip']}:{metadata['dst_port']} "
                           f"({metadata['protocol_name']}) - "
                           f"Packets: {metadata['packet_count']}, "
                           f"Duration: {metadata['duration']:.3f}s")
            
            feature_results.append(result)
            
            # Here you can feed features to your ML model
            # model_prediction = your_ml_model.predict([features])
            # if model_prediction indicates attack:
            #     send_alert(metadata, model_prediction)
    
    # Example: process a few packets (in real usage, this comes from your sniffer)
    print("Example integration ready. Call packet_handler(packet) from your sniffer.")
    print("Features will be extracted when flows have >= 4 packets.")
    
    return extractor, packet_handler


if __name__ == "__main__":
    # Example usage
    extractor, handler = example_packet_handler_integration()
    
    # Print feature names for verification