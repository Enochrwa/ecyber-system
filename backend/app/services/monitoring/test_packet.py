import time
import threading
from collections import defaultdict
import numpy as np
import pandas as pd
from scapy.all import *
import logging
import json
from typing import Dict, List, Optional, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Exact 40 features from CICIDS2017 dataset in correct order
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

class EnhancedCICFlow:
    """
    Enhanced CICFlowMeter-compatible flow implementation
    Fixes premature feature extraction and zero-value issues
    """
    
    def __init__(self, first_packet):
        self.packets = []
        self.fwd_packets = []
        self.bwd_packets = []
        
        # Timing - microsecond precision like CICFlowMeter
        self.start_time = float(first_packet.time)
        self.last_seen = float(first_packet.time)
        self.flow_iat = []  # Inter-arrival times between any packets
        self.fwd_iat = []   # Inter-arrival times between forward packets
        self.bwd_iat = []   # Inter-arrival times between backward packets
        
        # Packet lengths (including headers)
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        
        # Byte counters (payload only for some features)
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
        
        # TCP flags - count ALL occurrences
        self.fin_flag_count = 0
        self.syn_flag_count = 0  
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        
        # Window sizes - capture from SYN packets
        self.fwd_init_win_bytes = 0
        self.bwd_init_win_bytes = 0
        self.fwd_syn_seen = False
        self.bwd_syn_seen = False
        
        # Flow state
        self.is_terminated = False
        self.termination_reason = None
        self.min_packets_for_extraction = 3  # Reduced from 5 for better responsiveness
        
        # Idle detection - improved algorithm
        self.active_times = []
        self.idle_times = []
        self.last_activity_time = float(first_packet.time)
        self.activity_threshold = 1.0  # 1 second idle threshold
        
        # Flow metadata for debugging
        self.flow_id = None
        self.creation_time = time.time()
        
        # Extract flow 5-tuple and add first packet
        self._extract_flow_info(first_packet)
        self.add_packet(first_packet)

    def _extract_flow_info(self, packet):
        """Extract 5-tuple flow information with better error handling"""
        try:
            if packet.haslayer(IP):
                self.src_ip = packet[IP].src
                self.dst_ip = packet[IP].dst
                self.protocol = packet[IP].proto
                
                if packet.haslayer(TCP):
                    self.src_port = packet[TCP].sport
                    self.dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    self.src_port = packet[UDP].sport
                    self.dst_port = packet[UDP].dport
                else:
                    self.src_port = 0
                    self.dst_port = 0
            elif packet.haslayer(IPv6):
                self.src_ip = packet[IPv6].src
                self.dst_ip = packet[IPv6].dst
                self.protocol = packet[IPv6].nh  # Next header
                
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
                # Non-IP traffic - handle gracefully
                self.src_ip = getattr(packet, 'src', '0.0.0.0')
                self.dst_ip = getattr(packet, 'dst', '0.0.0.0')
                self.protocol = getattr(packet, 'type', 0)
                self.src_port = 0
                self.dst_port = 0
                
            # Create unique flow ID for debugging
            self.flow_id = f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}"
            
        except Exception as e:
            logger.warning(f"Flow info extraction error: {e}")
            # Set defaults
            self.src_ip = self.dst_ip = '0.0.0.0'
            self.src_port = self.dst_port = 0
            self.protocol = 0
            self.flow_id = "unknown_flow"

    def _is_forward_packet(self, packet):
        """
        Determine packet direction based on first packet in flow
        Forward: same source as flow initiator
        """
        try:
            if packet.haslayer(IP):
                return (packet[IP].src == self.src_ip and 
                       packet[IP].dst == self.dst_ip)
            elif packet.haslayer(IPv6):
                return (packet[IPv6].src == self.src_ip and 
                       packet[IPv6].dst == self.dst_ip)
            return getattr(packet, 'src', None) == self.src_ip
        except:
            return True  # Default to forward if cannot determine

    def _calculate_payload_size(self, packet):
        """Calculate payload size more accurately"""
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
            
            return max(0, total_len - header_len)
        except:
            return len(packet)  # Fallback to total packet size

    def _should_terminate_flow(self, packet):
        """
        Enhanced flow termination detection
        """
        if not packet.haslayer(TCP):
            # For non-TCP flows, use timeout-based termination
            return False
            
        try:
            tcp_flags = packet[TCP].flags
            
            # RST immediately terminates flow
            if tcp_flags.RST:
                self.termination_reason = "RST"
                return True
                
            # FIN flag handling - improved logic
            if tcp_flags.FIN:
                # Count FIN packets from both directions
                fwd_fin_count = sum(1 for p in self.fwd_packets 
                                  if p.haslayer(TCP) and p[TCP].flags.FIN)
                bwd_fin_count = sum(1 for p in self.bwd_packets 
                                  if p.haslayer(TCP) and p[TCP].flags.FIN)
                
                # Terminate if both directions sent FIN or if we have multiple FINs
                if (fwd_fin_count > 0 and bwd_fin_count > 0) or (fwd_fin_count + bwd_fin_count) >= 3:
                    self.termination_reason = "FIN-FIN"
                    return True
                    
        except Exception as e:
            logger.debug(f"Termination check error: {e}")
            
        return False

    def add_packet(self, packet):
        """Add packet to flow and update all statistics with enhanced error handling"""
        if self.is_terminated:
            return False
            
        try:
            current_time = float(packet.time)
            packet_len = len(packet)  # Total packet length including headers
            
            # Basic packet tracking
            self.packets.append(packet)
            self.packet_lengths.append(packet_len)
            
            # Calculate flow inter-arrival time (between any consecutive packets)
            if len(self.packets) > 1:
                iat = current_time - self.last_seen
                if iat >= 0:  # Ensure non-negative IAT
                    self.flow_iat.append(iat * 1000000)  # Convert to microseconds
                    
                    # Enhanced idle time detection
                    if iat > self.activity_threshold:
                        self.idle_times.append(iat)
                    else:
                        self.active_times.append(iat)
            
            # Determine packet direction
            is_forward = self._is_forward_packet(packet)
            
            if is_forward:
                self._process_forward_packet(packet, current_time, packet_len)
            else:
                self._process_backward_packet(packet, current_time, packet_len)
            
            # Count TCP flags for ALL packets
            self._count_tcp_flags(packet)
            
            # Update timing
            self.last_seen = current_time
            self.last_activity_time = current_time
            
            # Check for flow termination
            if self._should_terminate_flow(packet):
                self.is_terminated = True
                
            return True
            
        except Exception as e:
            logger.error(f"Error adding packet to flow {self.flow_id}: {e}")
            return False

    def _process_forward_packet(self, packet, current_time, packet_len):
        """Process forward direction packet"""
        self.fwd_packets.append(packet)
        self.fwd_packet_lengths.append(packet_len)
        
        # Calculate forward IAT
        if len(self.fwd_packets) > 1:
            prev_fwd_time = float(self.fwd_packets[-2].time)
            fwd_iat = current_time - prev_fwd_time
            if fwd_iat >= 0:  # Ensure non-negative IAT
                self.fwd_iat.append(fwd_iat * 1000000)  # microseconds
        
        # Forward bytes (payload size)
        payload_size = self._calculate_payload_size(packet)
        self.total_fwd_bytes += payload_size
            
        # Capture initial window size from first SYN packet
        if (packet.haslayer(TCP) and packet[TCP].flags.SYN and 
            not self.fwd_syn_seen):
            self.fwd_init_win_bytes = packet[TCP].window
            self.fwd_syn_seen = True

    def _process_backward_packet(self, packet, current_time, packet_len):
        """Process backward direction packet"""
        self.bwd_packets.append(packet)
        self.bwd_packet_lengths.append(packet_len)
        
        # Calculate backward IAT
        if len(self.bwd_packets) > 1:
            prev_bwd_time = float(self.bwd_packets[-2].time)
            bwd_iat = current_time - prev_bwd_time
            if bwd_iat >= 0:  # Ensure non-negative IAT
                self.bwd_iat.append(bwd_iat * 1000000)  # microseconds
        
        # Backward bytes (payload size)
        payload_size = self._calculate_payload_size(packet)
        self.total_bwd_bytes += payload_size
            
        # Capture initial window size from first SYN packet
        if (packet.haslayer(TCP) and packet[TCP].flags.SYN and 
            not self.bwd_syn_seen):
            self.bwd_init_win_bytes = packet[TCP].window
            self.bwd_syn_seen = True

    def _count_tcp_flags(self, packet):
        """Count TCP flags for all packets"""
        if not packet.haslayer(TCP):
            return
            
        try:
            tcp_flags = packet[TCP].flags
            if tcp_flags.FIN:
                self.fin_flag_count += 1
            if tcp_flags.SYN:
                self.syn_flag_count += 1
            if tcp_flags.PSH:
                self.psh_flag_count += 1
            if tcp_flags.ACK:
                self.ack_flag_count += 1
            if tcp_flags.URG:
                self.urg_flag_count += 1
        except Exception as e:
            logger.debug(f"TCP flag counting error: {e}")

    def is_ready_for_extraction(self):
        """
        Check if flow has enough packets for meaningful feature extraction
        This prevents premature extraction with mostly zero values
        """
        packet_count = len(self.packets)
        flow_age = time.time() - self.creation_time
        
        # More flexible conditions for feature extraction
        return (packet_count >= self.min_packets_for_extraction and
                (self.is_terminated or 
                 packet_count >= 5 or  # Allow extraction after 5 packets
                 flow_age > 10 or     # Or after 10 seconds
                 (packet_count >= 2 and flow_age > 5)))  # Quick extraction for short flows

    def extract_features(self):
        """
        Extract exact CICIDS2017 features with enhanced validation
        Returns None if flow is not ready for extraction
        """
        if not self.is_ready_for_extraction():
            logger.debug(f"Flow {self.flow_id} not ready for extraction: "
                        f"{len(self.packets)} packets, age: {time.time() - self.creation_time:.1f}s")
            return None
        
        if not self.packets:
            logger.warning(f"No packets in flow {self.flow_id}")
            return None
        
        try:
            return self._calculate_all_features()
        except Exception as e:
            logger.error(f"Feature extraction error for flow {self.flow_id}: {e}")
            return None

    def _safe_numpy_calc(self, data, func_name, default=0.0):
        """Safely perform numpy calculations with proper error handling"""
        try:
            if not data or len(data) == 0:
                return default
            
            arr = np.array(data, dtype=float)
            if len(arr) == 0:
                return default
            
            if func_name == 'mean':
                result = np.mean(arr)
            elif func_name == 'std':
                result = np.std(arr, ddof=0) if len(arr) > 1 else 0.0
            elif func_name == 'var':
                result = np.var(arr, ddof=0) if len(arr) > 1 else 0.0
            elif func_name == 'min':
                result = np.min(arr)
            elif func_name == 'max':
                result = np.max(arr)
            elif func_name == 'sum':
                result = np.sum(arr)
            else:
                return default
            
            # Handle infinite and NaN values
            if np.isnan(result) or np.isinf(result):
                return default
            
            return float(result)
        except:
            return default

    def _calculate_all_features(self):
        """Calculate all CICIDS2017 features with proper error handling"""
        # Basic flow duration (in seconds)
        flow_duration = max(0.000001, self.last_seen - self.start_time)  # Avoid division by zero
        
        # Packet length statistics (total packet size including headers)
        min_packet_length = self._safe_numpy_calc(self.packet_lengths, 'min')
        max_packet_length = self._safe_numpy_calc(self.packet_lengths, 'max')
        packet_length_mean = self._safe_numpy_calc(self.packet_lengths, 'mean')
        packet_length_std = self._safe_numpy_calc(self.packet_lengths, 'std')
        packet_length_variance = self._safe_numpy_calc(self.packet_lengths, 'var')
        
        # Forward packet statistics
        total_length_fwd_packets = self._safe_numpy_calc(self.fwd_packet_lengths, 'sum')
        fwd_packet_length_min = self._safe_numpy_calc(self.fwd_packet_lengths, 'min')
        
        # Backward packet statistics  
        bwd_packet_length_max = self._safe_numpy_calc(self.bwd_packet_lengths, 'max')
        bwd_packet_length_min = self._safe_numpy_calc(self.bwd_packet_lengths, 'min')
        bwd_packet_length_mean = self._safe_numpy_calc(self.bwd_packet_lengths, 'mean')
        bwd_packet_length_std = self._safe_numpy_calc(self.bwd_packet_lengths, 'std')
        
        # Flow IAT statistics (microseconds)
        flow_iat_mean = self._safe_numpy_calc(self.flow_iat, 'mean')
        flow_iat_std = self._safe_numpy_calc(self.flow_iat, 'std')
        flow_iat_max = self._safe_numpy_calc(self.flow_iat, 'max')
        
        # Forward IAT statistics (microseconds)
        fwd_iat_total = self._safe_numpy_calc(self.fwd_iat, 'sum')
        fwd_iat_mean = self._safe_numpy_calc(self.fwd_iat, 'mean')
        fwd_iat_std = self._safe_numpy_calc(self.fwd_iat, 'std')
        fwd_iat_max = self._safe_numpy_calc(self.fwd_iat, 'max')
        
        # Backward IAT statistics (microseconds)
        bwd_iat_total = self._safe_numpy_calc(self.bwd_iat, 'sum')
        bwd_iat_mean = self._safe_numpy_calc(self.bwd_iat, 'mean')
        bwd_iat_std = self._safe_numpy_calc(self.bwd_iat, 'std')
        bwd_iat_max = self._safe_numpy_calc(self.bwd_iat, 'max')
        
        # Rate calculations
        bwd_packets_s = float(len(self.bwd_packets)) / flow_duration if flow_duration > 0 else 0.0
        
        # Ratios
        down_up_ratio = (float(len(self.bwd_packets)) / float(len(self.fwd_packets)) 
                        if len(self.fwd_packets) > 0 else 0.0)
        
        # Average sizes
        average_packet_size = packet_length_mean
        avg_bwd_segment_size = bwd_packet_length_mean
        
        # Subflow bytes (payload bytes)
        subflow_fwd_bytes = float(self.total_fwd_bytes)
        
        # Idle time statistics (seconds)
        idle_mean = self._safe_numpy_calc(self.idle_times, 'mean')
        idle_std = self._safe_numpy_calc(self.idle_times, 'std')
        idle_max = self._safe_numpy_calc(self.idle_times, 'max')
        idle_min = self._safe_numpy_calc(self.idle_times, 'min')
        
        # Build feature dictionary
        features = {
            'Destination Port': int(self.dst_port),
            'Flow Duration': flow_duration,
            'Total Length of Fwd Packets': total_length_fwd_packets,
            'Fwd Packet Length Min': fwd_packet_length_min,
            'Bwd Packet Length Max': bwd_packet_length_max,
            'Bwd Packet Length Min': bwd_packet_length_min,
            'Bwd Packet Length Mean': bwd_packet_length_mean,
            'Bwd Packet Length Std': bwd_packet_length_std,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Std': flow_iat_std,
            'Flow IAT Max': flow_iat_max,
            'Fwd IAT Total': fwd_iat_total,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Std': fwd_iat_std,
            'Fwd IAT Max': fwd_iat_max,
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Std': bwd_iat_std,
            'Bwd IAT Max': bwd_iat_max,
            'Bwd Packets/s': bwd_packets_s,
            'Min Packet Length': min_packet_length,
            'Max Packet Length': max_packet_length,
            'Packet Length Mean': packet_length_mean,
            'Packet Length Std': packet_length_std,
            'Packet Length Variance': packet_length_variance,
            'FIN Flag Count': int(self.fin_flag_count),
            'SYN Flag Count': int(self.syn_flag_count),
            'PSH Flag Count': int(self.psh_flag_count),
            'ACK Flag Count': int(self.ack_flag_count),
            'URG Flag Count': int(self.urg_flag_count),
            'Down/Up Ratio': down_up_ratio,
            'Average Packet Size': average_packet_size,
            'Avg Bwd Segment Size': avg_bwd_segment_size,
            'Subflow Fwd Bytes': subflow_fwd_bytes,
            'Init_Win_bytes_forward': int(self.fwd_init_win_bytes),
            'Init_Win_bytes_backward': int(self.bwd_init_win_bytes),
            'Idle Mean': idle_mean,
            'Idle Std': idle_std,
            'Idle Max': idle_max,
            'Idle Min': idle_min
        }
        
        return features

class ComprehensiveCICIDS2017Extractor:
    """
    Production-ready CICIDS2017 feature extractor for live traffic analysis
    Designed for integration with ML-based threat detection systems
    """
    
    def __init__(self, flow_timeout=120, cleanup_interval=60, max_flows=10000):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.cleanup_interval = cleanup_interval
        self.max_flows = max_flows
        self.lock = threading.RLock()  # Use RLock for nested locking
        self.running = True
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'flows_created': 0,
            'flows_completed': 0,
            'flows_expired': 0,
            'feature_extractions': 0,
            'extraction_failures': 0
        }
        
        # Feature cache for recent extractions
        self.feature_cache = {}
        self.cache_timeout = 10  # Cache features for 10 seconds
        
        # Start background cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("ComprehensiveCICIDS2017Extractor initialized")

    def _get_flow_key(self, packet):
        """Generate bidirectional flow key with better error handling"""
        try:
            src_ip = dst_ip = None
            protocol = 0
            src_port = dst_port = 0
            
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
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Create normalized bidirectional key
            if (src_ip, src_port) < (dst_ip, dst_port):
                return (src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                return (dst_ip, src_ip, dst_port, src_port, protocol)
                
        except Exception as e:
            logger.debug(f"Flow key generation error: {e}")
            return None

    def process_packet(self, packet) -> Optional[Tuple]:
        """
        Process a single packet and return flow key if successful
        This is the main method to call from your packet handler
        """
        try:
            flow_key = self._get_flow_key(packet)
            if not flow_key:
                return None
            
            with self.lock:
                self.stats['total_packets'] += 1
                
                # Check if we're at max flows - clean up if necessary
                if len(self.flows) >= self.max_flows:
                    self._force_cleanup()
                
                if flow_key not in self.flows:
                    # Create new flow
                    self.flows[flow_key] = EnhancedCICFlow(packet)
                    self.stats['flows_created'] += 1
                    
                    if self.stats['flows_created'] % 100 == 0:
                        logger.info(f"Created {self.stats['flows_created']} flows, "
                                  f"{len(self.flows)} active")
                else:
                    # Add packet to existing flow
                    success = self.flows[flow_key].add_packet(packet)
                    
                    if not success:
                        logger.debug(f"Failed to add packet to flow {flow_key}")
                    
                    # Check if flow terminated
                    if self.flows[flow_key].is_terminated:
                        terminated_flow = self.flows.pop(flow_key)
                        self.stats['flows_completed'] += 1
                        
                        # Cache the final features for immediate extraction
                        features = terminated_flow.extract_features()
                        if features:
                            self.feature_cache[flow_key] = {
                                'features': features,
                                'timestamp': time.time()
                            }
                            self.stats['feature_extractions'] += 1
                            logger.debug(f"Flow terminated: {terminated_flow.termination_reason}, "
                                       f"{len(terminated_flow.packets)} packets")
            
            return flow_key
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self.stats['extraction_failures'] += 1
            return None

    def extract_features(self, flow_key: Tuple) -> Optional[Dict[str, Any]]:
        """
        Extract features for a specific flow
        Returns cached features if available, otherwise extracts from active flow
        """
        try:
            # Check cache first
            if flow_key in self.feature_cache:
                cache_entry = self.feature_cache[flow_key]
                if time.time() - cache_entry['timestamp'] < self.cache_timeout:
                    return cache_entry['features']
                else:
                    # Remove expired cache entry
                    del self.feature_cache[flow_key]
            
            # Extract from active flow
            with self.lock:
                if flow_key in self.flows:
                    flow = self.flows[flow_key]
                    features = flow.extract_features()
                    
                    if features:
                        self.stats['feature_extractions'] += 1
                        return features
                    else:
                        logger.debug(f"Flow {flow_key} not ready for extraction")
                        return None
                else:
                    logger.debug(f"Flow key {flow_key} not found in active flows")
                    return None
                    
        except Exception as e:
            logger.error(f"Error extracting features for flow {flow_key}: {e}")
            self.stats['extraction_failures'] += 1
            return None

    def extract_features_from_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        MAIN METHOD: Extract features from a single packet
        This is the method you should call for each packet
        Returns features if flow is ready, None otherwise
        """
        flow_key = self.process_packet(packet)
        if flow_key:
            return self.extract_features(flow_key)
        return None

 