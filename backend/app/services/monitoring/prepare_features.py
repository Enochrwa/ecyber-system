import time
import threading
from collections import defaultdict
import numpy as np
from scapy.all import *

# Exact 40 features from CICIDS2017 dataset
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
    """
    CICFlowMeter-compatible flow implementation with FIXED zero features
    """
    
    def __init__(self, first_packet):
        # Extract flow info FIRST - before any computations
        self._extract_flow_info(first_packet)
        
        self.packets = []
        self.fwd_packets = []
        self.bwd_packets = []
        
        # Timing - ALL in microseconds for consistency
        self.start_time = float(first_packet.time)
        self.last_seen = float(first_packet.time)
        self.flow_iat = []  # Inter-arrival times between any packets (microseconds)
        self.fwd_iat = []   # Inter-arrival times between forward packets (microseconds)  
        self.bwd_iat = []   # Inter-arrival times between backward packets (microseconds)
        
        # Store packet timestamps for better IAT calculation
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        
        # Packet lengths (including headers)
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        
        # Byte counters (payload only for subflow bytes)
        self.total_fwd_bytes = 0  # payload bytes
        self.total_bwd_bytes = 0  # payload bytes
        
        # TCP flags - count ALL occurrences with better detection
        self.fin_flag_count = 0
        self.syn_flag_count = 0  
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        
        # Window sizes - capture from ANY TCP packet, prioritize SYN
        self.fwd_init_win_bytes = 0
        self.bwd_init_win_bytes = 0
        self.fwd_win_captured = False
        self.bwd_win_captured = False
        
        # Flow state
        self.is_terminated = False
        self.termination_reason = None
        self.is_ready_for_prediction = False
        
        # Active/Idle detection - microsecond thresholds like CICFlowMeter
        self.active_times = []
        self.idle_times = []
        self.last_activity_time = float(first_packet.time)
        
        # Bulk transfer detection
        self.bulk_state_fwd = {'count': 0, 'size': 0, 'start_time': 0}
        self.bulk_state_bwd = {'count': 0, 'size': 0, 'start_time': 0}
        
        # Add first packet
        self.add_packet(first_packet)

    def _extract_flow_info(self, packet):
        """Extract 5-tuple flow information for any network protocol"""
        self.src_ip = '0.0.0.0'
        self.dst_ip = '0.0.0.0'
        self.src_port = 0
        self.dst_port = 0
        self.protocol = 0

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            self.src_ip = ip_layer.src
            self.dst_ip = ip_layer.dst
            self.protocol = ip_layer.proto

            # Dynamically find any layer with sport/dport attributes
            transport_layer = ip_layer.payload
            while transport_layer:
                if hasattr(transport_layer, 'sport') and hasattr(transport_layer, 'dport'):
                    self.src_port = transport_layer.sport
                    self.dst_port = transport_layer.dport
                    break
                transport_layer = transport_layer.payload

        elif hasattr(packet, 'src') and hasattr(packet, 'dst'):
            # Fallback for non-IP protocols like ARP, Ethernet, etc.
            self.src_ip = packet.src
            self.dst_ip = packet.dst
            self.protocol = getattr(packet, 'type', 0)

    def _is_forward_packet(self, packet):
        """
        Determine packet direction based on first packet in flow
        """
        if packet.haslayer(IP):
            return (packet[IP].src == self.src_ip and 
                   packet[IP].dst == self.dst_ip)
        elif hasattr(packet, 'src'):
            return packet.src == self.src_ip
        return True  # Default to forward if can't determine

    def _has_payload(self, packet):
        """Check if packet has actual application payload or is significant"""
        # For UDP, always count as it's likely meaningful data
        if packet.haslayer(UDP):
            return True
            
        if packet.haslayer(Raw):
            return len(packet[Raw].load) > 0
        
        # For TCP, be more inclusive - count control packets too
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            # Count SYN, FIN, RST, PSH packets even without payload
            if tcp_flags & 0x02 or tcp_flags & 0x01 or tcp_flags & 0x04 or tcp_flags & 0x08:  # SYN, FIN, RST, PSH
                return True
            # Pure ACK with no data - still count for backward direction
            # as it represents flow activity
            return True
        
        return True  # For non-TCP/UDP, assume it has meaningful data

    def _calculate_payload_bytes(self, packet):
        """Calculate payload bytes (application data only)"""
        if not packet.haslayer(IP):
            return len(packet)  # For non-IP, use full packet
        
        total_len = len(packet)
        
        # Subtract Ethernet header (14 bytes)
        ip_start = 14
        
        # Subtract IP header
        ip_header_len = packet[IP].ihl * 4
        
        # Subtract transport header
        transport_header_len = 0
        if packet.haslayer(TCP):
            transport_header_len = packet[TCP].dataofs * 4
        elif packet.haslayer(UDP):
            transport_header_len = 8
        
        payload_len = total_len - ip_start - ip_header_len - transport_header_len
        return max(0, payload_len)

    def _should_terminate_flow(self, packet):
        """Check if flow should terminate"""
        if not packet.haslayer(TCP):
            return False
            
        tcp_flags = packet[TCP].flags
        
        # RST immediately terminates
        if tcp_flags & 0x04:  # RST flag
            self.termination_reason = "RST"
            return True
            
        # FIN flag handling - need FIN from both directions
        if tcp_flags & 0x01:  # FIN flag
            fwd_fin_count = sum(1 for p in self.fwd_packets 
                               if p.haslayer(TCP) and (p[TCP].flags & 0x01))
            bwd_fin_count = sum(1 for p in self.bwd_packets 
                               if p.haslayer(TCP) and (p[TCP].flags & 0x01))
            
            if fwd_fin_count > 0 and bwd_fin_count > 0:
                self.termination_reason = "FIN-FIN"
                return True
                
        return False

    def _check_readiness_for_prediction(self):
        """Check if flow is ready for ML prediction"""
        # Minimum 2 packets total for basic flow analysis
        min_packets = len(self.packets) >= 2
        
        # Need some bidirectional activity OR sufficient unidirectional activity
        bidirectional = len(self.fwd_packets) >= 1 and len(self.bwd_packets) >= 1
        sufficient_unidirectional = len(self.packets) >= 3
        
        # Flow must have non-zero duration
        has_duration = (self.last_seen - self.start_time) > 0
        
        # For live prediction, be more aggressive about readiness
        sufficient_activity = (
            self.is_terminated or 
            (self.last_seen - self.start_time) >= 0.1 or  # 100ms minimum
            len(self.packets) >= 4
        )
        
        return (min_packets and has_duration and sufficient_activity and 
                (bidirectional or sufficient_unidirectional))

    def _update_bulk_detection(self, packet, is_forward):
        """Update bulk transfer detection (relaxed for 3+ packet bursts)"""
        current_time = float(packet.time)
        packet_size = len(packet)
        
        if is_forward:
            bulk_state = self.bulk_state_fwd
        else:
            bulk_state = self.bulk_state_bwd
        
        # Reset if gap > 100ms (100,000 microseconds)
        if bulk_state['count'] > 0:
            time_gap = (current_time - bulk_state['start_time']) * 1_000_000
            if time_gap > 100_000:  # 100ms threshold
                bulk_state['count'] = 0
                bulk_state['size'] = 0
        
        # Start or continue bulk detection
        if bulk_state['count'] == 0:
            bulk_state['start_time'] = current_time
            bulk_state['count'] = 1
            bulk_state['size'] = packet_size
        else:
            bulk_state['count'] += 1
            bulk_state['size'] += packet_size

    def _extract_tcp_flags(self, packet):
        """Enhanced TCP flag extraction with better detection"""
        if not packet.haslayer(TCP):
            return
            
        tcp_layer = packet[TCP]
        
        # Use bit field analysis for reliable flag detection
        try:
            flags_val = int(tcp_layer.flags)
            
            if flags_val & 0x01:  # FIN
                self.fin_flag_count += 1
            if flags_val & 0x02:  # SYN
                self.syn_flag_count += 1
            if flags_val & 0x08:  # PSH
                self.psh_flag_count += 1
            if flags_val & 0x10:  # ACK
                self.ack_flag_count += 1
            if flags_val & 0x20:  # URG
                self.urg_flag_count += 1
                    
        except Exception as e:
            # Fallback: try accessing flags as attributes
            try:
                flags = tcp_layer.flags
                if hasattr(flags, 'FIN') and flags.FIN:
                    self.fin_flag_count += 1
                if hasattr(flags, 'SYN') and flags.SYN:
                    self.syn_flag_count += 1
                if hasattr(flags, 'PSH') and flags.PSH:
                    self.psh_flag_count += 1
                if hasattr(flags, 'ACK') and flags.ACK:
                    self.ack_flag_count += 1
                if hasattr(flags, 'URG') and flags.URG:
                    self.urg_flag_count += 1
            except:
                pass

    def _capture_window_size(self, packet, is_forward):
        """Enhanced window size capture - prioritize SYN but fallback to any TCP"""
        if not packet.haslayer(TCP):
            return
            
        tcp_layer = packet[TCP]
        window_size = getattr(tcp_layer, 'window', 0)
        
        if is_forward and not self.fwd_win_captured and window_size > 0:
            # Prioritize SYN packets, but accept any packet with non-zero window
            tcp_flags = int(tcp_layer.flags)
            if (tcp_flags & 0x02) or window_size > 0:  # SYN flag or any non-zero window
                self.fwd_init_win_bytes = window_size
                self.fwd_win_captured = True
        elif not is_forward and not self.bwd_win_captured and window_size > 0:
            # Same for backward direction
            tcp_flags = int(tcp_layer.flags)
            if (tcp_flags & 0x02) or window_size > 0:  # SYN flag or any non-zero window
                self.bwd_init_win_bytes = window_size
                self.bwd_win_captured = True

    def add_packet(self, packet):
        """Add packet to flow and update all statistics"""
        if self.is_terminated:
            return False
            
        current_time = float(packet.time)
        packet_len = len(packet)  # Total packet length including headers
        
        # Basic packet tracking
        self.packets.append(packet)
        self.packet_lengths.append(packet_len)
        
        # Calculate flow inter-arrival time (between any consecutive packets)
        if len(self.packets) > 1:
            prev_time = float(self.packets[-2].time)
            iat_microseconds = (current_time - prev_time) * 1_000_000
            self.flow_iat.append(iat_microseconds)
            
            # Idle time detection - gap > 1ms (1000 microseconds) for more realistic idle detection
            if iat_microseconds > 1000:  # 1ms in microseconds
                idle_time_seconds = iat_microseconds / 1_000_000
                self.idle_times.append(idle_time_seconds)
        
        # Determine packet direction
        is_forward = self._is_forward_packet(packet)
        
        if is_forward:
            self.fwd_packets.append(packet)
            self.fwd_packet_lengths.append(packet_len)
            self.fwd_timestamps.append(current_time)
            
            # Calculate forward IAT - use timestamp list for accuracy
            if len(self.fwd_timestamps) > 1:
                prev_fwd_time = self.fwd_timestamps[-2]
                fwd_iat_us = (current_time - prev_fwd_time) * 1_000_000
                self.fwd_iat.append(fwd_iat_us)
            
            # Forward payload bytes
            payload_bytes = self._calculate_payload_bytes(packet)
            self.total_fwd_bytes += payload_bytes
                    # Capture Init_Win_bytes_forward (bytes sent before handshake completes)
            if not self.fwd_win_captured:
                self.fwd_init_win_bytes += payload_bytes
                if packet.haslayer(TCP) and packet[TCP].flags & 0x10:  # ACK flag
                    self.fwd_win_captured = True

                
        else:
            # More inclusive backward packet counting
            if self._has_payload(packet):
                self.bwd_packets.append(packet)
                self.bwd_packet_lengths.append(packet_len)
                self.bwd_timestamps.append(current_time)
                
                # Calculate backward IAT - use timestamp list for accuracy
                if len(self.bwd_timestamps) > 1:
                    prev_bwd_time = self.bwd_timestamps[-2]
                    bwd_iat_us = (current_time - prev_bwd_time) * 1_000_000
                    self.bwd_iat.append(bwd_iat_us)
                
                # Backward payload bytes
                payload_bytes = self._calculate_payload_bytes(packet)
                self.total_bwd_bytes += payload_bytes
                if not self.bwd_win_captured:
                    self.bwd_init_win_bytes += payload_bytes
                    if packet.haslayer(TCP) and packet[TCP].flags & 0x10:  # ACK flag
                        self.bwd_win_captured = True

        
        # Enhanced TCP flag counting
        self._extract_tcp_flags(packet)
        
        # Enhanced window size capture
        # self._capture_window_size(packet, is_forward)
        
        # Update bulk detection
        self._update_bulk_detection(packet, is_forward)
        
        # Update timing
        self.last_seen = current_time
        self.last_activity_time = current_time
        
        # Check for flow termination
        if self._should_terminate_flow(packet):
            self.is_terminated = True
        
        # Update readiness status
        self.is_ready_for_prediction = self._check_readiness_for_prediction()
            
        return True

    def extract_features(self):
        """Extract exact CICIDS2017 features with FIXED zero features"""
        if not self.is_ready_for_prediction:
            return None
        
        # Flow duration in microseconds (consistent with IAT units)
        flow_duration_seconds = max(self.last_seen - self.start_time, 0.000001)
        flow_duration_microseconds = flow_duration_seconds * 1_000_000
        
        # Packet length statistics (total packet size including headers)
        packet_lengths = np.array(self.packet_lengths, dtype=float)
        min_packet_length = float(np.min(packet_lengths)) if len(packet_lengths) > 0 else 0.0
        max_packet_length = float(np.max(packet_lengths)) if len(packet_lengths) > 0 else 0.0
        packet_length_mean = float(np.mean(packet_lengths)) if len(packet_lengths) > 0 else 0.0
        packet_length_std = float(np.std(packet_lengths, ddof=0)) if len(packet_lengths) > 1 else 0.0
        packet_length_variance = float(np.var(packet_lengths, ddof=0)) if len(packet_lengths) > 1 else 0.0
        
        # Forward packet statistics
        fwd_packet_lengths = np.array(self.fwd_packet_lengths, dtype=float)
        total_length_fwd_packets = float(np.sum(fwd_packet_lengths)) if len(fwd_packet_lengths) > 0 else 0.0
        fwd_packet_length_min = float(np.min(fwd_packet_lengths)) if len(fwd_packet_lengths) > 0 else 0.0
        
        # Backward packet statistics
        bwd_packet_lengths = np.array(self.bwd_packet_lengths, dtype=float)
        bwd_packet_length_max = float(np.max(bwd_packet_lengths)) if len(bwd_packet_lengths) > 0 else 0.0
        bwd_packet_length_min = float(np.min(bwd_packet_lengths)) if len(bwd_packet_lengths) > 0 else 0.0
        bwd_packet_length_mean = float(np.mean(bwd_packet_lengths)) if len(bwd_packet_lengths) > 0 else 0.0
        bwd_packet_length_std = float(np.std(bwd_packet_lengths, ddof=0)) if len(bwd_packet_lengths) > 1 else 0.0
        
        # Flow IAT statistics (microseconds) - Handle edge cases better
        flow_iat = np.array(self.flow_iat, dtype=float)
        flow_iat_mean = float(np.mean(flow_iat)) if len(flow_iat) > 0 else 0.0
        flow_iat_std = float(np.std(flow_iat, ddof=0)) if len(flow_iat) > 1 else 0.0
        flow_iat_max = float(np.max(flow_iat)) if len(flow_iat) > 0 else 0.0
        
        # Forward IAT statistics (microseconds) - FIXED: Better handling of single forward packet
        fwd_iat = np.array(self.fwd_iat, dtype=float)
        if len(fwd_iat) > 0:
            fwd_iat_total = float(np.sum(fwd_iat))
            fwd_iat_mean = float(np.mean(fwd_iat))
            fwd_iat_std = float(np.std(fwd_iat, ddof=0)) if len(fwd_iat) > 1 else 0.0
            fwd_iat_max = float(np.max(fwd_iat))
        else:
            # When only one forward packet, use flow duration for meaningful values
            if len(self.fwd_packets) == 1:
                fwd_iat_total = flow_duration_microseconds
                fwd_iat_mean = flow_duration_microseconds
                fwd_iat_std = 0.0
                fwd_iat_max = flow_duration_microseconds
            else:
                fwd_iat_total = 0.0
                fwd_iat_mean = 0.0
                fwd_iat_std = 0.0
                fwd_iat_max = 0.0
        
        # Backward IAT statistics (microseconds) - Better handling
                # Backward IAT statistics (microseconds) – add “single-packet” fallback
        bwd_iat = np.array(self.bwd_iat, dtype=float)
        if len(bwd_iat) > 0:
            bwd_iat_total = float(np.sum(bwd_iat))
            bwd_iat_mean  = float(np.mean(bwd_iat))
            bwd_iat_std   = float(np.std(bwd_iat, ddof=0)) if len(bwd_iat) > 1 else 0.0
            bwd_iat_max   = float(np.max(bwd_iat))
        else:
            # when exactly one backward packet, mirror flow duration
            if len(self.bwd_packets) == 1:
                bwd_iat_total = flow_duration_microseconds
                bwd_iat_mean  = flow_duration_microseconds
                bwd_iat_std   = 0.0
                bwd_iat_max   = flow_duration_microseconds
            else:
                bwd_iat_total = 0.0
                bwd_iat_mean  = 0.0
                bwd_iat_std   = 0.0
                bwd_iat_max   = 0.0

        
        # Rate calculations (packets per second)
        bwd_packets_s = float(len(self.bwd_packets)) / flow_duration_seconds if flow_duration_seconds > 0 else 0.0
        
        # Ratios
        down_up_ratio = float(len(self.bwd_packets)) / float(len(self.fwd_packets)) if len(self.fwd_packets) > 0 else 0.0
        
        # Average sizes
        average_packet_size = packet_length_mean
        avg_bwd_segment_size = bwd_packet_length_mean
        
        # Subflow bytes (payload bytes only)
        subflow_fwd_bytes = float(self.total_fwd_bytes)
        
        # Idle time statistics (converted to microseconds for consistency)
        idle_times = np.array(self.idle_times, dtype=float) * 1_000_000  # Convert to microseconds
        idle_mean = float(np.mean(idle_times)) if len(idle_times) > 0 else 0.0
        idle_std = float(np.std(idle_times, ddof=0)) if len(idle_times) > 1 else 0.0
        idle_max = float(np.max(idle_times)) if len(idle_times) > 0 else 0.0  
        idle_min = float(np.min(idle_times)) if len(idle_times) > 0 else 0.0
        
        return {
            'Destination Port': int(self.dst_port),
            'Flow Duration': flow_duration_microseconds,
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

class FlowManager:
    """Enhanced flow manager with all CICFlowMeter compatibility fixes"""
    
    def __init__(self, flow_timeout=120):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.lock = threading.Lock()
        self.flow_count = 0
        
        # Start cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_flows, daemon=True)
        self.cleanup_thread.start()

    def _get_flow_key(self, packet):
        """Generate bidirectional flow key"""
        if not packet.haslayer(IP):
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        src_port = 0
        dst_port = 0
        
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

    def process_packet(self, packet):
        """Process packet and return features if ready"""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return None
        
        with self.lock:
            # Create new flow or add to existing
            if flow_key not in self.flows:
                self.flows[flow_key] = CICFlow(packet)
                self.flow_count += 1
                flow = self.flows[flow_key]
            else:
                flow = self.flows[flow_key]
                flow.add_packet(packet)
            
            # Check if flow is ready for prediction
            if flow.is_ready_for_prediction:
                features = flow.extract_features()
                
                # If flow is terminated, remove it
                if flow.is_terminated:
                    del self.flows[flow_key]
                
                return features
            
            return None

    def _cleanup_flows(self):
        """Clean up expired flows"""
        while self.running:
            current_time = time.time()
            expired_flows = []
            
            with self.lock:
                for flow_key, flow in list(self.flows.items()):
                    if current_time - flow.last_activity_time > self.flow_timeout:
                        expired_flows.append(flow_key)
                        del self.flows[flow_key]
            
            time.sleep(30)  # Check every 30 seconds

    def get_active_flows_count(self):
        """Get number of active flows"""
        with self.lock:
            return len(self.flows)

    def stop(self):
        """Stop the flow manager"""
        self.running = False