// frontend/src/hooks/useSocket.ts
import { useEffect, useCallback, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { throttle } from 'lodash';
import { useDispatch } from 'react-redux';
import { setIsBackendUp } from "@/app/slices/displaySlice";
import {
  addHttpActivity,
  addTcpActivity,
  addUdpActivity,
  addIcmpActivity,
  addArpActivity,
  addPayloadAnalysisEvent,
  addBehaviorAnalysisEvent,
  // Import other actions from socketSlice if they were missed or are needed by other events
} from '@/app/slices/socketSlice';
import {
  addDnsActivity,
  addFirewallEvent as addRealtimeFirewallEvent, // Alias to avoid conflict if any
  addThreatDetection,
  addIPv6Activity,
  addPacketEntry,
  updateSystemStats,
  updateSystemStatus,
  addSecurityAlert,
  addPhishingDetection,
  addThreatResponse,
  addQuarantinedFile,
  addNetworkVolume,
  addMLNotifications
} from '@/app/slices/realtimeDataSlice';
// Make sure all types used in dispatch are imported if not already defined in this file
import {
  DnsQuery,
  FirewallEvent,
  Alert, // Already defined
  IPv6Activity, // Already defined
  PacketMetadata, // Already defined
  SystemStats, // Already defined
  SystemStatus, // Already defined
  HttpActivity, // Already defined
  // Import specific data types for new activities if not defined below
  // For example, if TcpActivityData is not defined in this file yet
} from './usePacketSnifferSocket'; // Assuming types are exported from here or defined below

// ==================== Refined Event Export Interfaces (Task 7) ====================

// General Alert structure (used by security_alert, threat_detected, critical_alert)
export interface Alert {
  id: string;
  timestamp: string; // ISO 8601
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  source_ip?: string; // Optional as not all alerts might have it
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  description: string;
  threat_type: string; // Replaces 'type' for clarity
  rule_id?: string;
  metadata?: Record<string, any>; // For any other specific details
}

// Specific for HTTP activities
export interface HttpActivity {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  source_port?: number;
  destination_ip?: string;
  destination_port?: number;
  method?: string;
  host?: string;
  path?: string;
  status_code?: number;
  user_agent?: string;
  content_type?: string;
  protocol?: string; // e.g., "HTTP/1.1", "HTTP/2" (derived from backend 'version')
  payload_size?: number;
  threat_score?: number;
  risk_level?: "Critical" | "High" | "Medium" | "Low" | "Info";
  contributing_indicators?: string[];
}

// Specific for DNS activities - Renaming DnsQuery to DnsActivityData for broader scope
export interface DnsQueryInfo {
  query_name: string;
  query_type: string | number; // e.g., "A", "AAAA", or number
}

interface MlAlert {
  info: any[]
}

export interface DnsResponseInfo {
  name: string;
  type: string | number;
  ttl?: number;
  response_data?: string; // e.g., IP address, CNAME
}
export interface DnsActivityData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  queries: DnsQueryInfo[];
  responses: DnsResponseInfo[];
  is_suspicious?: boolean;
  tunnel_detected?: boolean;
  dga_score?: number;
  nxdomain_ratio?: number;
  unique_domains_queried?: number;
  query_chain_depth?: number;
  ttl_variation?: number;
  subdomain_entropy?: number;
  ttl_anomaly?: boolean;
}
// Keep DnsQuery if it's used elsewhere for just the query part, or remove if DnsActivityData.queries suffices
export interface DnsQuery { domain: string; recordType: string; } // Original, may be deprecated by DnsActivityData


// Specific for IPv6 activities
export interface IPv6Activity {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string; // Renamed from 'source'
  destination_ip?: string; // Renamed from 'destination'
  payload_size?: number; // Renamed from 'payloadSize'
  next_header?: number | string; // Can be number or resolved name
  traffic_class?: number;
  flow_label?: number;
  hop_limit?: number;
  threat_indicators?: { // Keep as nested object as backend sends it this way
    tunneling_suspected?: boolean;
    unusual_extension_headers?: boolean;
    flood_attempt?: boolean; // This was hypothetical, confirm if backend sends
  };
}

// Specific for Firewall events (consolidating FirewallEvent and FirewallData)
export interface FirewallActivityData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  action: "Blocked" | "Allowed" | "Unblocked"; // Standardized
  reason?: string;
  rule_id?: string;
  direction?: "Inbound" | "Outbound" | "Unknown";
  duration?: number; // For temporary blocks
  // os_type?: string; // Retained if needed, but often less relevant for event table
}
// Original FirewallEvent and FirewallData might be deprecated
export interface FirewallEvent { ip: string; type: 'block' | 'allow'; reason: string; } // Original
export interface FirewallData { rule: string; action: 'block' | 'allow'; } // Original

// Specific for Phishing detections
export interface PhishingData {
  id: string;
  timestamp: string; // ISO 8601
  url: string;
  source_ip?: string; // Client IP
  confidence?: number; // 0-1 or 0-100 scale
  status: "Detected" | "Blocked";
  threat_type: "Phishing"; // Fixed
  severity?: "Critical" | "High" | "Medium" | "Low" | "Info";
  reasons?: string[];
}

// Protocol-specific activity data
export interface TcpFlags { // For clarity in TcpActivityData
  syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean;
  psh?: boolean; urg?: boolean; ece?: boolean; cwr?: boolean;
}
export interface TcpActivityData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol: "TCP";
  length?: number; // Overall packet length
  flags?: TcpFlags; // Changed from string[] to object
  window_size?: number;
  seq_num?: number;
  ack_num?: number;
  tcp_payload_size?: number;
  payload_preview?: string; // hex
  payload_entropy?: number;
  // Flattened boolean threat indicators
  syn_flood_detected?: boolean;
  fin_scan_detected?: boolean;
  rst_attack_detected?: boolean;
  syn_ack_anomaly_detected?: boolean;
  suspicious_port_detected?: boolean;
  // Nested objects for complex analysis results
  sequence_analysis?: Record<string, any>; 
  window_analysis?: Record<string, any>;
  behavioral_analysis_tcp?: Record<string, any>;
}

export interface UdpActivityData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol: "UDP";
  length?: number; // UDP datagram length (header + payload)
  udp_payload_size?: number;
  payload_preview?: string; // hex
  payload_entropy?: number;
  // Flattened boolean threat indicators
  ntp_amplification_detected?: boolean;
  udp_flood_detected?: boolean;
  suspicious_port_detected?: boolean;
  // Nested object for detailed payload analysis
  udp_payload_analysis_details?: Record<string, any>; 
}

export interface IcmpActivityData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  destination_ip?: string;
  protocol: "ICMP";
  icmp_type?: number;
  icmp_code?: number;
  icmp_payload_size?: number;
  payload_preview?: string; // hex
  payload_entropy?: number;
  // Flattened boolean threat indicators
  ping_flood_detected?: boolean;
  ping_of_death_detected?: boolean;
  icmp_redirect_detected?: boolean;
  timestamp_probe_detected?: boolean;
}

export interface ArpActivityData {
  id: string;
  timestamp: string; // ISO 8601
  protocol: "ARP";
  operation?: 'request' | 'reply';
  sender_mac?: string;
  sender_ip?: string;
  target_mac?: string;
  target_ip?: string;
  // Flattened boolean threat indicators
  arp_spoofing_detected?: boolean;
  gratuitous_arp_detected?: boolean;
  mac_spoofing_detected?: boolean;
}

// General Payload Analysis (can be for non-HTTP/DNS payloads or deeper inspection)
export interface PayloadAnalysisData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  destination_ip?: string;
  protocol?: string; // Contextual protocol of the packet carrying this payload
  actual_payload_size?: number;
  payload_preview?: string; // hex
  entropy?: number;
  // Flattened boolean threat indicators
  shellcode_detected?: boolean;
  sql_injection_detected?: boolean;
  xss_detected?: boolean;
  exploit_kit_pattern_detected?: boolean;
  obfuscation_detected?: boolean;
  high_entropy_detected?: boolean;
}

// Behavioral Analysis (flow-based or more general)
export interface BehaviorAnalysisData {
  id: string;
  timestamp: string; // ISO 8601
  source_ip?: string;
  destination_ip?: string;
  flow_id?: number | string; // Hash or other flow identifier
  duration_seconds?: number;
  packet_count_in_flow?: number;
  byte_count_in_flow?: number;
  // Flattened boolean threat indicators
  port_scan_detected?: boolean;
  dos_attempt_detected?: boolean;
  // beaconing_detected?: boolean; // Removed as it was context-specific in sniffer
  data_exfiltration_detected?: boolean;
  // entity_id, behavior_type, score, details - kept if backend sends them for general cases
  entity_id?: string; 
  behavior_type?: string; 
  score?: number; 
  details?: Record<string, any>;
}

// System Statistics
export interface SystemStats {
  id?: string; // Optional, as it's a snapshot
  timestamp: string; // ISO 8601
  cpu_usage_percent?: number;
  memory_usage_percent?: number;
  network_packets_per_minute?: number; // Or another throughput metric
  // Direct fields for SystemHealthCard
  cpu?: number; 
  memory?: number;
  network?: number; // General network load indicator
  top_talkers?: Array<{ ip: string; packets: number; }>;
  threat_distribution?: Array<{ threat_type: string; count: number; }>;
  queue_stats?: Record<string, any>; // e.g., { processed: number, dropped: number }
}

// Other existing interfaces (review if they need similar ID/timestamp or refinement)
export interface ThreatData { id: string; message: string; severity: 'low' | 'medium' | 'high'; timestamp: string; threat_type: string; } // Added timestamp, threat_type
export interface TrainingProgress { epoch: number; accuracy: number; loss: number; }
export interface NetworkAnomaly { type: string; packetCount: number; timestamp: string; id: string;} // Added id, timestamp
export interface AccessData { user: string; sourceIp: string; timestamp: string; id: string;} // Added id, timestamp
export interface UrlClassification { url: string; category: string; confidence: number; timestamp: string; id: string;} // Added id, timestamp
export interface ServiceStatus { name: string; status: 'running' | 'stopped'; uptime?: number; timestamp: string; id: string;} // Added id, timestamp
export interface ErrorData { error: string; code?: number; timestamp: string; id: string;} // Added id, timestamp
export interface SshConnection { ip: string; user?: string; timestamp: string; id: string; banner?: string; is_bruteforce?: boolean; is_encrypted?: boolean; } // Added id, timestamp and details
export interface Rule { id: string; name: string; description: string; } // Seems fine
export interface SystemStatus { online: boolean; services: string[]; timestamp: string; id: string;} // Added id, timestamp
export interface CriticalAlert extends Alert {} // Inherits from Alert, which is now refined
export interface ThreatResponse { id: string; timestamp: string; action: string; target: string; success: boolean; } // Added id, timestamp
export interface NetworkTrafficVolume { networkVolume: number }
export interface ProcessInspection {id: string; timestamp: string; pid: number; name: string; suspicious: boolean; } // Added id, timestamp
export interface ConnectionAnalysis {id: string; timestamp: string; protocol: string; count: number; riskScore: number; } // Added id, timestamp
export interface FileQuarantined {id: string; timestamp: string; path: string; hash: string; reason: string; } // Added id, timestamp
export interface SystemSnapshot {id: string; timestamp: string; metrics: SystemStats; } // metrics type changed to refined SystemStats

export interface ProcessInfo { pid: number; name: string; cpu: number; memory: number; }
export interface AnalysisError { data: any; timestamp: string; id: string;} // Added id, timestamp
export interface PacketMetadata { // This is for the PacketData slice, used by PacketAnalysisTable
  id: string; // Added
  timestamp: number; // Keep as number if backend sends it this way, or convert to string
  src_ip: string | null;
  dst_ip: string | null;
  protocol: number | null; // Or string if resolved
  length: number;
  src_port: number | null;
  dst_port: number | null;
  payload_preview?: string | null; // Added
  // payload: string | null; // Original full payload, consider if needed or if preview is enough
}

// ==================== Event Type Definitions ====================
export type SocketEvent =
  | { type: 'threat_detected'; data: Alert } // Uses refined Alert
  | { type: 'ml_alert'; data: Alert}
  | { type: 'analysis_error'; data: AnalysisError}
  | { type: 'network_metrics'; data: any } // Keep as any if structure is unknown or varies
  | { type: 'phishing_link_detected'; data: PhishingData } // Uses refined PhishingData
  | { type: 'training_progress'; data: TrainingProgress }
  | { type: 'training_completed'; data: null }
  | { type: 'network_anomaly'; data: NetworkAnomaly }
  | { type: 'unauthorized_access'; data: AccessData }
  | { type: 'firewall_blocked'; data: FirewallActivityData } // Uses refined FirewallActivityData
  | { type: 'firewall_unblocked'; data: FirewallActivityData } // For unblock events
  | { type: 'url_classification_result'; data: UrlClassification }
  | { type: 'packet_bytes'; data:NetworkTrafficVolume}
  | { type: 'service_status'; data: ServiceStatus }
  | { type: 'user_alert'; data: Alert } // Uses refined Alert
  | { type: 'security_alert'; data: Alert } // Uses refined Alert
  | { type: 'http_activity'; data: HttpActivity[] } 
  | { type: 'behavior_analysis'; data: BehaviorAnalysisData[] } // Uses refined BehaviorAnalysisData
  | { type: 'payload_analysis'; data: PayloadAnalysisData[] } // Uses refined PayloadAnalysisData
  | { type: 'tcp_activity'; data: TcpActivityData[] } // Uses refined TcpActivityData
  | { type: 'udp_activity'; data: UdpActivityData[] } // Uses refined UdpActivityData
  | { type: 'arp_activity'; data: ArpActivityData[] } // Uses refined ArpActivityData
  | { type: 'icmp_activity'; data: IcmpActivityData[] } // Uses refined IcmpActivityData
  | { type: 'dns_activity'; data: DnsActivityData } // Uses new DnsActivityData
  | { type: 'database_error'; data: ErrorData }
  | { type: 'ssh_connection'; data: SshConnection }
  | { type: 'firewall_event'; data: FirewallActivityData } // Standardize to FirewallActivityData
  | { type: 'detection_error'; data: ErrorData }
  | { type: 'rules_updated'; data: { count: number } }
  | { type: 'get_rules'; data: Rule[] }
  | { type: 'system_stats'; data: SystemStats } // Uses refined SystemStats
  | { type: 'system_error'; data: ErrorData }
  | { type: 'system_status'; data: SystemStatus } 
  | { type: 'ipv6_activity'; data: IPv6Activity } // Uses refined IPv6Activity
  | { type: 'critical_alert'; data: Alert } // Uses refined Alert
  | { type: 'threat_response'; data: ThreatResponse } 
  | { type: 'process_inspection'; data: ProcessInspection } 
  | { type: 'connection_analysis'; data: ConnectionAnalysis } 
  | { type: 'file_quarantined'; data: FileQuarantined } 
  | { type: 'system_snapshot'; data: SystemSnapshot } 
  | { type: 'packet_data'; data: PacketMetadata }; // For PacketAnalysisTable, uses refined PacketMetadata

// ==================== Hook Return Type ====================
export interface UseSocketReturn {
  timestamp: number;
  src_ip: string | null;
  dst_ip: string | null;
  protocol: number | null;
  length: number;
  src_port: number | null;
  dst_port: number | null;
  payload: string | null;
}



// ==================== Hook Return Type ====================
export interface UseSocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  connectionError: string | null;
  connect: () => void;
  disconnect: () => void;
  emitEvent: <T extends SocketEvent['type']>(
    type: T,
    data: Extract<SocketEvent, { type: T }>['data']
  ) => void;
  subscribe: <T extends SocketEvent['type']>(
    eventType: T,
    handler: (data: Extract<SocketEvent, { type: T }>['data']) => void
  ) => void;
  unsubscribe: <T extends SocketEvent['type']>(
    eventType: T,
    handler: (data: Extract<SocketEvent, { type: T }>['data']) => void
  ) => void;
}

// ==================== Event Handlers Configuration ====================


// ==================== Socket Event Types ====================
const ALL_SOCKET_EVENTS: SocketEvent['type'][] = [
  'threat_detected', 'network_metrics', 'phishing_link_detected',
  'training_progress', 'training_completed', 'network_anomaly',
  'unauthorized_access', 'firewall_blocked', 'url_classification_result',
  'service_status', 'user_alert', 'ml_alert','security_alert', 'http_activity', 'tcp_activity', 'icmp_activity',
  'udp_activity','arp_activity','behavior_analysis',
  'dns_activity', 'database_error', 'ssh_connection', 'firewall_event','payload_analysis',
  'detection_error', 'rules_updated', 'get_rules', 'system_stats','packet_bytes',
  'system_error', 'system_status', 'ipv6_activity', 'critical_alert',
 'threat_response', 'process_inspection',
  'connection_analysis', 'file_quarantined', 'system_snapshot', 'packet_data'
];

// ==================== Main Hook Implementation ====================
export default function usePacketSniffer(): UseSocketReturn {
  
  const dispatch = useDispatch();

  const EVENT_HANDLERS_CONFIG = {
    // High-priority security events & RealtimeDataSlice dispatches
    'threat_detected': (data: Alert) => { // Assuming ThreatData is compatible with Alert or needs mapping
      // console.warn('⚠️ Threat Detected:', data);
      dispatch(addThreatDetection(data as Alert));
      // Optionally, if all threat_detected events are also general security alerts:
      dispatch(addSecurityAlert(data as Alert));
    },
    'critical_alert': (data: Alert) => { // Assuming CriticalAlert is compatible with Alert
      // console.error('🔥 Critical Alert:', data);
      dispatch(addSecurityAlert(data as Alert));
      // Optionally, if critical alerts should also go to threat detections:
      // dispatch(addThreatDetection(data as Alert));
    },
    'security_alert': (data: Alert) => {
        // console.info('🛡️ Security Alert:', data);
        dispatch(addSecurityAlert(data as Alert));
    },
    "ml_alert": (data) =>{
      dispatch(addMLNotifications(data))
      console.log("ML alert: ", data);
    },
    'user_alert': (data: Alert) => { // Assuming UserAlert is compatible with Alert
        // console.info('👤 User Alert:', data);
        dispatch(addSecurityAlert(data as Alert));
    },
    'packet_bytes': (data: NetworkTrafficVolume) =>{
      dispatch(addNetworkVolume(data))
    },
    // 'unauthorized_access': (data: AccessData) => console.warn('🚨 Unauthorized Access:', data), // No specific slice for this yet, handled by socketSlice
    'phishing_link_detected': (data: PhishingData) => {
      // console.warn('🎣 Phishing Link:', data);
      dispatch(addPhishingDetection(data as PhishingData));
    },
    
    // System monitoring events & RealtimeDataSlice dispatches
    'system_error': (data: ErrorData) => console.error('❌ System Error:', data), // No specific slice for this yet, handled by socketSlice
    'system_status': (data: SystemStatus) => {
      // console.info('🖥️ System Status:', data);
      dispatch(updateSystemStatus(data as SystemStatus));
    },
    'service_status': (data: ServiceStatus) => {
        // console.info('🛠️ Service Status:', data);
        // Potential: dispatch(updateSystemStatus(transformServiceStatusToSystemStatus(data)));
        // For now, just logging as per instructions, or if SystemStatus can take it directly:
        // dispatch(updateSystemStatus({ online: true, services: [data.name] } as SystemStatus)); // Example: adapt as needed
    },
    'system_stats': (data: SystemStats) => {
      // console.debug('📈 System Stats:', data);
      dispatch(updateSystemStats(data as SystemStats));
    },
    // 'analysis_error': (data: AnalysisError) => console.log("Analysis Error", data),
    
    // Network events & RealtimeDataSlice/socketSlice dispatches
    // 'network_anomaly': throttle((data: NetworkAnomaly) =>
      // console.log('🌐 Network Anomaly:', data), 1000), // No specific slice for this yet, handled by socketSlice
    'firewall_event': (data: FirewallEvent) => {
      // console.info('🔥 Firewall Event (realtime):', data);
      dispatch(addRealtimeFirewallEvent(data as FirewallEvent));
    },
    'firewall_blocked': (data: FirewallData) => { // This is from socketSlice.ts originally
        // console.info('🧱 Firewall Blocked (socketSlice):', data);
        // Assuming FirewallData might be different from FirewallEvent.
        // If it should also go to the realtimeDataSlice's firewallEvents:
        // dispatch(addRealtimeFirewallEvent(data as FirewallEvent)); // Requires FirewallData to be compatible/mapped to FirewallEvent
        // For now, keeping it separate as per instructions.
        // If you have a specific action in socketSlice for 'firewall_blocked', use it here.
        // Otherwise, if it's for the realtime slice:
        dispatch(addRealtimeFirewallEvent(data as unknown as FirewallEvent)); // Type assertion needed if FirewallData and FirewallEvent differ significantly
    },
    'packet_data': (data: PacketMetadata) => {
      // console.debug('📦 Packet Data:', data); // Throttled if too verbose
      dispatch(addPacketEntry(data as PacketMetadata));
    },
    'dns_activity': (data: DnsQuery) => {
        // console.log('DNS Activity:', data);
        dispatch(addDnsActivity(data as DnsQuery));
    },
    'ipv6_activity': (data: IPv6Activity) => {
        // console.log('IPv6 Activity:', data);
        dispatch(addIPv6Activity(data as IPv6Activity));
    },
  
    // Training events
    'training_progress': (data: TrainingProgress) => console.info('🏋️ Training Progress:', data),
    'training_completed': () => console.info('✅ Training Completed'),
    
    // HTTP and other protocol activities from socketSlice
    'http_activity': (data: HttpActivity[]) => { // Assuming array based on previous code
      dispatch(addHttpActivity(data as HttpActivity[]));
      // console.log('🌐 HTTP Activity:', data);
    },
    'tcp_activity': (data: TcpActivityData[]) => {
      // console.log('🌐 TCP Activity:', data);
      dispatch(addTcpActivity(data as TcpActivityData[]));
    },
    'udp_activity': (data: UdpActivityData[]) => {
      // console.log('🌐 UDP Activity:', data);
      dispatch(addUdpActivity(data as UdpActivityData[]));
    },
    'icmp_activity': (data: IcmpActivityData[]) => {
      // console.log('🌐 ICMP Activity:', data);
      dispatch(addIcmpActivity(data as IcmpActivityData[]));
    },
    'arp_activity': (data: ArpActivityData[]) => {
      // console.log('🌐 ARP Activity:', data);
      dispatch(addArpActivity(data as ArpActivityData[]));
    },
    'payload_analysis': (data: PayloadAnalysisData[]) => {
      // console.log('🔍 Payload Analysis:', data);
      dispatch(addPayloadAnalysisEvent(data as PayloadAnalysisData[]));
    },
    'behavior_analysis': (data: BehaviorAnalysisData[]) => {
      // console.log('🧠 Behavior Analysis:', data);
      dispatch(addBehaviorAnalysisEvent(data as BehaviorAnalysisData[]));
    },
    'threat_response': (data: ThreatResponse) => {
      // console.log('🛡️ Threat Response:', data);
      dispatch(addThreatResponse(data as ThreatResponse));
    },
    'file_quarantined': (data: FileQuarantined) => {
      // console.log('📦 File Quarantined:', data);
      dispatch(addQuarantinedFile(data as FileQuarantined));
    },
    
    // Default handler for unconfigured events
    'default': () => null
  };

  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const initialized = useRef(false); // To prevent multiple initial connections
  const handlers = useRef(new Map<SocketEvent['type'], Set<Function>>());

  // State for custom reconnection logic
  const [retryAttempts, setRetryAttempts] = useState(0);
  const retryTimerIdRef = useRef<NodeJS.Timeout | null>(null);
  const MAX_RETRY_ATTEMPTS = 5;
  const RETRY_INTERVAL_MS = 30000; // 30 seconds
  const userManuallyDisconnected = useRef(false); // Flag to prevent retries on manual disconnect

  // ==================== Event Handler ====================
  const handleEvent = useCallback((event: SocketEvent) => {
    // Call registered handlers first
    const eventHandlers = handlers.current.get(event.type);
    eventHandlers?.forEach(handler => handler(event.data));

    // Then call configured handlers
    const configuredHandler = EVENT_HANDLERS_CONFIG[event.type] || 
      ((data: any) => EVENT_HANDLERS_CONFIG.default(event.type, data));
    configuredHandler(event.data);
  }, []);

  // ==================== Connection Management ====================
  const connect = useCallback((isRetry: boolean = false) => {
    if (socketRef.current?.connected) return;
    // Prevent multiple initial connection attempts if already trying or initialized by effect
    if (!isRetry && initialized.current && !socketRef.current) { 
      console.log("Connect called, but already initialized or attempting. current socket:", socketRef.current);
      //return; // Allow retries to proceed
    }


    // If it's a new connection attempt (not a retry from the timer), clear any existing retry timer.
    if (!isRetry && retryTimerIdRef.current) {
      clearTimeout(retryTimerIdRef.current);
      retryTimerIdRef.current = null;
    }
    
    userManuallyDisconnected.current = false; // Reset manual disconnect flag on new connect attempt

    const newSocket = io('http://127.0.0.1:8000/packet_sniffer', {
      path: '/socket.io',
      transports: ['websocket'],
      reconnection: false, // Disable built-in reconnection
      autoConnect: false,
      upgrade: false,
      // Consider adding timeout for connection attempts
      // timeout: 10000, // 10 seconds
    });

    newSocket.on('connect', () => {
      setIsConnected(true);
      setConnectionError(null);
      setRetryAttempts(0); // Reset retries on successful connection
      if (retryTimerIdRef.current) {
        clearTimeout(retryTimerIdRef.current);
        retryTimerIdRef.current = null;
      }
      dispatch(setIsBackendUp(true))
      console.log("✅ Socket connected to:", newSocket.nsp);
      if (!initialized.current) initialized.current = true; // Mark as initialized on first successful connect
      socketRef.current = newSocket; // Assign socketRef here after successful connect
    });

    newSocket.on('connect_error', (err) => {
      console.error('❌ Connection Error:', err.message);
      setConnectionError(`Connection failed: ${err.message}`);
      setIsConnected(false); // Ensure isConnected is false
      socketRef.current = null; // Clear socketRef on connection error
      initialized.current = false; // Allow re-initialization by useEffect or manual call

      if (!userManuallyDisconnected.current && retryAttempts < MAX_RETRY_ATTEMPTS) {
        setRetryAttempts(prev => prev + 1);
        const nextRetryIn = RETRY_INTERVAL_MS / 1000;
        setConnectionError(`Connection failed. Attempting retry ${retryAttempts + 1}/${MAX_RETRY_ATTEMPTS} in ${nextRetryIn}s. Error: ${err.message}`);
        console.log(`Retrying connection, attempt ${retryAttempts + 1}`);
        if (retryTimerIdRef.current) clearTimeout(retryTimerIdRef.current); // Clear previous timer if any
        retryTimerIdRef.current = setTimeout(() => connect(true), RETRY_INTERVAL_MS);
      } else if (!userManuallyDisconnected.current) {
        setConnectionError(`Connection failed after ${MAX_RETRY_ATTEMPTS} attempts. Please check the server or network. Error: ${err.message}`);
        console.error(`Failed to connect after ${MAX_RETRY_ATTEMPTS} attempts.`);
      }
    });

    newSocket.on('disconnect', (reason) => {
      setIsConnected(false);
      const wasConnected = socketRef.current === newSocket; // Check if this was the active socket
      socketRef.current = null; // Clear socketRef on disconnect
      initialized.current = false; // Allow re-initialization

      console.warn(`⚠️ Socket Disconnected. Reason: ${reason}`);
      if (userManuallyDisconnected.current) {
        setConnectionError("Disconnected by user.");
        console.log("Disconnected manually, no retry.");
        return;
      }

      if (wasConnected && reason !== 'io client disconnect' && retryAttempts < MAX_RETRY_ATTEMPTS) {
        setRetryAttempts(prev => prev + 1);
        const nextRetryIn = RETRY_INTERVAL_MS / 1000;
        setConnectionError(`Disconnected. Attempting retry ${retryAttempts + 1}/${MAX_RETRY_ATTEMPTS} in ${nextRetryIn}s. Reason: ${reason}`);
        console.log(`Retrying connection due to disconnect, attempt ${retryAttempts + 1}`);
        if (retryTimerIdRef.current) clearTimeout(retryTimerIdRef.current);
        retryTimerIdRef.current = setTimeout(() => connect(true), RETRY_INTERVAL_MS);
      } else if (wasConnected && reason !== 'io client disconnect') {
        setConnectionError(`Disconnected. Max retries (${MAX_RETRY_ATTEMPTS}) reached. Reason: ${reason}`);
        console.error(`Disconnected. Max retries reached.`);
      }
    });

    // Register all event listeners only once per socket instance
    ALL_SOCKET_EVENTS.forEach(eventType => {
      newSocket.on(eventType, (data: any) => handleEvent({ type: eventType, data } as SocketEvent));
    });
    
    console.log("Attempting to connect socket...");
    newSocket.connect();
    // Do not set socketRef.current here immediately for new sockets, wait for 'connect' event
    // For retries where newSocket is the same as socketRef.current, it's fine.
    if (!socketRef.current) { // Only if there's no existing socket trying to connect
       // This might lead to issues if connect() is called rapidly.
       // socketRef.current = newSocket; // This was problematic. Assign on 'connect'
    }


  }, [handleEvent, retryAttempts]); // Added retryAttempts as a dependency

  // ==================== Disconnection Handler ====================
  const disconnect = useCallback(() => {
    userManuallyDisconnected.current = true; // Set flag for manual disconnect
    if (retryTimerIdRef.current) {
      clearTimeout(retryTimerIdRef.current);
      retryTimerIdRef.current = null;
    }
    setRetryAttempts(0); // Reset retries on manual disconnect

    if (socketRef.current) {
      socketRef.current.disconnect();
      // socketRef.current = null; // Done in 'disconnect' event handler
      // initialized.current = false; // Done in 'disconnect' event handler
      // setIsConnected(false); // Done in 'disconnect' event handler
      console.log('🔌 Socket Disconnection initiated by user.');
    }
  }, []);

  // ==================== Event Emission ====================
  const emitEvent = useCallback<UseSocketReturn['emitEvent']>((type, data) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(type, data);
    } else {
      console.warn('⚠️ Cannot emit event - socket not connected');
    }
  }, []);

  // ==================== Subscription Management ====================
  const subscribe = useCallback<UseSocketReturn['subscribe']>((eventType, handler) => {
    if (!handlers.current.has(eventType)) {
      handlers.current.set(eventType, new Set());
    }
    handlers.current.get(eventType)?.add(handler);
  }, []);

  const unsubscribe = useCallback<UseSocketReturn['unsubscribe']>((eventType, handler) => {
    handlers.current.get(eventType)?.delete(handler);
  }, []);

  // ==================== Lifecycle Management ====================
  useEffect(() => {
    // Initial connection attempt
    if (!initialized.current && !socketRef.current && !userManuallyDisconnected.current) {
        console.log("Initial effect: calling connect()");
        connect();
        initialized.current = true; // Mark that initial attempt has been made by useEffect
    }

    // Cleanup on unmount
    return () => {
      console.log("Cleaning up usePacketSniffer hook.");
      if (retryTimerIdRef.current) {
        clearTimeout(retryTimerIdRef.current);
      }
      if (socketRef.current) {
        // Check if this is a user-initiated disconnect or component unmount
        // If it's a component unmount, we might not want to set userManuallyDisconnected.current = true
        // However, for simplicity, any disconnect via this cleanup is treated as final for this hook instance.
        socketRef.current.disconnect();
      }
      handlers.current.clear();
      initialized.current = false; // Reset for potential re-mount or new instance
    };
  }, [connect]); // `connect` itself has dependencies like `retryAttempts`


  return {
    socket: socketRef.current,
    isConnected,
    connectionError, // This will now include retry information
    connect, // Allow manual reconnection attempt from UI
    disconnect,
    emitEvent,
    subscribe,
    unsubscribe,
  };
}