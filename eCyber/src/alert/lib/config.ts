import {
  AlertTriangle, 
  Shield, 
  Globe, 
  Activity, 
  Info,
  Zap,
  ShieldCheck,
  ShieldOff,
  Waypoints, // For Network/Flow
  FileText, // For Logs
  Database, // For Packet Analysis
  RadioTower, // For IPv6 / General Network
  Wrench, // For System
  Gauge, // For generic anomaly
  Ban, // For Blocked
} from 'lucide-react';
import { ElementType } from 'react';

export interface SeverityConfig {
  color: string; // Tailwind background color class e.g., 'bg-red-500'
  textColor: string; // Tailwind text color class e.g., 'text-red-700'
  bgColor: string; // Tailwind background color for badges e.g., 'bg-red-50'
  borderColor?: string; // Tailwind border color e.g., 'border-red-300'
  icon: ElementType;
  label: string;
}

export const severityConfig: Record<string, SeverityConfig> = {
  critical: { 
    color: 'bg-red-600', 
    textColor: 'text-red-700', 
    bgColor: 'bg-red-100 dark:bg-red-900/30', 
    borderColor: 'border-red-500/50',
    icon: AlertTriangle,
    label: 'Critical'
  },
  high: { 
    color: 'bg-orange-500', 
    textColor: 'text-orange-600', 
    bgColor: 'bg-orange-100 dark:bg-orange-900/30', 
    borderColor: 'border-orange-500/50',
    icon: AlertTriangle, // Consider a different one if AlertTriangle is only for critical
    label: 'High'
  },
  medium: { 
    color: 'bg-yellow-500', 
    textColor: 'text-yellow-600', 
    bgColor: 'bg-yellow-100 dark:bg-yellow-900/30', 
    borderColor: 'border-yellow-500/50',
    icon: Info,
    label: 'Medium'
  },
  low: { 
    color: 'bg-blue-500', 
    textColor: 'text-blue-600', 
    bgColor: 'bg-blue-100 dark:bg-blue-900/30', 
    borderColor: 'border-blue-500/50',
    icon: Info,
    label: 'Low'
  },
  info: { 
    color: 'bg-gray-500', 
    textColor: 'text-gray-600', 
    bgColor: 'bg-gray-100 dark:bg-gray-700/30', 
    borderColor: 'border-gray-500/50',
    icon: Info,
    label: 'Info'
  },
  unknown: { 
    color: 'bg-gray-400', 
    textColor: 'text-gray-500', 
    bgColor: 'bg-gray-100 dark:bg-gray-700/30', 
    borderColor: 'border-gray-400/50',
    icon: Info,
    label: 'Unknown'
  }
};

export interface AlertTypeConfig {
  icon: ElementType;
  label: string;
  color: string; // Tailwind text color class
}

export const alertTypeConfig: Record<string, AlertTypeConfig> = {
  threat: { icon: ShieldOff, label: 'Generic Threat', color: 'text-red-600' },
  malware: { icon: Shield, label: 'Malware', color: 'text-red-500' },
  phishing: { icon: Globe, label: 'Phishing', color: 'text-orange-500' },
  firewall_block: { icon: Ban, label: 'Firewall Block', color: 'text-red-600' },
  firewall_allow: { icon: ShieldCheck, label: 'Firewall Allow', color: 'text-green-600' },
  firewall: { icon: Shield, label: 'Firewall Event', color: 'text-blue-600' },
  signature: { icon: Zap, label: 'Signature Match', color: 'text-purple-500' },
  ip_block: { icon: Ban, label: 'IP Blocked', color: 'text-red-600' },
  network_anomaly: { icon: Waypoints, label: 'Network Anomaly', color: 'text-yellow-600' },
  http_activity: { icon: Globe, label: 'HTTP Log', color: 'text-sky-600' },
  dns_activity: { icon: Activity, label: 'DNS Log', color: 'text-teal-600' },
  packet_analysis: { icon: Database, label: 'Packet Detail', color: 'text-indigo-600' },
  ipv6_activity: { icon: RadioTower, label: 'IPv6 Activity', color: 'text-cyan-600' },
  system_alert: { icon: Wrench, label: 'System Alert', color: 'text-slate-600' },
  ids_alert: { icon: ShieldOff, label: 'IDS Alert', color: 'text-pink-600' },
  ips_alert: { icon: ShieldCheck, label: 'IPS Alert', color: 'text-lime-600' },
  anomaly: { icon: Gauge, label: 'Anomaly', color: 'text-yellow-500' }, // Generic anomaly
  intrusion: { icon: ShieldOff, label: 'Intrusion', color: 'text-red-700' },
  ddos: { icon: Zap, label: 'DDoS', color: 'text-purple-600' },
  unknown: { icon: HelpCircle, label: 'Unknown Event', color: 'text-gray-500'}
};

// Helper function to get severity config, defaulting to 'unknown'
export const getSeverityConfig = (severity?: string | null): SeverityConfig => {
  const key = severity?.toLowerCase() || 'unknown';
  return severityConfig[key] || severityConfig.unknown;
};

// Helper function to get type config, defaulting to 'unknown'
export const getTypeConfig = (type?: string | null): AlertTypeConfig => {
  const key = type?.toLowerCase() || 'unknown';
  return alertTypeConfig[key] || alertTypeConfig.unknown;
};

// Helper to format timestamps consistently
export const formatAlertTimestamp = (timestamp?: string | number | Date | null): string => {
  if (!timestamp) return 'N/A';
  try {
    const date = new Date(timestamp);
    // Check if date is valid
    if (isNaN(date.getTime())) {
      return 'Invalid Date';
    }
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    });
  } catch (e) {
    return 'Invalid Date';
  }
};

// Helper for displaying N/A for empty or nullish values
export const displayValue = (value: any, placeholder: string = "N/A"): string => {
  if (value === null || typeof value === 'undefined' || value === "") {
    return placeholder;
  }
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : placeholder;
  }
  return String(value);
};

// Import HelpCircle icon if not already imported
import { HelpCircle } from 'lucide-react';
