import React, { useEffect, useState } from 'react';
import { Socket } from 'socket.io-client';
import { useTheme } from '@/components/theme/ThemeProvider';

// Define prediction interface based on the provided structure
interface MLPrediction {
  index: number;
  anomaly_detected: boolean;
  true_label: string;
  predicted_label: string;
  confidence: number;
  class_probabilities: {
    [key: string]: number;
  };
}

interface MLPredictionPayload {
  predictions: MLPrediction[];
  last_modified: string;
  error?: string;
}

interface AllMLPredictions {
  [predictionType: string]: MLPredictionPayload | { error: string };
}

// Define AlertData interface - converted from predictions
interface AlertData {
  id: string;
  timestamp: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  description: string;
  threat_type: string;
  rule_id?: string;
  metadata?: any;
  anomaly_score?: number;
  threshold?: number;
  is_anomaly?: number;
  confidence?: number;
  predicted_label?: string;
  true_label?: string;
  class_probabilities?: { [key: string]: number };
}

// Interface for Firewall Block events (kept for firewall alerts)
interface FirewallAlertData {
  id: string;
  timestamp: string;
  ip_address: string;
  reason: string;
  duration_seconds: number;
  source_component: string;
  packet_info?: {
    dst_ip?: string;
    protocol?: string;
  };
  action_taken: string;
}

import { 
  Shield, AlertTriangle, Network, Database, User, 
  Package, Globe, Terminal, Monitor 
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

// Import GenericAttackCard
import GenericAttackCard from '@/components/attack-simulations/GenericAttackCard';

// Import other simulation components
import NetworkTrafficVisualizer from '@/components/attack-simulations/NetworkTrafficVisualizer';
import UserEducationCenter from '@/components/attack-simulations/UserEducationCenter';
import SystemMonitoring from '@/components/attack-simulations/SystemMonitoring';

import { useTelemetrySocket } from '@/components/live-system/lib/socket';

const classifierModels = [
  { id: "Brute_Force", name: "Brute Force", displayName: "Brute Force", icon: <Terminal size={20} /> },
  { id: "DDoS", name: "DDoS", displayName: "DDoS Attack", icon: <Shield size={20} /> },
  { id: "DoS", name: "DoS", displayName: "DoS Attack", icon: <AlertTriangle size={20} /> },
  { id: "Port_Scan", name: "Port Scan", displayName: "Port Scanning", icon: <Network size={20} /> },
  { id: "Web_Attack", name: "Web Attack", displayName: "Web Attack", icon: <Globe size={20} /> }
];

// Helper function to convert ML predictions to AlertData format
const convertPredictionToAlert = (prediction: MLPrediction, predictionType: string, timestamp: string): AlertData => {
  const getSeverity = (confidence: number, anomalyDetected: boolean): string => {
    if (anomalyDetected && confidence > 0.8) return "Critical";
    if (anomalyDetected && confidence > 0.6) return "High";
    if (anomalyDetected && confidence > 0.4) return "Medium";
    return "Low";
  };

  const getDescription = (prediction: MLPrediction): string => {
    if (prediction.predicted_label === "BENIGN") {
      return "Normal traffic pattern detected";
    }
    return `${prediction.predicted_label} attack detected with ${(prediction.confidence * 100).toFixed(1)}% confidence`;
  };

  return {
    id: `pred-${predictionType}-${prediction.index}-${Date.now()}`,
    timestamp: timestamp,
    severity: getSeverity(prediction.confidence, prediction.anomaly_detected),
    source_ip: `192.168.1.${100 + (prediction.index % 50)}`, // Generate mock IP based on index
    destination_ip: `10.0.0.${50 + (prediction.index % 200)}`, // Generate mock destination IP
    destination_port: prediction.predicted_label === "Web Attack" ? 80 : 
                     prediction.predicted_label === "Port Scan" ? 22 : 
                     prediction.predicted_label === "DDoS" ? 443 : 0,
    protocol: prediction.predicted_label === "Web Attack" ? "HTTP" : 
              prediction.predicted_label === "Port Scan" ? "TCP" : 
              prediction.predicted_label === "DDoS" ? "TCP" : "TCP",
    description: getDescription(prediction),
    threat_type: prediction.predicted_label,
    rule_id: `ML-${predictionType}-${prediction.index}`,
    metadata: {
      prediction_index: prediction.index,
      ml_model: predictionType,
      class_probabilities: prediction.class_probabilities
    },
    anomaly_score: prediction.confidence,
    threshold: 0.5,
    is_anomaly: prediction.anomaly_detected ? 1 : 0,
    confidence: prediction.confidence,
    predicted_label: prediction.predicted_label,
    true_label: prediction.true_label,
    class_probabilities: prediction.class_probabilities
  };
};

const AttackSimulations = () => {
  const { getSocket } = useTelemetrySocket();
  const { theme } = useTheme();
  const [activeTab, setActiveTab] = useState("attack-simulations");
  const socket: Socket | null = getSocket();
  const [mlPredictionsData, setMlPredictionsData] = useState<AllMLPredictions | null>(null);

  // State for alerts - now populated from ML predictions
  const [alerts, setAlerts] = useState<Record<string, AlertData[]>>({
    Brute_Force: [],
    DDoS: [],
    DoS: [],
    Port_Scan: [],
    Web_Attack: [],
    SQL_Injection: [],
    Anomaly: [],
    Firewall: []
  });

  // Function to process ML predictions and convert to alerts
  const processPredictionsToAlerts = (predictions: AllMLPredictions) => {
    const newAlerts: Record<string, AlertData[]> = {
      Brute_Force: [],
      DDoS: [],
      DoS: [],
      Port_Scan: [],
      Web_Attack: [],
      SQL_Injection: [],
      Anomaly: [],
      Firewall: alerts.Firewall || [] // Keep existing firewall alerts
    };

    console.log("Processing predictions:", predictions);

    // Map prediction type names to our attack type IDs
    const predictionTypeMapping: { [key: string]: string } = {
      'bruteforce': 'Brute_Force',
      'ddos': 'DDoS', 
      'dos': 'DoS',
      'portscan': 'Port_Scan',
      'webattack': 'Web_Attack'
    };

    // Process each prediction type and assign to corresponding attack type
    Object.entries(predictions).forEach(([predictionType, payload]) => {
      if ('predictions' in payload && payload.predictions) {
        const attackTypeId = predictionTypeMapping[predictionType.toLowerCase()];
        
        if (attackTypeId) {
          console.log(`Processing ${predictionType} -> ${attackTypeId} with ${payload.predictions.length} predictions`);
          
          payload.predictions.forEach(prediction => {
            // Skip BENIGN predictions for attack cards unless they're anomalies
            if (prediction.predicted_label === "BENIGN" && !prediction.anomaly_detected) {
              return;
            }

            const alert = convertPredictionToAlert(prediction, predictionType, payload.last_modified);
            newAlerts[attackTypeId].push(alert);
            
            console.log(`Added ${prediction.predicted_label} prediction to ${attackTypeId}`);
            
            // Add to anomaly alerts if anomaly is detected
            if (prediction.anomaly_detected) {
              newAlerts.Anomaly.push({
                ...alert,
                id: `${alert.id}-anomaly`, // Ensure unique ID
                threat_type: "Anomaly",
                description: `Anomaly detected: ${prediction.predicted_label} pattern with ${(prediction.confidence * 100).toFixed(1)}% confidence`
              });
            }
          });
        }
      }
    });

    // Sort alerts by confidence (highest first) and limit to 20 each
    Object.keys(newAlerts).forEach(key => {
      if (key !== 'Firewall') { // Don't sort firewall alerts
        newAlerts[key] = newAlerts[key]
          .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
          .slice(0, 20);
      }
    });

    console.log("Final alerts distribution:", Object.keys(newAlerts).map(key => ({ 
      type: key, 
      count: newAlerts[key].length 
    })));

    setAlerts(newAlerts);
  };

  // Helper function to map prediction labels to alert types
  const mapPredictionLabelToAttackType = (predictedLabel: string): string | null => {
    const labelMap: { [key: string]: string } = {
      "Brute Force": "Brute_Force",
      "DDoS": "DDoS",
      "DoS": "DoS", 
      "Port Scan": "Port_Scan",
      "Web Attack": "Web_Attack",
      "SQL Injection": "SQL_Injection"
    };
    
    return labelMap[predictedLabel] || null;
  };

  // Helper function to map prediction labels to alert types
  const mapPredictionTypeToAlertType = (predictedLabel: string): string | null => {
    switch (predictedLabel) {
      case "Brute Force":
        return "Brute_Force";
      case "DDoS":
        return "DDoS";
      case "DoS":
        return "DoS";
      case "Port Scan":
        return "Port_Scan";
      case "Web Attack":
        return "Web_Attack";
      case "BENIGN":
        return null; // Don't create alerts for benign traffic
      default:
        return null;
    }
  };

  useEffect(() => {
    if (socket) {
      // Keep only firewall socket listener as it's not part of ML predictions
      const firewallEventName = "firewall_blocked";
      const firewallHandler = (data: FirewallAlertData) => {
        console.log(`Received ${firewallEventName}:`, data);
        const mappedAlert: AlertData = {
          id: data.id,
          timestamp: data.timestamp,
          severity: "High",
          source_ip: data.ip_address,
          destination_ip: data.packet_info?.dst_ip || "N/A",
          destination_port: 0,
          protocol: data.packet_info?.protocol || "N/A",
          description: data.reason,
          threat_type: "Firewall Block",
          rule_id: data.source_component,
          metadata: {
            duration_seconds: data.duration_seconds,
            action_taken: data.action_taken,
            original_packet_info: data.packet_info,
            source_component: data.source_component,
          }
        };
        setAlerts(prevAlerts => ({
          ...prevAlerts,
          Firewall: [mappedAlert, ...(prevAlerts.Firewall || [])].slice(0, 20)
        }));
      };
      socket.on(firewallEventName, firewallHandler);

      return () => {
        socket.off(firewallEventName, firewallHandler);
      };
    }
  }, [socket]);

  const fetchMlPredictions = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/models/predictions');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data: AllMLPredictions = await response.json();
      setMlPredictionsData(data);
      console.log("PREDICTIONS ZOSE: ", data)

      // Process predictions to create alerts
      processPredictionsToAlerts(data);

      // Dispatch event to send predictions to Header notifications
      if (data) {
        const mlNotificationsForHeader: any[] = [];
        Object.entries(data).forEach(([type, payload]) => {
          if ('predictions' in payload && payload.predictions.length > 0) {
            // Count anomalies and high-confidence predictions
            const anomalies = payload.predictions.filter(p => p.anomaly_detected);
            const highConfidencePredictions = payload.predictions.filter(p => p.confidence > 0.7);
            
            let highestSeverity = "info";
            if (highConfidencePredictions.length > 0) highestSeverity = "critical";
            else if (anomalies.length > 0) highestSeverity = "warning";

            mlNotificationsForHeader.push({
              id: `ml-pred-${type}-${payload.last_modified}`,
              name: `ML: ${type.replace(/_/g, ' ')} Predictions`,
              description: `${payload.predictions.length} predictions (${anomalies.length} anomalies, ${highConfidencePredictions.length} high confidence)`,
              severity: highestSeverity,
              timestamp: payload.last_modified,
              type: 'ml_prediction',
              read: false,
            });
          }
        });

        if (mlNotificationsForHeader.length > 0) {
          const event = new CustomEvent('mlPredictionNotification', { detail: mlNotificationsForHeader });
          window.dispatchEvent(event);
        }
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'An unknown error occurred while fetching ML predictions';
      console.error("Failed to fetch ML predictions:", e);
    }
  };

  // Fetch predictions on component mount and set up polling
  useEffect(() => {
    fetchMlPredictions();
    
    // Set up polling every 30 seconds to refresh predictions
    const interval = setInterval(fetchMlPredictions, 30000);
    
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="container mx-auto py-8 animate-fade-in">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-isimbi-purple mb-2">
          Attacks Playground
        </h1>
        <p className="text-muted-foreground">
          Interactive security testing environment for simulating various cyber attacks and monitoring system responses
        </p>
        <Separator className="my-4" />
      </header>
      
      <Tabs defaultValue="attack-simulations" className="w-full" onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-8 mb-8">
          <TabsTrigger value="attack-simulations" className="gap-2">
            <Shield size={16} />
            <span className="hidden md:inline">Attacks</span>
          </TabsTrigger>
          <TabsTrigger value="network">
            <Network size={16} />
            <span className="hidden md:inline">Network</span>
          </TabsTrigger>
          {/* <TabsTrigger value="system">
            <Monitor size={16} />
            <span className="hidden md:inline">System</span>
          </TabsTrigger> */}
        </TabsList>
        
       <TabsContent value="attack-simulations" className="space-y-6">
          {Object.entries(mlPredictionsData || {}).map(([key, payload], idx) => {
  // Map backend keys to display names and icons
  const mapping: Record<string, { displayName: string, icon: JSX.Element, alertKey: string }> = {
    bruteforce: { displayName: "Brute Force", icon: <Terminal size={20} />, alertKey: "Brute_Force" },
    ddos: { displayName: "DDoS Attack", icon: <Shield size={20} />, alertKey: "DDoS" },
    dos: { displayName: "DoS Attack", icon: <AlertTriangle size={20} />, alertKey: "DoS" },
    portscan: { displayName: "Port Scanning", icon: <Network size={20} />, alertKey: "Port_Scan" },
    webattack: { displayName: "Web Attack", icon: <Globe size={20} />, alertKey: "Web_Attack" }
  };

  const meta = mapping[key.toLowerCase()];
  if (!meta || !('predictions' in payload)) return null;

  return (
    <GenericAttackCard
      key={`${key}-${idx}`}
      attackName={meta.displayName}
      alerts={alerts[meta.alertKey] || []}
      modelPredictions={payload.predictions}
      icon={meta.icon}
    />
  );
})}

      </TabsContent>

        <TabsContent value="network">
          <NetworkTrafficVisualizer />
        </TabsContent>
        
        <TabsContent value="system">
          <SystemMonitoring anomalyAlerts={alerts.Anomaly || []} firewallAlerts={alerts.Firewall || []} />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AttackSimulations;