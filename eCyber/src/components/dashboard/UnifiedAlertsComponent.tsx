import React, { useMemo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  AlertTriangle, 
  Shield, 
  Globe, 
  Activity, 
  Clock, 
  Filter,
  ChevronDown,
  ChevronUp,
  Eye,
  AlertCircle,
  Info,
  Zap
} from 'lucide-react';
import { useSelector } from 'react-redux';
import { RootState } from '@/app/store';
import { cn } from '@/lib/utils';

interface UnifiedAlert {
  id: string;
  type: 'threat' | 'phishing' | 'firewall' | 'signature' | 'ip_block' | 'network' | 'system';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  timestamp: string;
  source: string;
  metadata?: Record<string, any>;
  actionTaken?: string;
  confidence?: number;
}

const severityConfig = {
  critical: { 
    color: 'bg-red-500', 
    textColor: 'text-red-700', 
    bgColor: 'bg-red-50', 
    icon: AlertTriangle,
    label: 'Critical'
  },
  high: { 
    color: 'bg-orange-500', 
    textColor: 'text-orange-700', 
    bgColor: 'bg-orange-50', 
    icon: AlertCircle,
    label: 'High'
  },
  medium: { 
    color: 'bg-yellow-500', 
    textColor: 'text-yellow-700', 
    bgColor: 'bg-yellow-50', 
    icon: Info,
    label: 'Medium'
  },
  low: { 
    color: 'bg-blue-500', 
    textColor: 'text-blue-700', 
    bgColor: 'bg-blue-50', 
    icon: Info,
    label: 'Low'
  },
  info: { 
    color: 'bg-gray-500', 
    textColor: 'text-gray-700', 
    bgColor: 'bg-gray-50', 
    icon: Info,
    label: 'Info'
  }
};

const typeConfig = {
  threat: { icon: Shield, label: 'Threat Detection', color: 'text-red-600' },
  phishing: { icon: Globe, label: 'Phishing', color: 'text-orange-600' },
  firewall: { icon: Shield, label: 'Firewall', color: 'text-blue-600' },
  signature: { icon: Zap, label: 'Signature Match', color: 'text-purple-600' },
  ip_block: { icon: Shield, label: 'IP Block', color: 'text-red-600' },
  network: { icon: Activity, label: 'Network', color: 'text-green-600' },
  system: { icon: Activity, label: 'System', color: 'text-gray-600' }
};

export const UnifiedAlertsComponent: React.FC = () => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [isExpanded, setIsExpanded] = useState(true);
  const [viewMode, setViewMode] = useState<'compact' | 'detailed'>('compact');

  // Get data from Redux store
  const threatDetections = useSelector((state: RootState) => state.realtimeData?.threatDetectionsData || []);
  const phishingDetections = useSelector((state: RootState) => state.realtimeData?.phishingDetectionsData || []);
  const firewallEvents = useSelector((state: RootState) => state.realtimeData?.firewallEventsData || []);
  const recentAlerts = useSelector((state: RootState) => state.realtimeData?.recentAlerts || []);
  const systemAlerts = useSelector((state: RootState) => state.systemMetrics?.systemAlerts || []);

  // Transform all alerts into unified format
  const unifiedAlerts = useMemo(() => {
    const alerts: UnifiedAlert[] = [];

    // Threat detections
    threatDetections.forEach((threat: any) => {
      alerts.push({
        id: `threat-${threat.id || Date.now()}-${Math.random()}`,
        type: 'threat',
        severity: threat.severity || 'medium',
        title: `Threat Detected: ${threat.threat_type || 'Unknown'}`,
        description: threat.message || threat.description || 'Threat detected in network traffic',
        timestamp: threat.timestamp || new Date().toISOString(),
        source: 'IPS Engine',
        metadata: threat,
        confidence: threat.confidence
      });
    });

    // Phishing detections
    phishingDetections.forEach((phishing: any) => {
      alerts.push({
        id: `phishing-${phishing.id || Date.now()}-${Math.random()}`,
        type: 'phishing',
        severity: phishing.severity || 'high',
        title: `Phishing Attempt Blocked`,
        description: `Malicious URL detected: ${phishing.url || 'Unknown URL'}`,
        timestamp: phishing.timestamp || new Date().toISOString(),
        source: 'Phishing Blocker',
        metadata: phishing,
        confidence: phishing.confidence,
        actionTaken: phishing.blocked ? 'Blocked' : 'Detected'
      });
    });

    // Firewall events
    firewallEvents.forEach((firewall: any) => {
      alerts.push({
        id: `firewall-${firewall.id || Date.now()}-${Math.random()}`,
        type: 'firewall',
        severity: firewall.type === 'block' ? 'medium' : 'low',
        title: `Firewall ${firewall.type === 'block' ? 'Block' : 'Allow'}`,
        description: `${firewall.type === 'block' ? 'Blocked' : 'Allowed'} connection from ${firewall.ip}`,
        timestamp: firewall.timestamp || new Date().toISOString(),
        source: 'Firewall',
        metadata: firewall,
        actionTaken: firewall.type
      });
    });

    // Recent alerts
    recentAlerts.forEach((alert: any) => {
      alerts.push({
        id: `alert-${alert.id || Date.now()}-${Math.random()}`,
        type: 'system',
        severity: alert.severity || 'info',
        title: 'System Alert',
        description: alert.message || 'System alert triggered',
        timestamp: alert.timestamp || new Date().toISOString(),
        source: 'System Monitor',
        metadata: alert
      });
    });

    // Sort by timestamp (newest first)
    return alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [threatDetections, phishingDetections, firewallEvents, recentAlerts, systemAlerts]);

  // Filter alerts
  const filteredAlerts = useMemo(() => {
    return unifiedAlerts.filter(alert => {
      const severityMatch = selectedSeverity === 'all' || alert.severity === selectedSeverity;
      const typeMatch = selectedType === 'all' || alert.type === selectedType;
      return severityMatch && typeMatch;
    });
  }, [unifiedAlerts, selectedSeverity, selectedType]);

  // Get alert counts by severity
  const alertCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    unifiedAlerts.forEach(alert => {
      counts[alert.severity]++;
      counts.total++;
    });
    return counts;
  }, [unifiedAlerts]);

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const AlertItem: React.FC<{ alert: UnifiedAlert }> = ({ alert }) => {
    const severityInfo = severityConfig[alert.severity];
    const typeInfo = typeConfig[alert.type];
    const SeverityIcon = severityInfo.icon;
    const TypeIcon = typeInfo.icon;

    return (
      <div className={cn(
        "p-3 rounded-lg border transition-all hover:shadow-md",
        severityInfo.bgColor
      )}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1">
            <div className="flex items-center gap-2">
              <div className={cn("w-2 h-2 rounded-full", severityInfo.color)} />
              <SeverityIcon className={cn("w-4 h-4", severityInfo.textColor)} />
              <TypeIcon className={cn("w-4 h-4", typeInfo.color)} />
            </div>
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h4 className="font-medium text-sm truncate">{alert.title}</h4>
                <Badge variant="outline" className="text-xs">
                  {typeInfo.label}
                </Badge>
                {alert.confidence && (
                  <Badge variant="secondary" className="text-xs">
                    {Math.round(alert.confidence * 100)}%
                  </Badge>
                )}
              </div>
              
              <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
                {alert.description}
              </p>
              
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatTimestamp(alert.timestamp)}
                </span>
                <span>Source: {alert.source}</span>
                {alert.actionTaken && (
                  <Badge variant="outline" className="text-xs">
                    {alert.actionTaken}
                  </Badge>
                )}
              </div>
            </div>
          </div>
          
          <Badge 
            variant="outline" 
            className={cn("text-xs", severityInfo.textColor)}
          >
            {severityInfo.label}
          </Badge>
        </div>
      </div>
    );
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-600" />
            <CardTitle className="text-lg">Unified Security Alerts</CardTitle>
            <Badge variant="secondary" className="ml-2">
              {alertCounts.total} Total
            </Badge>
          </div>
          
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setViewMode(viewMode === 'compact' ? 'detailed' : 'compact')}
            >
              <Eye className="w-4 h-4 mr-1" />
              {viewMode === 'compact' ? 'Detailed' : 'Compact'}
            </Button>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </Button>
          </div>
        </div>

        {/* Alert counts summary */}
        <div className="flex items-center gap-4 mt-3">
          {Object.entries(alertCounts).filter(([key]) => key !== 'total').map(([severity, count]) => {
            const config = severityConfig[severity as keyof typeof severityConfig];
            return (
              <div key={severity} className="flex items-center gap-1">
                <div className={cn("w-2 h-2 rounded-full", config.color)} />
                <span className="text-sm text-muted-foreground">
                  {config.label}: {count}
                </span>
              </div>
            );
          })}
        </div>
      </CardHeader>

      {isExpanded && (
        <CardContent className="pt-0">
          {/* Filters */}
          <div className="flex items-center gap-4 mb-4 p-3 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4" />
              <span className="text-sm font-medium">Filters:</span>
            </div>
            
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="text-sm border rounded px-2 py-1"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="text-sm border rounded px-2 py-1"
            >
              <option value="all">All Types</option>
              <option value="threat">Threats</option>
              <option value="phishing">Phishing</option>
              <option value="firewall">Firewall</option>
              <option value="signature">Signatures</option>
              <option value="ip_block">IP Blocks</option>
              <option value="network">Network</option>
              <option value="system">System</option>
            </select>
          </div>

          {/* Alerts list */}
          <ScrollArea className="h-96">
            <div className="space-y-3">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => (
                  <AlertItem key={alert.id} alert={alert} />
                ))
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <AlertCircle className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p>No alerts match the current filters</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      )}
    </Card>
  );
};

export default UnifiedAlertsComponent;

