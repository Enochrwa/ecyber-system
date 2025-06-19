import React, { useMemo, useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Globe, 
  Activity, 
  Shield, 
  AlertTriangle, 
  TrendingUp,
  MapPin,
  Zap,
  Eye,
  Filter,
  RotateCcw
} from 'lucide-react';
import { useSelector } from 'react-redux';
import { RootState } from '@/app/store';
import { cn } from '@/lib/utils';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area,
  ScatterChart,
  Scatter,
  PieChart,
  Pie,
  Cell,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';

interface ThreatEvent {
  id: string;
  type: 'malware' | 'phishing' | 'intrusion' | 'anomaly' | 'ddos';
  severity: 'critical' | 'high' | 'medium' | 'low';
  sourceIP: string;
  targetIP: string;
  country: string;
  timestamp: string;
  confidence: number;
  blocked: boolean;
  coordinates?: { lat: number; lng: number };
}

interface NetworkFlow {
  source: string;
  target: string;
  bytes: number;
  packets: number;
  protocol: string;
  timestamp: string;
  suspicious: boolean;
}

const threatTypeConfig = {
  malware: { color: '#ef4444', label: 'Malware', icon: Shield },
  phishing: { color: '#f97316', label: 'Phishing', icon: Globe },
  intrusion: { color: '#dc2626', label: 'Intrusion', icon: AlertTriangle },
  anomaly: { color: '#eab308', label: 'Anomaly', icon: Activity },
  ddos: { color: '#7c3aed', label: 'DDoS', icon: Zap }
};

const severityColors = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a'
};

export const RealTimeThreatVisualization: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'timeline' | 'geographic' | 'network' | 'analytics'>('timeline');
  const [timeRange, setTimeRange] = useState<'5m' | '1h' | '6h' | '24h'>('1h');
  const [selectedThreatType, setSelectedThreatType] = useState<string>('all');
  const [isRealTime, setIsRealTime] = useState(true);

  // Mock data - in real implementation, this would come from Redux store
  const [threatEvents] = useState<ThreatEvent[]>([
    {
      id: '1',
      type: 'malware',
      severity: 'critical',
      sourceIP: '203.0.113.45',
      targetIP: '192.168.1.100',
      country: 'Unknown',
      timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
      confidence: 0.95,
      blocked: true,
      coordinates: { lat: 40.7128, lng: -74.0060 }
    },
    {
      id: '2',
      type: 'phishing',
      severity: 'high',
      sourceIP: '198.51.100.23',
      targetIP: '192.168.1.105',
      country: 'Russia',
      timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
      confidence: 0.87,
      blocked: true,
      coordinates: { lat: 55.7558, lng: 37.6176 }
    },
    {
      id: '3',
      type: 'intrusion',
      severity: 'high',
      sourceIP: '192.0.2.67',
      targetIP: '192.168.1.110',
      country: 'China',
      timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
      confidence: 0.92,
      blocked: false,
      coordinates: { lat: 39.9042, lng: 116.4074 }
    }
  ]);

  // Generate timeline data
  const timelineData = useMemo(() => {
    const now = new Date();
    const intervals = timeRange === '5m' ? 5 : timeRange === '1h' ? 12 : timeRange === '6h' ? 24 : 48;
    const intervalMs = timeRange === '5m' ? 60000 : timeRange === '1h' ? 300000 : timeRange === '6h' ? 900000 : 1800000;
    
    return Array.from({ length: intervals }, (_, i) => {
      const time = new Date(now.getTime() - (intervals - 1 - i) * intervalMs);
      const threats = Math.floor(Math.random() * 10);
      const blocked = Math.floor(threats * 0.8);
      
      return {
        time: time.toLocaleTimeString('en-US', { 
          hour: '2-digit', 
          minute: '2-digit',
          ...(timeRange === '24h' && { hour12: false })
        }),
        threats,
        blocked,
        allowed: threats - blocked,
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 4),
        medium: Math.floor(Math.random() * 5),
        low: Math.floor(Math.random() * 3)
      };
    });
  }, [timeRange]);

  // Generate threat distribution data
  const threatDistribution = useMemo(() => {
    return Object.entries(threatTypeConfig).map(([type, config]) => ({
      name: config.label,
      value: Math.floor(Math.random() * 50) + 10,
      color: config.color
    }));
  }, []);

  // Generate network flow data
  const networkFlowData = useMemo(() => {
    return Array.from({ length: 20 }, (_, i) => ({
      source: `192.168.1.${100 + i}`,
      target: `10.0.0.${50 + i}`,
      bytes: Math.floor(Math.random() * 10000) + 1000,
      packets: Math.floor(Math.random() * 100) + 10,
      protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
      timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      suspicious: Math.random() > 0.7
    }));
  }, []);

  // Generate geographic threat data
  const geographicData = useMemo(() => {
    const countries = ['USA', 'Russia', 'China', 'Germany', 'Brazil', 'India', 'Japan', 'UK'];
    return countries.map(country => ({
      country,
      threats: Math.floor(Math.random() * 100) + 10,
      blocked: Math.floor(Math.random() * 80) + 5,
      coordinates: { 
        lat: Math.random() * 180 - 90, 
        lng: Math.random() * 360 - 180 
      }
    }));
  }, []);

  // Generate threat analytics data
  const analyticsData = useMemo(() => {
    return [
      { metric: 'Detection Rate', value: 94, max: 100 },
      { metric: 'Response Time', value: 87, max: 100 },
      { metric: 'False Positives', value: 12, max: 100 },
      { metric: 'Coverage', value: 98, max: 100 },
      { metric: 'Accuracy', value: 91, max: 100 },
      { metric: 'Efficiency', value: 89, max: 100 }
    ];
  }, []);

  const ThreatTimeline: React.FC = () => (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Threat Activity Timeline</CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant={isRealTime ? "default" : "secondary"}>
              {isRealTime ? 'Live' : 'Paused'}
            </Badge>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsRealTime(!isRealTime)}
            >
              {isRealTime ? 'Pause' : 'Resume'}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={timelineData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Area 
              type="monotone" 
              dataKey="critical" 
              stackId="1" 
              stroke={severityColors.critical} 
              fill={severityColors.critical}
              fillOpacity={0.8}
            />
            <Area 
              type="monotone" 
              dataKey="high" 
              stackId="1" 
              stroke={severityColors.high} 
              fill={severityColors.high}
              fillOpacity={0.8}
            />
            <Area 
              type="monotone" 
              dataKey="medium" 
              stackId="1" 
              stroke={severityColors.medium} 
              fill={severityColors.medium}
              fillOpacity={0.8}
            />
            <Area 
              type="monotone" 
              dataKey="low" 
              stackId="1" 
              stroke={severityColors.low} 
              fill={severityColors.low}
              fillOpacity={0.8}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );

  const GeographicView: React.FC = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Threat Sources by Country</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {geographicData.slice(0, 8).map((item, index) => (
              <div key={item.country} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-5 bg-gray-200 rounded flex items-center justify-center text-xs font-medium">
                    {item.country.slice(0, 2)}
                  </div>
                  <span className="text-sm font-medium">{item.country}</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-sm font-medium">{item.threats}</div>
                    <div className="text-xs text-muted-foreground">
                      {item.blocked} blocked
                    </div>
                  </div>
                  <div className="w-16 bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-red-500 h-2 rounded-full" 
                      style={{ width: `${(item.threats / Math.max(...geographicData.map(d => d.threats))) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Threat Type Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={threatDistribution}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {threatDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );

  const NetworkFlowView: React.FC = () => (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Network Flow Analysis</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={400}>
          <ScatterChart data={networkFlowData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="bytes" 
              name="Bytes" 
              type="number"
              domain={['dataMin', 'dataMax']}
            />
            <YAxis 
              dataKey="packets" 
              name="Packets" 
              type="number"
              domain={['dataMin', 'dataMax']}
            />
            <Tooltip 
              cursor={{ strokeDasharray: '3 3' }}
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload as NetworkFlow;
                  return (
                    <div className="bg-white p-3 border rounded shadow">
                      <p className="font-medium">{data.source} → {data.target}</p>
                      <p className="text-sm">Protocol: {data.protocol}</p>
                      <p className="text-sm">Bytes: {data.bytes.toLocaleString()}</p>
                      <p className="text-sm">Packets: {data.packets}</p>
                      {data.suspicious && (
                        <Badge variant="destructive" className="mt-1">Suspicious</Badge>
                      )}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Scatter 
              dataKey="packets" 
              fill={(entry: any) => entry.suspicious ? '#ef4444' : '#3b82f6'}
            />
          </ScatterChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );

  const AnalyticsView: React.FC = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Security Metrics Radar</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={analyticsData}>
              <PolarGrid />
              <PolarAngleAxis dataKey="metric" />
              <PolarRadiusAxis angle={90} domain={[0, 100]} />
              <Radar
                name="Performance"
                dataKey="value"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.3}
                strokeWidth={2}
              />
              <Tooltip />
            </RadarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Threat Response Effectiveness</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {analyticsData.map((metric) => (
              <div key={metric.metric}>
                <div className="flex justify-between text-sm mb-1">
                  <span>{metric.metric}</span>
                  <span className="font-medium">{metric.value}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className={cn(
                      "h-2 rounded-full transition-all",
                      metric.value >= 90 ? "bg-green-500" :
                      metric.value >= 70 ? "bg-yellow-500" : "bg-red-500"
                    )}
                    style={{ width: `${metric.value}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-600" />
            <CardTitle className="text-lg">Real-Time Threat Visualization</CardTitle>
          </div>
          
          <div className="flex items-center gap-2">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value as any)}
              className="text-sm border rounded px-2 py-1"
            >
              <option value="5m">Last 5 Minutes</option>
              <option value="1h">Last Hour</option>
              <option value="6h">Last 6 Hours</option>
              <option value="24h">Last 24 Hours</option>
            </select>
            
            <select
              value={selectedThreatType}
              onChange={(e) => setSelectedThreatType(e.target.value)}
              className="text-sm border rounded px-2 py-1"
            >
              <option value="all">All Threats</option>
              {Object.entries(threatTypeConfig).map(([type, config]) => (
                <option key={type} value={type}>{config.label}</option>
              ))}
            </select>
            
            <Button variant="ghost" size="sm">
              <RotateCcw className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as any)}>
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="geographic">Geographic</TabsTrigger>
            <TabsTrigger value="network">Network Flow</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
          </TabsList>

          <TabsContent value="timeline" className="space-y-4">
            <ThreatTimeline />
            
            {/* Recent Events */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Recent Threat Events</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {threatEvents.slice(0, 5).map((event) => {
                    const typeConfig = threatTypeConfig[event.type];
                    const TypeIcon = typeConfig.icon;
                    
                    return (
                      <div key={event.id} className="flex items-center gap-3 p-3 border rounded-lg">
                        <TypeIcon className="w-5 h-5" style={{ color: typeConfig.color }} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-sm">{typeConfig.label}</span>
                            <Badge 
                              variant="outline" 
                              className="text-xs"
                              style={{ color: severityColors[event.severity] }}
                            >
                              {event.severity}
                            </Badge>
                            {event.blocked && (
                              <Badge variant="destructive" className="text-xs">Blocked</Badge>
                            )}
                          </div>
                          <div className="text-sm text-muted-foreground">
                            {event.sourceIP} → {event.targetIP} • {event.country}
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-medium">
                            {(event.confidence * 100).toFixed(0)}%
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="geographic">
            <GeographicView />
          </TabsContent>

          <TabsContent value="network">
            <NetworkFlowView />
          </TabsContent>

          <TabsContent value="analytics">
            <AnalyticsView />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default RealTimeThreatVisualization;

