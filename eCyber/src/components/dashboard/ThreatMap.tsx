import React, { useEffect, useRef, useMemo } from 'react';
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';
import { Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert } from '@/hooks/usePacketSnifferSocket'; // Import Alert type

// Define interfaces for props and state
interface ThreatLocation {
  id: string;
  latitude?: number;
  longitude?: number;
  country?: string; // Or source_ip
  severity: 'critical' | 'warning' | 'info' | 'blocked' | string;
  count: number;
  name?: string;
}

interface ThreatActivityDataPoint {
  time: string;
  threats: number;
}

interface ThreatMapProps {
  className?: string;
  threatsData?: Alert[];
}

// Simulated data for canvas map points (as lat/long not in alerts)
// const mockCanvasLocations: ThreatLocation[] = [
//   { id: "canvas-1", latitude: 40.7128, longitude: -74.0060, name: "New York", severity: "critical", count: 5 },
//   { id: "canvas-2", latitude: 51.5074, longitude: -0.1278, name: "London", severity: "warning", count: 3 },
//   { id: "canvas-3", latitude: 35.6762, longitude: 139.6503, name: "Tokyo", severity: "info", count: 2 },
// ];

// --- Helper: Basic GeoIP from IP (Illustrative - replace with actual library or backend service) ---
// This is a very basic placeholder. In a real app, use a library or backend service.
const getGeoFromIp = (ip: string): { latitude?: number; longitude?: number; country?: string } => {
  if (!ip) return {};
  // Simple hash function to generate pseudo-random but consistent coordinates for IPs
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    const char = ip.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0; // Convert to 32bit integer
  }

  // Generate somewhat plausible global coordinates
  // This is NOT real GeoIP, just for visualization diversity
  const pseudoLat = (hash % 180) - 90; // -90 to 90
  const pseudoLng = (hash % 360) - 180; // -180 to 180
  
  // Very basic country association (example)
  const firstOctet = parseInt(ip.split('.')[0]);
  let country = "Unknown";
  if (firstOctet >= 1 && firstOctet <= 126) country = "USA";
  else if (firstOctet >= 128 && firstOctet <= 191) country = "Europe";
  else if (firstOctet >= 192 && firstOctet <= 223) country = "Asia";


  // For known IPs, return more specific mock data
  if (ip.startsWith("203.0")) return { latitude: 40.7128, longitude: -74.0060, country: "USA (NY)" };
  if (ip.startsWith("198.51")) return { latitude: 51.5074, longitude: -0.1278, country: "UK (London)" };
  if (ip.startsWith("192.0.2")) return { latitude: 35.6762, longitude: 139.6503, country: "Japan (Tokyo)" };
  if (ip.startsWith("8.8.8")) return { latitude: 37.3861, longitude: -122.0839, country: "USA (Google)" };


  return { latitude: pseudoLat, longitude: pseudoLng, country: country };
};


const ThreatMap: React.FC<ThreatMapProps> = ({ className, threatsData }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Process data for canvas map points from actual threatsData
  const canvasMapLocations = useMemo(() => {
    if (!threatsData || threatsData.length === 0) {
      // Return a few default points or an empty array if no threats
      return [
        { id: "placeholder-1", latitude: 30, longitude: -20, name: "Atlantic Region", severity: "info", count: 0 },
        { id: "placeholder-2", latitude: 20, longitude: 100, name: "Asia-Pacific Region", severity: "info", count: 0 },
      ];
    }

    const locationCounts: { [key: string]: ThreatLocation } = {};
    threatsData.forEach((threat, index) => {
      const geo = getGeoFromIp(threat.source_ip || `unknown-${index}`); // Use index for unique key if IP is missing
      const key = threat.source_ip || geo.country || `loc-${index}`;

      if (!locationCounts[key]) {
        locationCounts[key] = {
          id: key,
          latitude: geo.latitude,
          longitude: geo.longitude,
          name: geo.country || threat.source_ip || "Unknown Source",
          severity: threat.severity?.toLowerCase() || 'info',
          count: 0,
        };
      }
      locationCounts[key].count++;
      // Potentially update severity if a new threat for this location is higher
      const severityOrder = { critical: 3, warning: 2, blocked: 1, info: 0 };
      const currentSeverity = locationCounts[key].severity.toLowerCase();
      const newSeverity = threat.severity?.toLowerCase() || 'info';
      if (severityOrder[newSeverity] > severityOrder[currentSeverity]) {
        locationCounts[key].severity = newSeverity;
      }
    });
    return Object.values(locationCounts).filter(loc => loc.latitude && loc.longitude); // Only use locations with coordinates
  }, [threatsData]);


  // Process data for Threat Activity Chart using useMemo
  const chartData = useMemo(() => {
    if (!threatsData) return [];

    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const hourlyThreats: { [key: string]: number } = {};

    // Initialize hourly buckets
    for (let i = 0; i < 24; i++) {
      const d = new Date(twentyFourHoursAgo.getTime() + i * 60 * 60 * 1000);
      hourlyThreats[`${d.getHours()}:00`] = 0;
    }

    // Count threats per hour
    threatsData.forEach(threat => {
      const threatTime = new Date(threat.timestamp);
      if (threatTime >= twentyFourHoursAgo) {
        const hourKey = `${threatTime.getHours()}:00`;
        if (hourlyThreats[hourKey] !== undefined) {
          hourlyThreats[hourKey]++;
        }
      }
    });

    return Object.entries(hourlyThreats)
      .map(([time, threats]) => ({ time, threats }))
      .sort((a, b) => parseInt(a.time.split(':')[0]) - parseInt(b.time.split(':')[0]));
  }, [threatsData]);

  // Process data for Top Threat Locations using useMemo
  const processedThreatLocations = useMemo(() => {
    if (!threatsData) return [];

    const locationsMap: { [key: string]: ThreatLocation } = {};
    const severityOrder = { critical: 3, warning: 2, blocked: 1, info: 0 };

    threatsData.forEach(threat => {
      const key = threat.source_ip || 'Unknown';
      if (!locationsMap[key]) {
        locationsMap[key] = {
          id: key,
          name: key,
          country: key,
          count: 0,
          severity: threat.severity?.toLowerCase() || 'info',
        };
      }
      locationsMap[key].count++;
      
      const currentSeverity = locationsMap[key].severity.toLowerCase();
      const newSeverity = threat.severity?.toLowerCase() || 'info';
      if (severityOrder[newSeverity] > severityOrder[currentSeverity]) {
        locationsMap[key].severity = newSeverity;
      }
    });

    return Object.values(locationsMap)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [threatsData]);

  // Redraw canvas when component mounts or canvasMapLocations changes
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
   
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
   
    // Set canvas dimensions
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
   
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
   
    // Draw world map outline (simplified for this example)
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.beginPath();
    ctx.arc(canvas.width / 2, canvas.height / 2, canvas.height / 3, 0, Math.PI * 2);
    ctx.stroke();
   
    // Draw grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    for (let i = 0; i < 360; i += 20) {
      const angle = (i * Math.PI) / 180;
      const radius = canvas.height / 3;
     
      ctx.beginPath();
      ctx.moveTo(canvas.width / 2, canvas.height / 2);
      ctx.lineTo(
        canvas.width / 2 + Math.cos(angle) * radius,
        canvas.height / 2 + Math.sin(angle) * radius
      );
      ctx.stroke();
    }
   
    // Draw animated pulse circles using MOCK canvas locations
    const drawPulses = () => {
      if (!canvasRef.current) return;
      const currentCtx = canvasRef.current.getContext('2d');
      if (!currentCtx) return;

      currentCtx.clearRect(0, 0, canvasRef.current.width, canvasRef.current.height);
      // Redraw map outline and grid
      currentCtx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
      currentCtx.beginPath();
      currentCtx.arc(canvasRef.current.width / 2, canvasRef.current.height / 2, canvasRef.current.height / 3, 0, Math.PI * 2);
      currentCtx.stroke();
      currentCtx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      for (let i = 0; i < 360; i += 20) {
        const angle = (i * Math.PI) / 180;
        const radius = canvasRef.current.height / 3;
        currentCtx.beginPath();
        currentCtx.moveTo(canvasRef.current.width / 2, canvasRef.current.height / 2);
        currentCtx.lineTo(
          canvasRef.current.width / 2 + Math.cos(angle) * radius,
          canvasRef.current.height / 2 + Math.sin(angle) * radius
        );
        currentCtx.stroke();
      }

      // Use processed canvasMapLocations from threatsData
      canvasMapLocations.forEach((threat) => {
        if (!threat.latitude || !threat.longitude || !canvasRef.current) return;
        
        // Adjust scaling factor as needed for better map projection
        const mapRadiusX = canvasRef.current.width / 2.5; // Adjust for desired spread
        const mapRadiusY = canvasRef.current.height / 2.5;

        const x = canvasRef.current.width / 2 + (threat.longitude / 180) * mapRadiusX;
        const y = canvasRef.current.height / 2 - (threat.latitude / 90) * (canvasRef.current.height / 4);
       
        let color = 'rgba(14, 165, 233, 0.8)'; // info blue
        if (threat.severity === 'warning') color = 'rgba(245, 158, 11, 0.8)';
        if (threat.severity === 'critical') color = 'rgba(239, 68, 68, 0.8)';
        if (threat.severity === 'blocked') color = 'rgba(16, 185, 129, 0.8)';
       
        currentCtx.fillStyle = color;
        currentCtx.beginPath();
        currentCtx.arc(x, y, 4, 0, Math.PI * 2);
        currentCtx.fill();
       
        const time = Date.now() / 1000;
        const idSegment = parseInt(threat.id.split('-')[1]) || 0;
        const pulseSize = 8 + (Math.sin(time * 2 + idSegment) + 1) * 8;
       
        currentCtx.strokeStyle = color.replace('0.8', '0.3');
        currentCtx.beginPath();
        currentCtx.arc(x, y, pulseSize, 0, Math.PI * 2);
        currentCtx.stroke();
      });
    };
    
    let animationFrameId: number;
    
    const animate = () => {
      drawPulses();
      animationFrameId = requestAnimationFrame(animate);
    };
    animate(); // Start animation loop
    
    return () => cancelAnimationFrame(animationFrameId);
  }, [canvasMapLocations]); // Redraw if canvasMapLocations changes

  return (
    <Card className={`${className} shadow-lg border-border relative overflow-hidden`}>
      <CardHeader className="flex flex-row items-center justify-between pb-2 z-10 relative bg-card/50 backdrop-blur-sm">
        <CardTitle className="text-sm font-medium">Global Threat Map</CardTitle>
        <Button variant="ghost" size="sm" className="text-muted-foreground">
          <Settings size={16} />
        </Button>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Threat map visualization */}
          <div className="glass-card p-0 lg:col-span-2 relative rounded-lg overflow-hidden">
            <div className="aspect-[16/9] relative">
              <canvas
                ref={canvasRef}
                className="absolute inset-0 w-full h-full"
              ></canvas>
            </div>
            <div className="absolute bottom-2 left-2 right-2 p-2 bg-card/30 backdrop-blur-sm rounded flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex items-center space-x-2 sm:space-x-4">
                <div className="flex items-center">
                  <span className="inline-block w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-blue-500 mr-1"></span>
                  <span>Info</span>
                </div>
                <div className="flex items-center">
                  <span className="inline-block w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-amber-500 mr-1"></span>
                  <span>Warning</span>
                </div>
                <div className="flex items-center">
                  <span className="inline-block w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-red-500 mr-1"></span>
                  <span>Critical</span>
                </div>
                <div className="flex items-center">
                  <span className="inline-block w-2 h-2 sm:w-3 sm:h-3 rounded-full bg-green-500 mr-1"></span>
                  <span>Blocked</span>
                </div>
              </div>
              <span>Map Illustrative</span>
            </div>
          </div>
         
          {/* Threat metrics */}
          <div className="space-y-4">
            <div className="glass-card p-4">
              <h3 className="text-xs font-medium text-muted-foreground mb-2">Threat Activity (Last 24h)</h3>
              <ResponsiveContainer width="100%" height={120}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
                    tickLine={false}
                    axisLine={false}
                    interval="preserveStartEnd"
                    minTickGap={30}
                  />
                  <YAxis
                    hide={true}
                    domain={['auto', 'auto']}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'hsl(var(--background-tooltip))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: 'var(--radius)',
                      color: 'hsl(var(--foreground-tooltip))'
                    }}
                    itemStyle={{ color: 'hsl(var(--foreground-tooltip))' }}
                    formatter={(value: number) => [`${value} threats`, 'Detected']}
                    labelFormatter={(label: string) => `Time: ${label}`}
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="hsl(var(--destructive))"
                    fill="url(#threatGradient)"
                    strokeWidth={2}
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
           
            <div className="glass-card p-4">
              <h3 className="text-xs font-medium text-muted-foreground mb-3">Top Threat Sources (by IP)</h3>
              {processedThreatLocations.length > 0 ? (
                <ul className="space-y-3">
                  {processedThreatLocations.map((location) => (
                    <li key={location.id} className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div
                          className={`w-2 h-2 rounded-full mr-2 ${
                            location.severity === 'critical' ? 'bg-red-500' :
                            location.severity === 'warning' ? 'bg-amber-500' :
                            location.severity === 'blocked' ? 'bg-green-500' :
                            'bg-blue-500'
                          }`}
                        ></div>
                        <span className="text-sm truncate" title={location.name}>{location.name}</span>
                      </div>
                      <span className="text-sm font-medium data-highlight">
                        {location.count}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">No significant threat sources detected.</p>
              )}
              <div className="mt-3 pt-3 border-t border-border">
                <Button variant="ghost" size="sm" className="w-full text-xs text-muted-foreground hover:text-primary" disabled={processedThreatLocations.length === 0}>
                  View All Sources
                </Button>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatMap;