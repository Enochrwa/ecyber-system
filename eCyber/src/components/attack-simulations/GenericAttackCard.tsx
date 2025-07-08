import React, { useMemo } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, Area, AreaChart, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, AlertTriangle, CheckCircle, Target, TrendingUp, Activity, Brain, Zap, Eye, AlertCircle } from "lucide-react";

// Simplified interfaces to match the new data structure
interface ModelPrediction {
  index: number;
  anomaly_detected: boolean;
  true_label: string;
  predicted_label: string;
  confidence: number;
  class_probabilities: {
    [key: string]: number;
  };
}

interface GenericAttackCardProps {
  attackName: string;
  modelPredictions: ModelPrediction[]; // Only predictions needed
  icon?: React.ReactNode;
}

const COLORS = ['#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#6366f1'];

const GenericAttackCard: React.FC<GenericAttackCardProps> = ({ 
  attackName, 
  alerts, 
  modelPredictions = [], 
  icon 
}) => {
  const processedChartData = useMemo(() => {
    if (!alerts || alerts.length === 0) return [];

    const timeWindow = 5000;
    const alertCountsByTime: { [key: string]: number } = {};

    alerts.forEach(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      const windowStart = Math.floor(alertTime / timeWindow) * timeWindow;
      const windowKey = new Date(windowStart).toLocaleTimeString();
      alertCountsByTime[windowKey] = (alertCountsByTime[windowKey] || 0) + 1;
    });

    return Object.entries(alertCountsByTime)
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => new Date(`1/1/1970 ${a.time}`).getTime() - new Date(`1/1/1970 ${b.time}`).getTime());
  }, [alerts]);

  const aggregatedMetrics = useMemo(() => {
    if (!modelPredictions || modelPredictions.length === 0) {
      return {
        totalPredictions: 0,
        overallAccuracy: 0,
        avgConfidence: 0,
        correctPredictions: 0,
        anomalyDetected: 0,
        classDistribution: {},
        recentPredictions: []
      };
    }

    const correctPredictions = modelPredictions?.filter(p => p.true_label === p.predicted_label).length;
    const totalPredictions = modelPredictions.length;
    const accuracy = totalPredictions > 0 ? (correctPredictions / totalPredictions) * 100 : 0;
    const avgConfidence = totalPredictions > 0 ? modelPredictions.reduce((sum, p) => sum + p.confidence, 0) / totalPredictions : 0;
    const anomalyDetected = modelPredictions.filter(p => p.anomaly_detected).length;

    // Class distribution
    const classCount: { [key: string]: number } = {};
    modelPredictions.forEach(p => {
      classCount[p.predicted_label] = (classCount[p.predicted_label] || 0) + 1;
    });

    return {
      totalPredictions,
      overallAccuracy: accuracy,
      avgConfidence,
      correctPredictions,
      anomalyDetected,
      classDistribution: classCount,
      recentPredictions: modelPredictions.slice(-5).reverse() // Show last 5 predictions
    };
  }, [modelPredictions]);

  const classDistributionData = useMemo(() => {
    return Object.entries(aggregatedMetrics.classDistribution)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [aggregatedMetrics.classDistribution]);

  const radarChartData = useMemo(() => {
    const classes = ['BENIGN', 'Brute Force', 'DDoS', 'DoS', 'Port Scan', 'Web Attack'];
    
    return classes.map(className => ({
      class: className,
      value: (aggregatedMetrics.classDistribution[className] || 0) / aggregatedMetrics.totalPredictions * 100 || 0
    }));
  }, [aggregatedMetrics]);

  const confidenceDistributionData = useMemo(() => {
    if (!modelPredictions || modelPredictions.length === 0) return [];

    const confidenceRanges = [
      { name: '0-20%', min: 0, max: 0.2 },
      { name: '20-40%', min: 0.2, max: 0.4 },
      { name: '40-60%', min: 0.4, max: 0.6 },
      { name: '60-80%', min: 0.6, max: 0.8 },
      { name: '80-100%', min: 0.8, max: 1.0 }
    ];

    return confidenceRanges.map(range => ({
      name: range.name,
      count: modelPredictions.filter(p => p.confidence >= range.min && p.confidence < range.max).length,
      percentage: (modelPredictions.filter(p => p.confidence >= range.min && p.confidence < range.max).length / modelPredictions.length) * 100
    }));
  }, [modelPredictions]);

  const getSeverityColor = (confidence: number) => {
    if (confidence >= 0.95) return 'bg-red-500';
    if (confidence >= 0.8) return 'bg-orange-500';
    if (confidence >= 0.6) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const getStatusIcon = (correct: boolean) => {
    return correct ? <CheckCircle className="w-2 h-2 text-green-400" /> : <AlertTriangle className="w-2 h-2 text-red-400" />;
  };

  return (
    <div className="w-full space-y-2 bg-gray-900 text-white p-2 rounded-lg text-xs">
      {/* Ultra Compact Header */}
      <Card className="bg-gradient-to-r from-purple-900 via-blue-900 to-cyan-900 text-white border-gray-700">
        <CardHeader className="pb-1 pt-2 px-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1">
              {icon && <div className="text-white text-sm">{icon}</div>}
              <div>
                <CardTitle className="text-sm font-bold">{attackName}</CardTitle>
                <CardDescription className="text-purple-200 text-xs">
                  ML Detection System
                </CardDescription>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <Badge variant="secondary" className="bg-white/20 text-white border-white/30 text-xs px-1 py-0">
                {aggregatedMetrics.totalPredictions} pred
              </Badge>
              <Badge variant="secondary" className="bg-white/20 text-white border-white/30 text-xs px-1 py-0">
                {aggregatedMetrics.overallAccuracy.toFixed(1)}% acc
              </Badge>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Compact Key Metrics */}
      <div className="grid grid-cols-4 gap-2">
        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-2">
            <div className="flex items-center gap-1 mb-1">
              <Target className="w-3 h-3 text-blue-400" />
              <h3 className="font-semibold text-blue-400 text-xs">Accuracy</h3>
            </div>
            <div className="text-sm font-bold text-blue-300 mb-1">
              {aggregatedMetrics.overallAccuracy.toFixed(1)}%
            </div>
            <Progress value={aggregatedMetrics.overallAccuracy} className="h-1" />
          </CardContent>
        </Card>

        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-2">
            <div className="flex items-center gap-1 mb-1">
              <Shield className="w-3 h-3 text-green-400" />
              <h3 className="font-semibold text-green-400 text-xs">Confidence</h3>
            </div>
            <div className="text-sm font-bold text-green-300 mb-1">
              {(aggregatedMetrics.avgConfidence * 100).toFixed(1)}%
            </div>
            <Progress value={aggregatedMetrics.avgConfidence * 100} className="h-1" />
          </CardContent>
        </Card>

        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-2">
            <div className="flex items-center gap-1 mb-1">
              <Brain className="w-3 h-3 text-purple-400" />
              <h3 className="font-semibold text-purple-400 text-xs">Anomalies</h3>
            </div>
            <div className="text-sm font-bold text-purple-300 mb-1">
              {aggregatedMetrics.anomalyDetected}
            </div>
            <p className="text-xs text-purple-400">Detected</p>
          </CardContent>
        </Card>

        <Card className="bg-gray-800 border-gray-700">
          <CardContent className="p-2">
            <div className="flex items-center gap-1 mb-1">
              <Activity className="w-3 h-3 text-orange-400" />
              <h3 className="font-semibold text-orange-400 text-xs">Classes</h3>
            </div>
            <div className="text-sm font-bold text-orange-300 mb-1">
              {classDistributionData.length}
            </div>
            <p className="text-xs text-orange-400">Types</p>
          </CardContent>
        </Card>
      </div>

      {/* Compact Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
        {/* Compact Alert Timeline */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-1 pt-2 px-3">
            <CardTitle className="flex items-center gap-1 text-xs">
              <TrendingUp className="w-3 h-3 text-purple-400" />
              Alert Timeline
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0 px-3 pb-2">
            <div className="h-24">
              {processedChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={processedChartData}>
                    <defs>
                      <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.1}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" opacity={0.2} stroke="#374151" />
                    <XAxis dataKey="time" tick={{ fontSize: 8, fill: '#9ca3af' }} />
                    <YAxis tick={{ fontSize: 8, fill: '#9ca3af' }} />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: '1px solid #374151',
                        borderRadius: '4px',
                        color: '#fff',
                        fontSize: '10px'
                      }}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="count" 
                      stroke="#8b5cf6" 
                      strokeWidth={1}
                      fill="url(#colorAlerts)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <Eye className="w-4 h-4 mr-1" />
                  <span className="text-xs">No data</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Compact Confidence Distribution */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-1 pt-2 px-3">
            <CardTitle className="flex items-center gap-1 text-xs">
              <Target className="w-3 h-3 text-blue-400" />
              Confidence Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0 px-3 pb-2">
            <div className="h-24">
              {confidenceDistributionData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={confidenceDistributionData}>
                    <CartesianGrid strokeDasharray="3 3" opacity={0.2} stroke="#374151" />
                    <XAxis dataKey="name" tick={{ fontSize: 8, fill: '#9ca3af' }} />
                    <YAxis tick={{ fontSize: 8, fill: '#9ca3af' }} />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: '1px solid #374151',
                        borderRadius: '4px',
                        color: '#fff',
                        fontSize: '10px'
                      }}
                    />
                    <Bar dataKey="count" fill="#06b6d4" name="Count" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <AlertCircle className="w-4 h-4 mr-1" />
                  <span className="text-xs">No data</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Compact Threat Distribution */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-1 pt-2 px-3">
            <CardTitle className="flex items-center gap-1 text-xs">
              <Zap className="w-3 h-3 text-yellow-400" />
              Threat Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0 px-3 pb-2">
            <div className="h-24">
              {classDistributionData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={classDistributionData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={35}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {classDistributionData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: '1px solid #374151',
                        borderRadius: '4px',
                        color: '#fff',
                        fontSize: '10px'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <AlertCircle className="w-4 h-4 mr-1" />
                  <span className="text-xs">No data</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Compact Radar Chart */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-1 pt-2 px-3">
            <CardTitle className="flex items-center gap-1 text-xs">
              <Activity className="w-3 h-3 text-green-400" />
              Class Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0 px-3 pb-2">
            <div className="h-24">
              {radarChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarChartData}>
                    <PolarGrid stroke="#374151" />
                    <PolarAngleAxis dataKey="class" tick={{ fontSize: 8, fill: '#9ca3af' }} />
                    <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fontSize: 8, fill: '#9ca3af' }} />
                    <Radar
                      name="Distribution"
                      dataKey="value"
                      stroke="#8b5cf6"
                      fill="#8b5cf6"
                      fillOpacity={0.1}
                      strokeWidth={1}
                    />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: '1px solid #374151',
                        borderRadius: '4px',
                        color: '#fff',
                        fontSize: '10px'
                      }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <Brain className="w-4 h-4 mr-1" />
                  <span className="text-xs">No data</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Compact Recent Predictions */}
      <Card className="bg-gray-800 border-gray-700">
        <CardHeader className="pb-1 pt-2 px-3">
          <CardTitle className="flex items-center gap-1 text-xs">
            <Brain className="w-3 h-3 text-purple-400" />
            Recent Predictions
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0 px-3 pb-2">
          <div className="space-y-1">
            {aggregatedMetrics.recentPredictions.length > 0 ? (
              aggregatedMetrics.recentPredictions.map((prediction) => (
                <div key={prediction.index} className="flex items-center justify-between p-2 bg-gray-700 rounded text-xs">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(prediction.predicted_label === prediction.true_label)}
                    <span className="text-xs font-mono text-gray-300">#{prediction.index}</span>
                    <Badge variant="outline" className="text-xs px-1 py-0 text-gray-300 border-gray-500">
                      {prediction.predicted_label}
                    </Badge>
                    {prediction.anomaly_detected && (
                      <Badge variant="destructive" className="text-xs px-1 py-0">
                        Anomaly
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">
                      True: {prediction.true_label}
                    </span>
                    <div className="flex items-center gap-1">
                      <div className={`w-2 h-2 rounded-full ${getSeverityColor(prediction.confidence)}`}></div>
                      <span className="text-xs font-mono text-gray-300">
                        {(prediction.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="flex items-center justify-center p-4 text-gray-500">
                <AlertCircle className="w-4 h-4 mr-1" />
                <span className="text-xs">No predictions available</span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default GenericAttackCard