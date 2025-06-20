import React, { useMemo, useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Brain, 
  TrendingUp, 
  Target, 
  Activity, 
  Clock, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  BarChart3,
  Zap,
  Eye,
  RefreshCw
} from 'lucide-react';
import { useSelector } from 'react-redux';
import { RootState } from '@/app/store';
import { cn } from '@/lib/utils';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';

interface MLPrediction {
  id: string;
  modelName: string;
  predictionType: 'threat' | 'anomaly' | 'classification' | 'regression';
  confidence: number;
  prediction: string;
  actualValue?: string;
  isCorrect?: boolean;
  timestamp: string;
  inputFeatures: Record<string, any>;
  metadata?: Record<string, any>;
}

interface MLModel {
  id: string;
  name: string;
  type: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  lastTrained: string;
  status: 'active' | 'training' | 'inactive' | 'error';
  predictionsCount: number;
  correctPredictions: number;
  version: string;
}

const modelTypeConfig = {
  threat: { 
    color: 'text-red-600', 
    bgColor: 'bg-red-50', 
    icon: AlertTriangle,
    label: 'Threat Detection'
  },
  anomaly: { 
    color: 'text-orange-600', 
    bgColor: 'bg-orange-50', 
    icon: Activity,
    label: 'Anomaly Detection'
  },
  classification: { 
    color: 'text-blue-600', 
    bgColor: 'bg-blue-50', 
    icon: Target,
    label: 'Classification'
  },
  regression: { 
    color: 'text-green-600', 
    bgColor: 'bg-green-50', 
    icon: TrendingUp,
    label: 'Regression'
  }
};

const statusConfig = {
  active: { color: 'text-green-600', bgColor: 'bg-green-50', label: 'Active' },
  training: { color: 'text-blue-600', bgColor: 'bg-blue-50', label: 'Training' },
  inactive: { color: 'text-gray-600', bgColor: 'bg-gray-50', label: 'Inactive' },
  error: { color: 'text-red-600', bgColor: 'bg-red-50', label: 'Error' }
};

export const MLPredictionsDisplay: React.FC = () => {
  const [selectedModel, setSelectedModel] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [activeTab, setActiveTab] = useState<'overview' | 'predictions' | 'performance'>('overview');

  // Mock data - in real implementation, this would come from Redux store
  const [models] = useState<MLModel[]>([
    {
      id: 'threat-detector-v2',
      name: 'Advanced Threat Detector',
      type: 'threat',
      accuracy: 0.94,
      precision: 0.92,
      recall: 0.89,
      f1Score: 0.90,
      lastTrained: '2024-06-19T10:30:00Z',
      status: 'active',
      predictionsCount: 1247,
      correctPredictions: 1172,
      version: 'v2.1.3'
    },
    {
      id: 'anomaly-detector-v1',
      name: 'Network Anomaly Detector',
      type: 'anomaly',
      accuracy: 0.87,
      precision: 0.85,
      recall: 0.88,
      f1Score: 0.86,
      lastTrained: '2024-06-18T15:45:00Z',
      status: 'active',
      predictionsCount: 892,
      correctPredictions: 776,
      version: 'v1.4.2'
    },
    {
      id: 'malware-classifier-v3',
      name: 'Malware Classifier',
      type: 'classification',
      accuracy: 0.96,
      precision: 0.95,
      recall: 0.94,
      f1Score: 0.94,
      lastTrained: '2024-06-19T08:15:00Z',
      status: 'active',
      predictionsCount: 2156,
      correctPredictions: 2070,
      version: 'v3.0.1'
    },
    {
      id: 'risk-predictor-v1',
      name: 'Risk Score Predictor',
      type: 'regression',
      accuracy: 0.82,
      precision: 0.80,
      recall: 0.84,
      f1Score: 0.82,
      lastTrained: '2024-06-17T12:00:00Z',
      status: 'training',
      predictionsCount: 567,
      correctPredictions: 465,
      version: 'v1.2.0'
    }
  ]);

  const [predictions] = useState<MLPrediction[]>([
    {
      id: 'pred-1',
      modelName: 'Advanced Threat Detector',
      predictionType: 'threat',
      confidence: 0.94,
      prediction: 'Malicious',
      actualValue: 'Malicious',
      isCorrect: true,
      timestamp: '2024-06-19T14:30:00Z',
      inputFeatures: { 
        packetSize: 1024, 
        protocol: 'TCP', 
        sourceIP: '192.168.1.100',
        payloadEntropy: 7.2
      }
    },
    {
      id: 'pred-2',
      modelName: 'Network Anomaly Detector',
      predictionType: 'anomaly',
      confidence: 0.87,
      prediction: 'Anomalous',
      actualValue: 'Normal',
      isCorrect: false,
      timestamp: '2024-06-19T14:25:00Z',
      inputFeatures: { 
        bandwidth: 1500, 
        connectionCount: 45, 
        timeOfDay: 14
      }
    },
    {
      id: 'pred-3',
      modelName: 'Malware Classifier',
      predictionType: 'classification',
      confidence: 0.98,
      prediction: 'Trojan',
      actualValue: 'Trojan',
      isCorrect: true,
      timestamp: '2024-06-19T14:20:00Z',
      inputFeatures: { 
        fileSize: 2048576, 
        entropy: 6.8, 
        peImports: 23
      }
    }
  ]);

  // Generate performance data for charts
  const performanceData = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, i) => {
      const hour = new Date();
      hour.setHours(hour.getHours() - (23 - i));
      return {
        time: hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        accuracy: 0.85 + Math.random() * 0.15,
        predictions: Math.floor(Math.random() * 50) + 10,
        threats: Math.floor(Math.random() * 10),
        anomalies: Math.floor(Math.random() * 5)
      };
    });
    return hours;
  }, []);

  const confidenceDistribution = useMemo(() => {
    return [
      { range: '90-100%', count: 45, color: '#10b981' },
      { range: '80-90%', count: 32, color: '#3b82f6' },
      { range: '70-80%', count: 18, color: '#f59e0b' },
      { range: '60-70%', count: 8, color: '#ef4444' },
      { range: '<60%', count: 3, color: '#6b7280' }
    ];
  }, []);

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    return date.toLocaleTimeString();
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.9) return 'text-green-600';
    if (confidence >= 0.8) return 'text-blue-600';
    if (confidence >= 0.7) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getConfidenceBgColor = (confidence: number) => {
    if (confidence >= 0.9) return 'bg-green-50';
    if (confidence >= 0.8) return 'bg-blue-50';
    if (confidence >= 0.7) return 'bg-yellow-50';
    return 'bg-red-50';
  };

  const ModelCard: React.FC<{ model: MLModel }> = ({ model }) => {
    const typeConfig = modelTypeConfig[model.type as keyof typeof modelTypeConfig];
    const statusInfo = statusConfig[model.status];
    const TypeIcon = typeConfig.icon;

    return (
      <Card className="h-full">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TypeIcon className={cn("w-5 h-5", typeConfig.color)} />
              <CardTitle className="text-base">{model.name}</CardTitle>
            </div>
            <Badge 
              variant="outline" 
              className={cn("text-xs", statusInfo.color)}
            >
              {statusInfo.label}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">{typeConfig.label} • {model.version}</p>
        </CardHeader>
        
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-muted-foreground">Accuracy</p>
              <div className="flex items-center gap-2">
                <Progress value={model.accuracy * 100} className="flex-1" />
                <span className="text-sm font-medium">{(model.accuracy * 100).toFixed(1)}%</span>
              </div>
            </div>
            
            <div>
              <p className="text-xs text-muted-foreground">F1 Score</p>
              <div className="flex items-center gap-2">
                <Progress value={model.f1Score * 100} className="flex-1" />
                <span className="text-sm font-medium">{(model.f1Score * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-muted-foreground">Predictions</p>
              <p className="font-medium">{model.predictionsCount.toLocaleString()}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Correct</p>
              <p className="font-medium text-green-600">
                {model.correctPredictions.toLocaleString()}
              </p>
            </div>
          </div>
          
          <div>
            <p className="text-xs text-muted-foreground">Last Trained</p>
            <p className="text-sm">{formatTimestamp(model.lastTrained)}</p>
          </div>
        </CardContent>
      </Card>
    );
  };

  const PredictionItem: React.FC<{ prediction: MLPrediction }> = ({ prediction }) => {
    const typeConfig = modelTypeConfig[prediction.predictionType];
    const TypeIcon = typeConfig.icon;

    return (
      <div className={cn(
        "p-4 rounded-lg border transition-all hover:shadow-md",
        getConfidenceBgColor(prediction.confidence)
      )}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1">
            <TypeIcon className={cn("w-5 h-5 mt-0.5", typeConfig.color)} />
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2">
                <h4 className="font-medium text-sm">{prediction.modelName}</h4>
                <Badge variant="outline" className="text-xs">
                  {typeConfig.label}
                </Badge>
                {prediction.isCorrect !== undefined && (
                  prediction.isCorrect ? 
                    <CheckCircle className="w-4 h-4 text-green-600" /> :
                    <XCircle className="w-4 h-4 text-red-600" />
                )}
              </div>
              
              <div className="space-y-1 mb-3">
                <p className="text-sm">
                  <span className="text-muted-foreground">Prediction:</span>{' '}
                  <span className="font-medium">{prediction.prediction}</span>
                </p>
                {prediction.actualValue && (
                  <p className="text-sm">
                    <span className="text-muted-foreground">Actual:</span>{' '}
                    <span className="font-medium">{prediction.actualValue}</span>
                  </p>
                )}
              </div>
              
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatTimestamp(prediction.timestamp)}
                </span>
                <span>
                  Confidence: {(prediction.confidence * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          </div>
          
          <div className="text-right">
            <div className={cn(
              "text-lg font-bold",
              getConfidenceColor(prediction.confidence)
            )}>
              {(prediction.confidence * 100).toFixed(1)}%
            </div>
            <div className="text-xs text-muted-foreground">Confidence</div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            <CardTitle className="text-lg">ML Model Predictions & Performance</CardTitle>
          </div>
          
          <div className="flex items-center gap-2">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value as any)}
              className="text-sm border rounded px-2 py-1"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            
            <Button variant="ghost" size="sm">
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as any)}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="predictions">Recent Predictions</TabsTrigger>
            <TabsTrigger value="performance">Performance Metrics</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            {/* Model Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {models.map((model) => (
                <ModelCard key={model.id} model={model} />
              ))}
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Target className="w-4 h-4 text-blue-600" />
                    <span className="text-sm font-medium">Total Predictions</span>
                  </div>
                  <div className="text-2xl font-bold">
                    {models.reduce((sum, model) => sum + model.predictionsCount, 0).toLocaleString()}
                  </div>
                  <div className="text-xs text-muted-foreground">Last 24 hours</div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-4 h-4 text-green-600" />
                    <span className="text-sm font-medium">Accuracy Rate</span>
                  </div>
                  <div className="text-2xl font-bold text-green-600">
                    {((models.reduce((sum, model) => sum + model.correctPredictions, 0) / 
                       models.reduce((sum, model) => sum + model.predictionsCount, 0)) * 100).toFixed(1)}%
                  </div>
                  <div className="text-xs text-muted-foreground">Overall performance</div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="w-4 h-4 text-yellow-600" />
                    <span className="text-sm font-medium">Active Models</span>
                  </div>
                  <div className="text-2xl font-bold">
                    {models.filter(model => model.status === 'active').length}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {models.filter(model => model.status === 'training').length} training
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="predictions" className="space-y-4">
            <div className="flex items-center gap-4 mb-4">
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="text-sm border rounded px-2 py-1"
              >
                <option value="all">All Models</option>
                {models.map((model) => (
                  <option key={model.id} value={model.id}>{model.name}</option>
                ))}
              </select>
            </div>

            <div className="space-y-3">
              {predictions.map((prediction) => (
                <PredictionItem key={prediction.id} prediction={prediction} />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="performance" className="space-y-6">
            {/* Performance Chart */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Model Performance Over Time</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={performanceData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Line 
                      type="monotone" 
                      dataKey="accuracy" 
                      stroke="#3b82f6" 
                      strokeWidth={2}
                      name="Accuracy"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="predictions" 
                      stroke="#10b981" 
                      strokeWidth={2}
                      name="Predictions/Hour"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Confidence Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Confidence Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={confidenceDistribution}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="range" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="count" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default MLPredictionsDisplay;

