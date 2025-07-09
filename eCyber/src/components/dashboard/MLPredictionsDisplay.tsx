import React, { useMemo, useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useSelector, useDispatch } from 'react-redux';
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
import { RootState } from '@/app/store';
// import { useSelector } from 'react-redux'; // Not used directly with new props
// import { RootState } from '@/app/store'; // Not used directly with new props
import { cn } from '@/lib/utils';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { addThreats } from '@/app/slices/displaySlice';
import { IMLAlert } from '@/app/slices/mlAlertsSlice'; // Import IMLAlert

// Old API interfaces (can be removed or kept for reference if other parts use them)
// interface ClassProbabilities { ... }
// interface MLPredictionItemFromAPI { ... }
// interface MLPredictionPayloadFromAPI { ... }
// interface AllMLPredictionsFromAPI { ... }

interface MLPredictionsDisplayProps {
  predictionsData: IMLAlert[] | null; // Updated to use IMLAlert[] from Redux
  isLoading: boolean;
  error: string | null;
}

// Internal component interface for display purposes
interface DisplayablePrediction {
  id: string; // Unique ID for the alert item (e.g., from IMLAlert.id)
  modelName: string; // Derived from IMLAlert.type (e.g., "Port Scan" -> "Port Scan Model")
  attackType: string; // IMLAlert.type
  predictionType: 'threat' | 'anomaly' | 'classification'; // Simplified category for UI
  confidence: number; // From IMLAlert.prediction.confidence
  predictedLabel: string; // From IMLAlert.prediction.predicted_label
  timestamp: string; // From IMLAlert.timestamp
  anomalyDetected: boolean; // From IMLAlert.prediction.anomaly_detected
  sourceIp: string; // From IMLAlert.source_ip
  destinationIp: string; // From IMLAlert.destination_ip
  classProbabilities?: { [key: string]: number }; // From IMLAlert.prediction.class_probabilities
  // trueLabel?: string; // From IMLAlert.prediction.true_label - for display if needed
}

// Wrap PredictionItem with React.memo
const PredictionItem = React.memo(function PredictionItem({ prediction }: { prediction: DisplayablePrediction }) {
  const typeConfig = modelTypeConfig[prediction.predictionType];
  const TypeIcon = typeConfig.icon;

  const classProbabilitiesString = useMemo(() => {
    if (!prediction.classProbabilities) return "";
    return Object.entries(prediction.classProbabilities)
      .sort(([, a], [, b]) => b - a) // Sort by probability desc
      .slice(0, 3) // Take top 3
      .map(([label, prob]) => `${label}: ${(prob * 100).toFixed(1)}%`)
      .join("\n");
  }, [prediction.classProbabilities]);

  return (
    <div 
      title={classProbabilitiesString ? `Class Probabilities:\n${classProbabilitiesString}` : "No class probabilities available"}
      className={cn(
      "p-4 rounded-lg border border-slate-700/50 bg-slate-900/50 backdrop-blur-sm",
      "transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/10",
      "hover:border-cyan-500/30 hover:bg-slate-800/60",
      "relative overflow-hidden group"
    )}>
      {/* Cyber glow effect */}
      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-transparent to-blue-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      <div className="flex items-start justify-between gap-3 relative z-10">
        <div className="flex items-start gap-3 flex-1">
          <div className="relative">
            <TypeIcon className={cn(
              "w-5 h-5 mt-0.5 transition-all duration-300",
              "text-cyan-400 group-hover:text-cyan-300",
              "drop-shadow-[0_0_4px_rgba(34,211,238,0.4)]"
            )} />
            {/* Pulsing dot indicator */}
            <div className="absolute -top-1 -right-1 w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h4 className="font-medium text-sm text-slate-200 group-hover:text-white transition-colors">
                {prediction.modelName} {/* Already includes attackType */}
              </h4>
              <Badge variant="outline" className={cn(
                "text-xs border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
                "hover:bg-cyan-500/20 transition-colors"
              )}>
                {typeConfig.label}
              </Badge>
              {prediction.anomalyDetected && (
                 <Badge variant="outline" className="text-xs border-orange-500/50 bg-orange-500/10 text-orange-300">
                   Anomaly
                 </Badge>
              )}
              {/* isCorrect logic removed as it's not in DisplayablePrediction for now */}
            </div>
            
            <div className="space-y-1 mb-3">
              <p className="text-sm">
                <span className="text-slate-400 font-mono">PREDICTION:</span>{' '}
                <span className="font-medium text-slate-200 bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/50">
                  {prediction.predictedLabel}
                </span>
              </p>
              {/* actualValue logic removed as it's not in DisplayablePrediction for now */}
            </div>
            
            <div className="flex items-center gap-4 text-xs text-slate-400 font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" />
                {formatTimestamp(prediction.timestamp)}
              </span>
              <span className="flex items-center gap-1">
                <div className="w-1 h-1 bg-cyan-400 rounded-full animate-pulse" />
                CONFIDENCE: {(prediction.confidence * 100).toFixed(1)}%
              </span>
            </div>
            
            {/* Network traffic info */}
            <div className="flex items-center gap-4 text-xs text-slate-400 font-mono mt-2 pt-2 border-t border-slate-700/30">
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-pulse" />
                SRC: <span className="text-orange-300">{prediction.sourceIp}</span>
              </span>
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
                DST: <span className="text-blue-300">{prediction.destinationIp}</span>
              </span>
            </div>
          </div>
        </div>
        
        <div className="text-right">
          <div className={cn(
            "text-lg font-bold font-mono tracking-wider",
            "text-transparent bg-clip-text bg-gradient-to-r",
            prediction.confidence >= 0.8 ? "from-green-400 to-cyan-400" :
            prediction.confidence >= 0.6 ? "from-yellow-400 to-orange-400" :
            "from-red-400 to-pink-400",
            "drop-shadow-[0_0_8px_rgba(34,211,238,0.3)]"
          )}>
            {(prediction.confidence * 100).toFixed(1)}%
          </div>
          <div className="text-xs text-slate-500 font-mono tracking-wide">
            CONFIDENCE
          </div>
          
          {/* Confidence level indicator bars */}
          <div className="flex gap-0.5 mt-2 justify-end">
            {[...Array(5)].map((_, i) => (
              <div
                key={i}
                className={cn(
                  "w-1 h-3 rounded-full transition-all duration-300",
                  i < Math.floor(prediction.confidence * 5) 
                    ? "bg-cyan-400 shadow-[0_0_4px_rgba(34,211,238,0.6)]" 
                    : "bg-slate-700"
                )}
              />
            ))}
          </div>
        </div>
      </div>
      
      {/* Bottom border accent */}
      <div className={cn(
        "absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r",
        "from-transparent via-cyan-500/50 to-transparent",
        "opacity-0 group-hover:opacity-100 transition-opacity duration-300"
      )} />
    </div>
  );
});

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

export const MLPredictionsDisplay: React.FC<MLPredictionsDisplayProps> = ({
  predictionsData,
  isLoading,
  error
}) => {
  const [selectedModelType, setSelectedModelType] = useState<string>('all'); // For filtering predictions by type
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h'); // Kept for UI consistency, though data is static
  const [activeTab, setActiveTab] = useState<'overview' | 'predictions' | 'performance'>('predictions'); // Default to predictions tab
  const dispatch = useDispatch();

  // Mock data for models - keep for overview tab for now, or remove if focusing only on predictions
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

    const displayablePredictions = useMemo((): DisplayablePrediction[] => {
      if (!predictionsData || !Array.isArray(predictionsData)) return [];

      const allPreds: DisplayablePrediction[] = predictionsData.map((alert: IMLAlert) => {
        let uiPredictionType: DisplayablePrediction['predictionType'] = 'classification';
        if (alert.prediction.anomaly_detected) {
          uiPredictionType = 'anomaly';
        }
        // If predicted label is not BENIGN, or if it's a known attack type, consider it a threat for UI purposes
        if (alert.prediction.predicted_label && alert.prediction.predicted_label.toUpperCase() !== 'BENIGN') {
          uiPredictionType = 'threat';
        } else if (['port scan', 'brute force', 'web attack', 'ddos', 'dos'].includes(alert.type.toLowerCase())) {
          uiPredictionType = 'threat';
        }

        return {
          id: alert.id || `${new Date(alert.timestamp).getTime()}-${alert.type}`, // Use existing id or generate one
          modelName: `${alert.type} Scanner`, // Or a more sophisticated naming based on alert.type
          attackType: alert.type,
          predictionType: uiPredictionType,
          confidence: alert.prediction.confidence,
          predictedLabel: alert.prediction.predicted_label,
          timestamp: alert.timestamp,
          anomalyDetected: alert.prediction.anomaly_detected,
          sourceIp: alert.source_ip,
          destinationIp: alert.destination_ip,
          classProbabilities: alert.prediction.class_probabilities,
          // trueLabel: alert.prediction.true_label, // Uncomment if needed
        };
      });

      // Dispatching total number of alerts (which could be interpreted as threats)
      // This logic might need adjustment based on what `addThreats` expects or if numThreats should be more specific
      dispatch(addThreats(allPreds.length)); 
      
      // Already sorted by Redux slice, but re-sorting here won't harm if needed, though ideally source is sorted.
      return allPreds.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    }, [predictionsData, dispatch]);



  const filteredPredictions = useMemo(() => {
    if (selectedModelType === 'all') {
      return displayablePredictions;
    }
    return displayablePredictions.filter(p => 
      p.modelName.toLowerCase().replace(/\s+/g, '_') === selectedModelType // Match modelName to selectedModelType key
    );
  }, [displayablePredictions, selectedModelType]);


  // Generate performance data for charts (mocked for now)
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

  // PredictionItem component needs to be updated to use DisplayablePrediction type
  // const PredictionItem: React.FC<{ prediction: DisplayablePrediction }> = ({ prediction }) => {
  //   const typeConfig = modelTypeConfig[prediction.predictionType]; // Uses 'threat', 'anomaly', 'classification'
  //   const TypeIcon = typeConfig.icon;

  //   // Determine if the prediction was "correct" based on true_label vs predicted_label if available
  //   // For now, isCorrect is not part of DisplayablePrediction, so this part is illustrative
  //   // const isCorrect = prediction.trueLabel && prediction.predictedLabel && prediction.trueLabel === prediction.predictedLabel;

  //   return (
  //     <div className={cn(
  //       "p-4 rounded-lg border border-slate-700/50 bg-slate-900/50 backdrop-blur-sm",
  //       "transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/10",
  //       "hover:border-cyan-500/30 hover:bg-slate-800/60",
  //       "relative overflow-hidden group"
  //     )}>
  //       {/* Cyber glow effect */}
  //       <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-transparent to-blue-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
        
  //       <div className="flex items-start justify-between gap-3 relative z-10">
  //         <div className="flex items-start gap-3 flex-1">
  //           <div className="relative">
  //             <TypeIcon className={cn(
  //               "w-5 h-5 mt-0.5 transition-all duration-300",
  //               "text-cyan-400 group-hover:text-cyan-300",
  //               "drop-shadow-[0_0_4px_rgba(34,211,238,0.4)]"
  //             )} />
  //             <div className="absolute -top-1 -right-1 w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
  //           </div>
            
  //           <div className="flex-1 min-w-0">
  //             <div className="flex items-center gap-2 mb-2">
  //               <h4 className="font-medium text-sm text-slate-200 group-hover:text-white transition-colors">
  //                 {prediction.modelName} ({prediction.attackType})
  //               </h4>
  //               <Badge variant="outline" className={cn(
  //                 "text-xs border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  //                 "hover:bg-cyan-500/20 transition-colors"
  //               )}>
  //                 {typeConfig.label}
  //               </Badge>
  //               {prediction.anomalyDetected && (
  //                 <Badge variant="outline" className="text-xs border-orange-500/50 bg-orange-500/10 text-orange-300">
  //                   Anomaly
  //                 </Badge>
  //               )}
  //                {/* Example for showing if prediction was correct - needs trueLabel in DisplayablePrediction
  //               {isCorrect !== undefined && (
  //                 isCorrect ? 
  //                   <CheckCircle className="w-4 h-4 text-green-400 drop-shadow-[0_0_4px_rgba(34,197,94,0.4)]" /> :
  //                   <XCircle className="w-4 h-4 text-red-400 drop-shadow-[0_0_4px_rgba(239,68,68,0.4)]" />
  //               )}
  //               */}
  //             </div>
              
  //             <div className="space-y-1 mb-3">
  //               <p className="text-sm">
  //                 <span className="text-slate-400 font-mono">PREDICTION:</span>{' '}
  //                 <span className="font-medium text-slate-200 bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/50">
  //                   {prediction.predictedLabel}
  //                 </span>
  //               </p>
  //               {/* Example for showing true label
  //               {prediction.trueLabel && (
  //                 <p className="text-sm">
  //                   <span className="text-slate-400 font-mono">TRUE LABEL:</span>{' '}
  //                   <span className="font-medium text-slate-200 bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/50">
  //                     {prediction.trueLabel}
  //                   </span>
  //                 </p>
  //               )}
  //               */}
  //             </div>
              
  //             <div className="flex items-center gap-4 text-xs text-slate-400 font-mono">
  //               <span className="flex items-center gap-1">
  //                 <Clock className="w-3 h-3 text-cyan-400" />
  //                 {formatTimestamp(prediction.timestamp)}
  //               </span>
  //               <span className="flex items-center gap-1">
  //                 <div className="w-1 h-1 bg-cyan-400 rounded-full animate-pulse" />
  //                 CONFIDENCE: {(prediction.confidence * 100).toFixed(1)}%
  //               </span>
  //             </div>
              
  //             {/* Network traffic info */}
  //             <div className="flex items-center gap-4 text-xs text-slate-400 font-mono mt-2 pt-2 border-t border-slate-700/30">
  //               <span className="flex items-center gap-1">
  //                 <div className="w-2 h-2 bg-orange-400 rounded-full animate-pulse" />
  //                 SRC: <span className="text-orange-300">{prediction.sourceIp}</span>
  //               </span>
  //               <span className="flex items-center gap-1">
  //                 <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
  //                 DST: <span className="text-blue-300">{prediction.destinationIp}</span>
  //               </span>
  //             </div>
  //           </div>
  //         </div>
          
  //         <div className="text-right">
  //           <div className={cn(
  //             "text-lg font-bold font-mono tracking-wider",
  //             "text-transparent bg-clip-text bg-gradient-to-r",
  //             prediction.confidence >= 0.8 ? "from-green-400 to-cyan-400" :
  //             prediction.confidence >= 0.6 ? "from-yellow-400 to-orange-400" :
  //             "from-red-400 to-pink-400",
  //             "drop-shadow-[0_0_8px_rgba(34,211,238,0.3)]"
  //           )}>
  //             {(prediction.confidence * 100).toFixed(1)}%
  //           </div>
  //           <div className="text-xs text-slate-500 font-mono tracking-wide">
  //             CONFIDENCE
  //           </div>
            
  //           {/* Confidence level indicator bars */}
  //           <div className="flex gap-0.5 mt-2 justify-end">
  //             {[...Array(5)].map((_, i) => (
  //               <div
  //                 key={i}
  //                 className={cn(
  //                   "w-1 h-3 rounded-full transition-all duration-300",
  //                   i < Math.floor(prediction.confidence * 5) 
  //                     ? "bg-cyan-400 shadow-[0_0_4px_rgba(34,211,238,0.6)]" 
  //                     : "bg-slate-700"
  //                 )}
  //               />
  //             ))}
  //           </div>
  //         </div>
  //       </div>
        
  //       {/* Bottom border accent */}
  //       <div className={cn(
  //         "absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r",
  //         "from-transparent via-cyan-500/50 to-transparent",
  //         "opacity-0 group-hover:opacity-100 transition-opacity duration-300"
  //       )} />
  //     </div>
  //   );
  // };

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

  const PredictionItem: React.FC<{ prediction: DisplayablePrediction }> = ({ prediction }) => { // Changed prop type to DisplayablePrediction
  const typeConfig = modelTypeConfig[prediction.predictionType];
  const TypeIcon = typeConfig.icon;

  const classProbabilitiesString = useMemo(() => {
    if (!prediction.classProbabilities) return "";
    return Object.entries(prediction.classProbabilities)
      .sort(([, a], [, b]) => b - a) // Sort by probability desc
      .slice(0, 3) // Take top 3
      .map(([label, prob]) => `${label}: ${(prob * 100).toFixed(1)}%`)
      .join("\n");
  }, [prediction.classProbabilities]);

  return (
    <div 
      title={classProbabilitiesString ? `Class Probabilities:\n${classProbabilitiesString}` : "No class probabilities available"}
      className={cn(
      "p-4 rounded-lg border border-slate-700/50 bg-slate-900/50 backdrop-blur-sm",
      "transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/10",
      "hover:border-cyan-500/30 hover:bg-slate-800/60",
      "relative overflow-hidden group"
    )}>
      {/* Cyber glow effect */}
      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-transparent to-blue-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      <div className="flex items-start justify-between gap-3 relative z-10">
        <div className="flex items-start gap-3 flex-1">
          <div className="relative">
            <TypeIcon className={cn(
              "w-5 h-5 mt-0.5 transition-all duration-300",
              "text-cyan-400 group-hover:text-cyan-300",
              "drop-shadow-[0_0_4px_rgba(34,211,238,0.4)]"
            )} />
            {/* Pulsing dot indicator */}
            <div className="absolute -top-1 -right-1 w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h4 className="font-medium text-sm text-slate-200 group-hover:text-white transition-colors">
                {prediction.modelName} {/* Already includes attackType */}
              </h4>
              <Badge variant="outline" className={cn(
                "text-xs border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
                "hover:bg-cyan-500/20 transition-colors"
              )}>
                {typeConfig.label}
              </Badge>
              {prediction.anomalyDetected && (
                 <Badge variant="outline" className="text-xs border-orange-500/50 bg-orange-500/10 text-orange-300">
                   Anomaly
                 </Badge>
              )}
              {/* isCorrect logic removed as it's not in DisplayablePrediction for now */}
            </div>
            
            <div className="space-y-1 mb-3">
              <p className="text-sm">
                <span className="text-slate-400 font-mono">PREDICTION:</span>{' '}
                <span className="font-medium text-slate-200 bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/50">
                  {prediction.predictedLabel}
                </span>
              </p>
              {/* actualValue logic removed as it's not in DisplayablePrediction for now */}
            </div>
            
            <div className="flex items-center gap-4 text-xs text-slate-400 font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" />
                {formatTimestamp(prediction.timestamp)}
              </span>
              <span className="flex items-center gap-1">
                <div className="w-1 h-1 bg-cyan-400 rounded-full animate-pulse" />
                CONFIDENCE: {(prediction.confidence * 100).toFixed(1)}%
              </span>
            </div>
            
            {/* Network traffic info */}
            <div className="flex items-center gap-4 text-xs text-slate-400 font-mono mt-2 pt-2 border-t border-slate-700/30">
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-pulse" />
                SRC: <span className="text-orange-300">{prediction.sourceIp}</span>
              </span>
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
                DST: <span className="text-blue-300">{prediction.destinationIp}</span>
              </span>
            </div>
          </div>
        </div>
        
        <div className="text-right">
          <div className={cn(
            "text-lg font-bold font-mono tracking-wider",
            "text-transparent bg-clip-text bg-gradient-to-r",
            prediction.confidence >= 0.8 ? "from-green-400 to-cyan-400" :
            prediction.confidence >= 0.6 ? "from-yellow-400 to-orange-400" :
            "from-red-400 to-pink-400",
            "drop-shadow-[0_0_8px_rgba(34,211,238,0.3)]"
          )}>
            {(prediction.confidence * 100).toFixed(1)}%
          </div>
          <div className="text-xs text-slate-500 font-mono tracking-wide">
            CONFIDENCE
          </div>
          
          {/* Confidence level indicator bars */}
          <div className="flex gap-0.5 mt-2 justify-end">
            {[...Array(5)].map((_, i) => (
              <div
                key={i}
                className={cn(
                  "w-1 h-3 rounded-full transition-all duration-300",
                  i < Math.floor(prediction.confidence * 5) 
                    ? "bg-cyan-400 shadow-[0_0_4px_rgba(34,211,238,0.6)]" 
                    : "bg-slate-700"
                )}
              />
            ))}
          </div>
        </div>
      </div>
      
      {/* Bottom border accent */}
      <div className={cn(
        "absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r",
        "from-transparent via-cyan-500/50 to-transparent",
        "opacity-0 group-hover:opacity-100 transition-opacity duration-300"
      )} />
    </div>
  );
};
  if (isLoading) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            ML Model Predictions & Performance
          </CardTitle>
        </CardHeader>
        <CardContent className="flex justify-center items-center h-40">
          <p>Loading predictions...</p>
        </CardContent>
      </Card>
    );
  }

  if (!predictionsData || displayablePredictions.length === 0) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-600" />
            ML Model Predictions & Performance
          </CardTitle>
        </CardHeader>
        <CardContent className="flex justify-center items-center h-40">
          <p>No ML predictions available at the moment.</p>
        </CardContent>
      </Card>
    );
  }

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
              value={timeRange} // This is now less relevant as data is static from files
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
                value={selectedModelType}
                onChange={(e) => setSelectedModelType(e.target.value)}
                className="text-sm border rounded px-2 py-1"
              >
                <option value="all">All Prediction Types</option>
                {/* Populate options from unique attack types in displayablePredictions */}
                {Array.from(new Set(displayablePredictions.map(p => p.attackType))).map((typeKey) => {
                  const modelDisplayName = `${typeKey} Scanner`; // Consistent with modelName generation
                  return (
                    <option key={typeKey} value={typeKey.toLowerCase().replace(/\s+/g, '_')}>
                      {modelDisplayName}
                    </option>
                  );
                })}
              </select>
            </div>

            {filteredPredictions.length > 0 ? (
              <div className="space-y-3">
                {filteredPredictions.map((item) => ( // Renamed to item to avoid conflict with PredictionItem component
                  <PredictionItem key={item.id} prediction={item} />
                ))}
              </div>
            ) : (
              <div className="text-center text-muted-foreground py-8">
                No predictions to display for the selected type.
              </div>
            )}
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

