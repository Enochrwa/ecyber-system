import React, {
  createContext,
  useState,
  useEffect,
  useContext,
  ReactNode,
} from 'react';
import useSocket from '@/hooks/useSocket'; // Ensure this returns a { socket } object

// Structure of a single ML alert
export interface IMLAlert {
  type: string; // e.g., "DDoS", "Brute Force"
  source_ip: string;
  destination_ip: string;
  prediction: Record<string, any>; // Use Record if structure varies
  timestamp: string; // ISO format string
}

// Context shape
interface IAlertsContext {
  mlAlerts: IMLAlert[];
}

// Create context
const AlertsContext = createContext<IAlertsContext | undefined>(undefined);

// Provider props
interface AlertsProviderProps {
  children: ReactNode;
}

export const AlertsProvider: React.FC<AlertsProviderProps> = ({ children }) => {
  const { socket } = useSocket(); // Your socket hook must return `{ socket }`
  const [mlAlerts, setMlAlerts] = useState<IMLAlert[]>(() => {
    try {
      const stored = localStorage.getItem('mlAlerts');
      return stored ? JSON.parse(stored) as IMLAlert[] : [];
    } catch {
      return [];
    }
  });

  // Save alerts to localStorage on every change
  useEffect(() => {
    try {
      localStorage.setItem('mlAlerts', JSON.stringify(mlAlerts));
    } catch (err) {
      console.error('Failed to store mlAlerts in localStorage:', err);
    }
  }, [mlAlerts]);

  // Listen to incoming ML alerts via socket
  useEffect(() => {
    if (!socket) return;

    const handleNewMlAlert = (batch: IMLAlert | IMLAlert[]) => {
      const newAlerts = Array.isArray(batch) ? batch : [batch];

      setMlAlerts(prev => {
        const combined = [...newAlerts, ...prev]
          .sort((a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          );

        // Optional: limit total number
        const MAX_ALERTS = 200;
        return combined.slice(0, MAX_ALERTS);
      });
    };

    socket.on('new_ml_alert', handleNewMlAlert);

    return () => {
      socket.off('new_ml_alert', handleNewMlAlert);
    };
  }, [socket]);

  return (
    <AlertsContext.Provider value={{ mlAlerts }}>
      {children}
    </AlertsContext.Provider>
  );
};

// Custom hook to use alert context
export const useAlerts = (): IAlertsContext => {
  const context = useContext(AlertsContext);
  if (!context) {
    throw new Error('useAlerts must be used within an AlertsProvider');
  }
  return context;
};