import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { RootState } from '../store'; // Assuming RootState is exported from store.ts

// Define the structure of a single ML alert
// Based on backend structure and frontend expectations
interface IMLPrediction {
  index?: number; // Make index optional as it might not always be primary key
  anomaly_detected: boolean;
  true_label?: string; // Optional as it might not be in all contexts
  predicted_label: string;
  confidence: number;
  class_probabilities?: {
    [key: string]: number;
  };
}

export interface IMLAlert {
  id?: string; // Optional: A unique ID for each alert, can be generated on client
  type: string; // Attack type e.g., "Port Scan"
  source_ip: string;
  destination_ip: string;
  // In backend, `prediction` is one item from the JSON array.
  // So, `prediction` here is a single prediction object.
  prediction: IMLPrediction;
  timestamp: string; // ISO string
}

interface MlAlertsState {
  alerts: IMLAlert[];
  error: string | null;
}

const MAX_STORED_ALERTS = 200; // Define a max number of alerts to store

// Function to load state from localStorage
const loadState = (): IMLAlert[] => {
  try {
    const serializedState = localStorage.getItem('reduxMlAlerts');
    if (serializedState === null) {
      return [];
    }
    return JSON.parse(serializedState);
  } catch (err) {
    console.warn("Could not load ML alerts from localStorage", err);
    return [];
  }
};

// Function to save state to localStorage
const saveState = (state: IMLAlert[]) => {
  try {
    const serializedState = JSON.stringify(state);
    localStorage.setItem('reduxMlAlerts', serializedState);
  } catch (err) {
    console.warn("Could not save ML alerts to localStorage", err);
  }
};

const initialState: MlAlertsState = {
  alerts: loadState(),
  error: null,
};

const mlAlertsSlice = createSlice({
  name: 'mlAlerts',
  initialState,
  reducers: {
    addMlAlerts: (state, action: PayloadAction<IMLAlert | IMLAlert[]>) => {
      const newAlertsRaw = Array.isArray(action.payload) ? action.payload : [action.payload];
      
      // Add unique ID and ensure timestamp is valid Date object for sorting before re-serializing
      const newAlertsWithId = newAlertsRaw.map((alert, index) => ({
        ...alert,
        id: alert.id || `${new Date(alert.timestamp).getTime()}-${index}-${alert.type}`, // Create a somewhat unique ID
        timestamp: alert.timestamp // Keep as string, sorting will parse it
      }));

      // Combine, sort, and cap
      const combined = [...state.alerts, ...newAlertsWithId];
      
      // Deduplicate based on the generated 'id'
      const uniqueAlerts = Array.from(new Map(combined.map(alert => [alert.id, alert])).values());

      state.alerts = uniqueAlerts
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, MAX_STORED_ALERTS);
      
      saveState(state.alerts); // Persist after update
    },
    clearMlAlerts: (state) => {
      state.alerts = [];
      saveState(state.alerts); // Persist after clearing
      state.error = null;
    },
    setMlAlertsError: (state, action: PayloadAction<string>) => {
      state.error = action.payload;
    }
  },
});

export const { addMlAlerts, clearMlAlerts, setMlAlertsError } = mlAlertsSlice.actions;

// Selector to get all ML alerts
export const selectAllMlAlerts = (state: RootState) => state.mlAlerts.alerts;
export const selectMlAlertsError = (state: RootState) => state.mlAlerts.error;

export default mlAlertsSlice.reducer;
