import { configureStore } from '@reduxjs/toolkit'

import socketSlice  from './slices/socketSlice'
import {
  dnsActivityReducer,
  firewallEventsReducer,
  threatDetectionsReducer,
  ipv6ActivityReducer,
  packetDataReducer,
  systemMetricsReducer,
  securityAlertsReducer,
  phishingDetectionsReducer,
  threatResponsesReducer,
  quarantinedFilesReducer,
  networkVolumeReducer,
  networkInterfaceReducer,
  mlNOtificationsReducer
} from './slices/realtimeDataSlice';
import mlAlertsReducer from './slices/mlAlertsSlice'; // Import the new reducer

import 
  displaySliceReducer
from './slices/displaySlice'

export const store = configureStore({
  reducer: {
    display:displaySliceReducer,
    socket:socketSlice,
    networkVolume: networkVolumeReducer,
    networkInterfaces: networkInterfaceReducer,
    dnsActivity: dnsActivityReducer,
    firewallEvents: firewallEventsReducer,
    threatDetections: threatDetectionsReducer,
    ipv6Activity: ipv6ActivityReducer,
    packetData: packetDataReducer,
    systemMetrics: systemMetricsReducer,
    securityAlerts: securityAlertsReducer,
    phishingDetections: phishingDetectionsReducer,
    threatResponses: threatResponsesReducer,
    quarantinedFiles: quarantinedFilesReducer,
    mlNotifications: mlNOtificationsReducer,
    mlAlerts: mlAlertsReducer, // Add the new reducer here
  },
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
