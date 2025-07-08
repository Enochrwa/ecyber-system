
import React, { useEffect, lazy, useState, Suspense } from "react";

import { BrowserRouter, Routes, Route } from "react-router-dom";
import AlertSound from "alert.mp3"
import Index from "./pages/Index";

import Dashboard from "./pages/Dashboard";
import Threats from "./pages/Threats";
import Network from "./pages/Network";
import Logs from "./pages/Logs";
import Models from "./pages/Models";
import System from "./components/live-system/System";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import AttackSimulations from "./pages/AttackSimulations";

import MainLayout from "./components/layout/MainLayout";
import NotFound from "./pages/NotFound";

import LoginPage from "./pages/Login";
import { ThreatCve } from "./pages/threats/ThreatCve";
import { ThreatMitre } from "./pages/threats/ThreatMitre";
import { ThreatIntel } from "./pages/threats/ThreatIntel";
import { ThreatOsint } from "./pages/threats/ThreatOsint";
import Alerts from "./alert/Alerts";
// import useSocket from "./hooks/useSocket"; // Assuming this is not the primary socket hook for app connectivity status
import usePacketSniffer from "./hooks/usePacketSnifferSocket";
import RegisterPage from "./pages/Register";
import CyberLoader from "./utils/Loader"
// import AuthModal from "./pages/AuthModal";
// import LoadingSpinner from "./utils/LoadingSpinner";
import { useSelector, useDispatch } from "react-redux" // Added useDispatch
import { RootState } from "@/app/store"
import { setIsBackendUp } from "@/app/slices/displaySlice"; // Added import for action
import { checkBackendHealth } from "@/services/api"; // Added import for health check
import useSocket from "./hooks/useSocket";
import { useTelemetrySocket } from "./components/live-system/lib/socket";
import { useThrottledSocket } from "./hooks/useThrottledSocket";

interface IMLAlert {
  type: string;
  source_ip: string;
  destination_ip: string;
  prediction: any; // Consider defining a more specific type for prediction
  timestamp: string;
}

const App = () => {
  const { isConnected, connectionError, socket } = usePacketSniffer();
  const { socket: socket2 } = useSocket()
  const { getSocket } = useTelemetrySocket()
  const rootSocket = getSocket()

  const [showLoader, setShowLoader] = useState(true);
  const dispatch = useDispatch();
  const isBackendUp = useSelector((state: RootState) => state.display.isBackendUp);
  // Initialize mlAlerts from localStorage
  const [mlAlerts, setMlAlerts ] = useState<IMLAlert[]>(() => {
    const storedAlerts = localStorage.getItem("mlAlerts");
    return storedAlerts ? JSON.parse(storedAlerts) : [];
  });

  const [anomalies, setAnomalies] = useState([]);

  useEffect(() => {
    // Persist mlAlerts to localStorage whenever it changes
    localStorage.setItem("mlAlerts", JSON.stringify(mlAlerts));
  }, [mlAlerts]);

  useEffect(() => {
    socket2?.on("new_ml_alert", (batch: IMLAlert[] | IMLAlert) => { // Adjusted to handle single or batch
      setMlAlerts(prevAlerts => {
        const newAlerts = Array.isArray(batch) ? batch : [batch];
        // Add new alerts and prevent duplicates based on a unique key if available, e.g., prediction.id + timestamp
        // For now, just adding, assuming backend might send same alert if not handled there.
        // A more robust solution would involve a unique ID for each alert.
        const updatedAlerts = [...prevAlerts, ...newAlerts].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        // Optional: Limit the number of stored alerts to prevent localStorage from growing too large
        // const MAX_STORED_ALERTS = 200; 
        // return updatedAlerts.slice(0, MAX_STORED_ALERTS);
        return updatedAlerts;
      });
    });

    return () => {
      socket2?.off("new_ml_alert");
    };
  }, [socket2]); // Dependency array includes socket2 to re-subscribe if it changes
  
  useEffect(() => {
    const performHealthCheck = async () => {
      try {
        // const health = await checkBackendHealth(); // Optionally check health.status
        await checkBackendHealth();
        dispatch(setIsBackendUp(true));
        // setShowLoader(false); // Handled by the next useEffect
      } catch (error) {
        console.error("Backend health check failed:", error);
        dispatch(setIsBackendUp(false));
        // Consider if setShowLoader(true) is needed here or if loader remains visible by default
      }
    };

    if (!isBackendUp) { // Only run if backend isn't already marked as up
      performHealthCheck();
    } else {
      setShowLoader(false); // If already up (e.g. from persisted state), hide loader
    }
  }, [dispatch, isBackendUp]);

  // This useEffect handles hiding the loader once isBackendUp becomes true
  // (either from health check or other means like persisted Redux state).
  useEffect(() => {
    if (isBackendUp) {
      setShowLoader(false);
    }
    // If !isBackendUp, showLoader remains true (or its current state), 
    // allowing CyberLoader to display "Connecting..." or "Backend unavailable"
    // For now, CyberLoader just shows a generic loading animation.
  }, [isBackendUp]);

  // if (showLoader) {
  //   // Optionally, CyberLoader could take isBackendUp as a prop to show different messages
  //   // e.g., <CyberLoader isLoading={true} backendStatusKnown={isBackendUp !== undefined} isUp={isBackendUp} />
  //   return <CyberLoader isLoading={true} />; 
  // }

  return (
    <>
      <Routes>
        <Route path="/" element={<Index />} />
        <Route path="/loading" element={<CyberLoader />} />
        <Route element={<MainLayout />}>
          <Route path="/dashboard" element={<Dashboard mlAlerts={mlAlerts} />} />
          <Route path="/system" element={<System />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/network" element={<Network />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/models" element={<Models />} />
          <Route path="/users" element={<Users />} />
          <Route path="/threats/cve" element={<ThreatCve />} />
          <Route path="/threats/intel" element={<ThreatIntel />} />
          <Route path="/threats/mitre" element={<ThreatMitre />} />
          <Route path="/threats/osint" element={<ThreatOsint />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/attack-simulations" element={<AttackSimulations />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
      {/* <AuthModal /> */}
    </>
  );
};

export default App