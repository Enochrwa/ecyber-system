// Custom hook to throttle updates
import { useEffect  } from "react";
export const  useThrottledSocket = (socket, eventName, setData, interval = 1000) => {
  useEffect(() => {
    if (!socket) return;

    let buffer = [];
    let lastEmit = Date.now();

    const handler = (data) => {
      buffer.push(data);
      const now = Date.now();
      if (now - lastEmit >= interval) {
        setData(prev => [...prev, ...buffer]);
        buffer = [];
        lastEmit = now;
      }
    };

    socket.on(eventName, handler);

    const intervalId = setInterval(() => {
      if (buffer.length > 0) {
        setData(prev => [...prev, ...buffer]);
        buffer = [];
      }
    }, interval);

    return () => {
      socket.off(eventName, handler);
      clearInterval(intervalId);
    };
  }, [socket, eventName, setData, interval]);
}
