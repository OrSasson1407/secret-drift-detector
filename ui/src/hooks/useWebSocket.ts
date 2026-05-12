import { useState, useEffect } from 'react';

export function useWebSocket(url: string) {
  const [message, setMessage] = useState<any>(null);

  useEffect(() => {
    const ws = new WebSocket(url);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setMessage(data);
      } catch (err) {
        console.error("WS Parse Error:", err);
      }
    };

    ws.onerror = (error) => {
      // Suppress strict mode connection abort errors in console
      if (ws.readyState !== WebSocket.CLOSED) {
        console.error("WS Error Event", error);
      }
    };

    ws.onclose = () => {
      console.log("WS Disconnected");
    };

    return () => {
      // React 18 Strict Mode Fix: Prevent closing a websocket while it is still connecting
      if (ws.readyState === 1) { // OPEN
        ws.close();
      } else if (ws.readyState === 0) { // CONNECTING
        ws.onopen = () => ws.close();
      }
    };
  }, [url]);

  return message;
}