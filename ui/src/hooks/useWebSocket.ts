import { useState, useEffect } from 'react';

export function useWebSocket(url: string, token?: string) {
  const [message, setMessage] = useState<any>(null);

  useEffect(() => {
    const fullUrl = token ? `${url}?token=${token}` : url;
    const ws = new WebSocket(fullUrl);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setMessage(data);
      } catch (err) {
        console.error('WS Parse Error:', err);
      }
    };

    ws.onerror = (error) => {
      if (ws.readyState !== WebSocket.CLOSED) {
        console.error('WS Error Event', error);
      }
    };

    ws.onclose = () => {
      console.log('WS Disconnected');
    };

    return () => {
      if (ws.readyState === 1) {
        ws.close();
      } else if (ws.readyState === 0) {
        ws.onopen = () => ws.close();
      }
    };
  }, [url, token]);

  return message;
}