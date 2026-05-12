import { useEffect, useState } from 'react';

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<any>(null);

  useEffect(() => {
    const ws = new WebSocket(url);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLastMessage(data);
      } catch (e) {
        console.error("WS Parse error", e);
      }
    };

    ws.onclose = () => console.log('WS Disconnected');
    ws.onerror = (err) => console.error('WS Error', err);

    return () => ws.close();
  }, [url]);

  return lastMessage;
}
