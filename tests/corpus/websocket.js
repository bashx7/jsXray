const socketUrl = "wss://realtime.example.com/v1/chat/stream?channel=general";
const ws = new WebSocket(socketUrl);

ws.onopen = function() {
  ws.send(JSON.stringify({ action: "subscribe", topic: "alerts" }));
};

const rawSocket = new WebSocket("ws://10.0.4.55:8080/events");
