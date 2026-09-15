const eventSource = new EventSource("https://stream.example.com/api/v1/live-feed");
eventSource.onmessage = function(e) {
  console.log("New event:", e.data);
};
