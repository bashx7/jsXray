import { createApp } from 'vue';
if (import.meta.hot) {
  import.meta.hot.accept((newModule) => {
    console.log("Vite HMR updated");
  });
}
const apiBase = "https://vite-api.example.com";
export async function getDashboardData() {
  const res = await fetch(`${apiBase}/api/v2/dashboard/stats?period=monthly&filter=active`);
  return res.json();
}
