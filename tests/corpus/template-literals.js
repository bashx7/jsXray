const BASE_URL = "https://service.example.com";
const API_VERSION = "v3";
function fetchUserProfile(userId, accountId) {
  return fetch(`${BASE_URL}/api/${API_VERSION}/accounts/${accountId}/users/${userId}/profile`);
}
function fetchAccountSettings(accountId) {
  return axios.get(`${BASE_URL}/api/${API_VERSION}/accounts/${accountId}/settings`);
}
