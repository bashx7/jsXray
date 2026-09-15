function setAuthHeader(token) {
  return {
    "Authorization": "Bearer " + token,
    "X-CSRF-Token": "token-xyz-12345",
    "X-Api-Key": "apikey-prod-998877"
  };
}

const loginUrl = "/api/v1/auth/login";
const refreshTokenUrl = "/api/v1/auth/token/refresh";
const logoutUrl = "/api/v1/auth/logout";
