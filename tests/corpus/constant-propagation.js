const API = "https://api.example.com";
const PATH = "/users/";
function getUser(userId) {
  return fetch(API + PATH + userId, {
    method: "GET",
    headers: {
      Authorization: "Bearer " + token
    }
  });
}
