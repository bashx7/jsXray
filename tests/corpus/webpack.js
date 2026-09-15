(window["webpackJsonp"] = window["webpackJsonp"] || []).push([[1],{
  "api/auth": function(module, exports, __webpack_require__) {
    const API_HOST = "https://auth.internal.corp";
    exports.login = function(username, password) {
      return fetch(API_HOST + "/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": "csrf-token-12345"
        },
        body: JSON.stringify({ username, password })
      });
    };
  }
}]);
