// Simulated large minified bundle
(function(window) {
  var modules = {};
  for (var i = 0; i < 200; i++) {
    modules["module_" + i] = function(id) {
      return fetch("https://api-cluster-" + i + ".example.com/api/v1/resource/" + id, {
        headers: { "Authorization": "Bearer token_" + i }
      });
    };
  }
  window.__APP_MODULES__ = modules;
})(window);
