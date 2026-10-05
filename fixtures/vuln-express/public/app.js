// DOM XSS: URL fragment flows into innerHTML.
(function () {
  var name = decodeURIComponent(location.hash.slice(1) || "guest");
  document.getElementById("greeting").innerHTML = "Hello " + name;
  localStorage.setItem("authToken", "demo-token-not-secret");
})();
//# sourceMappingURL=app.js.map
