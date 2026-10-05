(function () {
  var name = decodeURIComponent(location.hash.slice(1) || "guest");
  document.getElementById("greeting").textContent = "Hello " + name;
})();
