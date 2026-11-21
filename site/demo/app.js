// Demo app for the Routelark test page. All addresses and keys are made up.
var API = "/api/v2";
var userId = 42;

function loadUser() { return fetch("/api/v2/users/" + userId); }
function removeUser() { return fetch("/api/v2/users/" + userId, { method: "DELETE", headers: { Authorization: "Bearer " + token() } }); }
function createOrder() { return axios.post("/api/v2/orders", { price: 10, role: "user", items: [] }); }
function search(q) { return fetch(`${API}/search?q=${q}&redirect=/home`); }
function legacy() { var x = new XMLHttpRequest(); x.open("GET", "/api/legacy/export?file=report.csv"); return x; }
function live() { return new WebSocket("wss://ws.shop.example/socket"); }

var routes = [{ path: "/admin/users", component: "AdminUsers" }, { path: "/internal/metrics", component: "Metrics" }];
var docs = "./openapi.json";
var bucket = "https://shop-uploads.s3.eu-west-1.amazonaws.com/avatars/";
var staging = "http://10.20.0.5:8080/health";

function token() { return localStorage.getItem("auth_token"); }
function isAllowed(user) { return user.isAdmin === true; }

// Risky spots for the Code section
function showWelcome() { document.getElementById("out").innerHTML = decodeURIComponent(location.hash.slice(1)); }
window.addEventListener("message", function (e) { if (e.data && e.data.html) document.getElementById("out").innerHTML = e.data.html; });

// Browser data: a JWT (alg none, no exp) and cookies
localStorage.setItem("auth_token", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJEZW1vIFVzZXIifQ.");
localStorage.setItem("cart", JSON.stringify({ items: [{ sku: "A-100", qty: 2 }], total: 1990 }));
document.cookie = "sid=4f9c2d7e1a6b4c3d8e5f; path=/";
document.cookie = "theme=dark; path=/; max-age=2592000";

document.getElementById("ping").addEventListener("click", function () {
  fetch("demo/api/profile.json?expand=orders").then(function (r) { return r.json(); }).then(function (j) { document.getElementById("out").textContent = "Response: " + j.name; });
});
//# sourceMappingURL=app.js.map
