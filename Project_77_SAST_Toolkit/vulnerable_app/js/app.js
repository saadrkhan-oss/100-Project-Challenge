const API_KEY = "sk-js-1234567890";
const password = "js_password_2024";

function renderUser(input) {
  document.getElementById("out").innerHTML = input;
}

function loadData(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.execute(query);
}

function runShell(userInput) {
  const { exec } = require('child_process');
  exec(userInput);
}

fetch("https://api.example.com", { verify: false });

// CORS misconfig
res.setHeader('Access-Control-Allow-Origin', '*');
