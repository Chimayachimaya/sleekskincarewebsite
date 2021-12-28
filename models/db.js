const mysql = require("mysql");
require("dotenv").config();

const db = mysql.createConnection({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.on("error", function (err) {
  console.log(err);
  console.log("No connection to your DB");
});

module.exports = db;
