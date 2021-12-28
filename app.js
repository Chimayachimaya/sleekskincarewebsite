const express = require("express");
const bodyParser = require("body-parser");
const client = require("./routes/client_r");
const admin = require("./routes/admin_r");
const prod = require("./routes/products");
const fileUpload = require("express-fileupload");
const cookieParser = require("cookie-parser");
const path = require("path");
const { allData, address } = require("addresspinas");

// All sensitive variables are kept here
require("dotenv").config();

// Init app
const app = express();

// View engine setup
app.set("view engine", "ejs");

// Express fileUpload middleware
app.use(fileUpload());

// Express cookies middleware
app.use(cookieParser());

// Set public folder
app.use(express.static(path.join(__dirname, "public")));

// Set upload folder
app.use(express.static(path.join(__dirname, "upload")));

// parse application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

// parse application/json
app.use(express.json());

// Routes
app.use(client);
app.use(admin);
app.use(prod);

app.get("/", (req, res) => {
  res.redirect("/sleekskincare");
});
console.log(address);

// Listen on enviroment port 3000
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}`));
