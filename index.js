const express = require("express");
const db = require("./routes/db-config");
const app = express();
const route = require("./routes/auth");

const cookie = require("cookie-parser");
const PORT = process.env.PORT || 5000;
app.use("/js", express.static(__dirname + "./public/js"));
app.use("/css", express.static(__dirname + "./public/css"));
app.set("view engine", "ejs");
app.set("views", "./views");
app.use(cookie());
app.use(express.json());
db.connect((err) => {
  if (err) throw err;
  console.log("database connected");
});
app.use("/", require("./routes/pages"));
app.use(route);
app.listen(
  PORT,
  console.log(
    ` Servever Listening to ${process.env.NODE_ENV} mode on port ${PORT} `
  )
);
