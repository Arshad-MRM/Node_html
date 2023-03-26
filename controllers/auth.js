const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { promisify } = require("util");
const dotenv = require("dotenv").config();

//database connect
const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

//Login the user
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(404).json({
        success: false,
        message: "Please Provide an email and password",
      });
    }
    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        console.log(results);
        if (
          !results ||
          !(await bcrypt.compare(password, results[0].password))
        ) {
          res.status(404).json({
            success: false,
            message: "Email or Password is incorrect",
          });
        } else {
          const id = results[0].id;

          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
          });

          console.log("token: " + token);

          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true,
          };
          res.cookie("userSave", token, cookieOptions);
          res.status(200).json({
            success: true,
            message: "User has been logged In",
          });
        }
      }
    );
  } catch (err) {
    console.log("line 61");
    console.log(err);
  }
};

//register the user
exports.register = (req, res) => {
  console.log(req.body);
  const { email, password, passwordConfirm } = req.body;
  db.query(
    "SELECT email from users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.log(err);
        return res.status(404).json({
          success: false,
          message: "Bad sql queried!!! ",
        });
      } else {
        if (results.length > 0) {
          //console.log("11");
          return res.status(404).json({
            success: false,
            message: "The email is already in use",
          });
        } else if (password != passwordConfirm) {
          console.log("password dont match");
          return res.status(404).json({
            success: false,
            message: "Password don't match",
          });
        }
      }

      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);

      db.query(
        "INSERT INTO users SET ?",
        { email: email, password: hashedPassword },
        (err, results) => {
          if (err) {
            console.log(err);
          } else {
            return res.status(201).json({
              success: true,
              message: "User registered",
            });
          }
        }
      );
    }
  );
};

exports.isLoggedIn = async (req, res, next) => {
  console.log("----------*");
  if (req.cookies.userSave) {
    console.log("12");
    try {
      // 1. Verify the token
      const decoded = await promisify(jwt.verify)(
        req.cookies.userSave,
        process.env.JWT_SECRET
      );
      console.log(decoded);
      console.log("13");

      // 2. Check if the user still exist
      db.query(
        "SELECT * FROM users WHERE id = ?",
        [decoded.id],
        (err, results) => {
          console.log(results);
          if (!results) {
            console.log("14");
            return next();
          }
          req.user = results[0];
          return next();
        }
      );
    } catch (err) {
      console.log("15");
      console.log(err);
      return next();
    }
  } else {
    console.log("16");
    next();
  }
};

//logout
exports.logout = (req, res) => {
  res.cookie("userSave", "logout", {
    expires: new Date(Date.now() + 2 * 1000),
    httpOnly: true,
  });
  res.status(200).json({
    success: true,
    message: "logged Out!!!",
  });
};
