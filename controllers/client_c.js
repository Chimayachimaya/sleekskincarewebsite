const db = require("../models/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
require("dotenv").config();
// const messagebird = require("messagebird")("zTuEV2Uw8PRbtbcXKgjrfplyb");

const twilio = require("twilio")(process.env.ACCOUNTSID, process.env.AUTHTOKEN);

/*-- ======== Reusable Function ======= --*/

let createCookies = (id, res) => {
  const token = jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  return res.cookie("jwt", token, cookieOptions);
};

/*-- ========================== --*/

/*-- ======== log In Page ======= --*/

//Render The Login Page
exports.get_login = (req, res) => {
  res.render("client/login", {
    title: "Log In",
    user: "",
    cartTotal: "",
  });
};

//Log in for existing user
exports.post_login = (req, res) => {
  const { email, password } = req.body;
  //if the email and password input fields are empty
  if (!email || !password) {
    res.send({ msg: "Please fill out all the fields" });
  } else {
    //check the email from the database if they are exist
    db.query(
      "SELECT * FROM roles JOIN tblcustomer ON roles.customer_id = tblcustomer.customer_id WHERE customer_email = ?",
      [email],
      async (error, results) => {
        if (error) {
          console.log(error);
        } else if (results.length > 0) {
          //if the email are already exist but the password are not same from the database this error will occur
          if (
            !results ||
            !(await bcrypt.compare(password, results[0].customer_password))
          ) {
            res.send({ msg: "Email or Password is incorrect" });
          } else {
            //if the customer are successfully login. the createCookies function will run to create a cookie from the current id of the user
            const id = results[0].customer_id;
            createCookies(id, res);
            res.send({ msg: "", admin: "false" });
          }
        } else {
          db.query(
            "SELECT * FROM roles JOIN tbladmin ON roles.admin_id = tbladmin.admin_id WHERE email_address=?",
            [email],
            async (error, adminResult) => {
              if (adminResult.length > 0) {
                //  if the email are already exist but the password are not same from the database this error will occur
                if (
                  !adminResult ||
                  !(await bcrypt.compare(password, adminResult[0].password))
                ) {
                  res.send({
                    msg: "Email or Password is incorrect",
                  });
                } else {
                  //if the admin user are successfully login. the createCookies function will run to create a cookie from the current id of the user
                  const id = adminResult[0].admin_id;
                  createCookies(id, res);
                  res.send({ msg: "", admin: "true" });
                }
              } else {
                //if the email are not exist this error will occur
                res.send({
                  msg: "Email or Password is incorrect",
                });
              }
            }
          );
        }
      }
    );
  }
};

//Render The Forgot Page
exports.get_forgot = (req, res) => {
  res.render("client/forgot", {
    title: "Log In",
    user: "",
    cartTotal: "",
  });
};

exports.post_forgot = (req, res) => {
  const { eORp } = req.body;
  if (!eORp) {
    res.send({ msg: "Phone number is required" });
  } else {
    db.query(
      "SELECT * FROM tblcustomer WHERE customer_contact = ?",
      [eORp],
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          if (results.length == 0) {
            res.send({
              msg: "No account found with that phone number.",
            });
          } else {
            res.send({ msg: "" });
          }
        }
      }
    );
  }
};
/*-- ========================== --*/

/*-- ======== Signup Page ======= --*/

//Render The Signup Page
exports.get_signup = (req, res) => {
  res.render("client/signup", {
    title: "Sign Up",
    user: "",
    cartTotal: "",
  });
};
let phone;
exports.post_signup = (req, res) => {
  const { phoneno } = req.body;
  //if phoneno field is empty
  if (!phoneno) {
    res.send({ msg: "Phone no. is required" });
  }

  //contact field must have 10 digits
  else if (phoneno.length <= 9 || phoneno.length >= 11) {
    res.send({ msg: "Phone no. must be 10 digits, with no leading zeros" });
  }
  //if the contact field are not number and not starts with the 9
  else if (isNaN(phoneno) || !phoneno.startsWith("9")) {
    res.send({ msg: "Invalid Phone no." });
  } else {
    //check if the phone are already exist from the database
    db.query(
      "SELECT customer_contact FROM tblcustomer WHERE customer_contact = ?",
      [phoneno],
      async (error, results) => {
        if (error) {
          console.log(error);
        }
        //if the email are already exist from the database this error will occur
        else if (results.length > 0) {
          res.send({ msg: "That Phone no. is already use" });
        } else {
          twilio.verify
            .services(process.env.SERVICEID)
            .verifications.create({
              to: `+63${phoneno}`,
              channel: "sms",
            })
            .then((data) => {
              res.send({ msg: "" });
            });
          phone = phoneno;
        }
      }
    );
  }
};

/*-- ========================== --*/
/*-- ======== Signup OTP Page ======= --*/

//Render The OTP Page
exports.get_signupDetails = (req, res) => {
  res.render("client/otpSignup", {
    title: "Sign Up",
    user: "",
    phoneno: phone,
    cartTotal: "",
  });
};

exports.post_signupDetails1 = (req, res) => {
  const { code, phoneno } = req.body;

  if (code.length == 0) {
    res.send({ msg: "This field is required" });
  } else {
    twilio.verify
      .services(process.env.SERVICEID)
      .verificationChecks.create({
        to: `+63${phoneno}`,
        code: code,
      })
      .then((data) => {
        console.log(data);
        if (data.status == "approved") {
          res.send({ msg: "" });
        } else if (data.status == "pending") {
          res.send({ msg: "Your verification code is incorrect" });
        }
      });
  }
};

exports.post_signupDetails2 = (req, res) => {
  const { fname, lname, email, area, position } = req.body;

  db.query(
    "SELECT customer_email FROM tblcustomer WHERE customer_email = ?",
    [email],
    async (error, results) => {
      if (
        (!email || !fname, !lname || area.length == 0 || position.length == 0)
      ) {
        res.send({
          status: "err",
          msg: "All fields are required",
        });
      } else if (fname.length < 2 || lname.length < 2) {
        res.send({
          status: "err",
          msg: "Name must be atleast 2 characters",
        });
      }
      //email field have atleast 7 characters and must have include @ .
      else if (
        email.length < 7 ||
        !email.includes("@") ||
        !email.includes(".")
      ) {
        res.send({
          status: "err",
          msg: "Enter a valid Email",
        });
      }
      //if the email are already exist from the database this error will occur
      else if (results.length > 0) {
        res.send({
          status: "err",
          msg: "That Email is already use",
        });
      } else {
        res.send({ status: "success" });
      }
    }
  );
};

exports.post_signupDetails3 = async (req, res) => {
  const { phoneno, fname, lname, email, area, position, pass1, pass2 } =
    req.body;

  if (!pass1 || !pass2) {
    res.send({ msg: "All fields are required" });
  }
  //password field should have atleast 8 characters
  else if (pass1.length <= 7) {
    res.send({ msg: "Password must be atleast 8 characters" });
  }
  //if the password and confirm password fields are not match
  else if (pass1 !== pass2) {
    res.send({ msg: "Password confirmation does not match" });
  } else {
    //this salt will add some random string that makes the hash unpredictable
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(pass1, salt);

    //all the info that the user put from the input fields will insert to tblcustomer table
    db.query(
      "INSERT INTO tblcustomer SET  customer_fname = ?, customer_lname= ?,customer_email = ?, customer_password = ?, customer_contact = ?, customer_position = ?, customer_area = ?",
      [fname, lname, email, hashedPassword, phoneno, position, area],
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          const id = results.insertId;
          db.query(
            "INSERT INTO roles SET customer_id = ?, roles=?",
            [id, "Customer"],
            (error, results) => {
              if (error) {
                console.log(error);
              } else {
                //if the user are successfully signup. the createCookies function will run and will create a cookie from the current id of the user
                createCookies(id, res);
                res.send({ msg: "" });
              }
            }
          );
        }
      }
    );
  }
};

exports.post_resend = async (req, res) => {
  const { pho } = req.body;
  twilio.verify
    .services(process.env.SERVICEID)
    .verifications.create({
      to: `+63${pho}`,
      channel: "sms",
    })
    .then((data) => {
      res.send({ msg: "" });
    });
};

/*-- ========================== --*/

/*-- ======== Product Details Page ======= --*/
let detailsFunction = (params, user, res) => {
  //Joining the tblproduct and tblratings table group by product id to get product details and rating of the specific product
  db.query(
    "SELECT prod_id, prod_name, price, prod_img, prod_categories, prod_status, prod_details ,prod_qty, score, SUM(score) AS No_Of_Reviews, COUNT(*) AS Total_No_Of_Reviews  FROM tblproduct JOIN tblratings ON tblproduct.prod_id = tblratings.prods_id  WHERE tblproduct.prod_id = ?  GROUP BY tblratings.prods_id",
    [params],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        //Joining the tblcustomer and tblratings table to get all reviews from specific product
        db.query(
          "SELECT customer_id, customer_fname, customer_lname, customer_img, customer_position, score, remarks FROM tblcustomer JOIN tblratings ON tblcustomer.customer_id = tblratings.customers_id  WHERE tblratings.prods_id = ? ORDER BY date_recorded DESC",
          [params],
          (error, RateResults) => {
            if (error) {
              console.log(error);
            } else {
              //Joining the tblproduct and tblratings table to all products (related on current product category)
              db.query(
                "SELECT prod_id, prod_name, price, prod_img, SUM(score) AS No_Of_Reviews, COUNT(*) AS Total_No_Of_Reviews FROM tblproduct JOIN tblratings ON tblproduct.prod_id = tblratings.prods_id WHERE prod_categories = ? AND prod_status=? GROUP BY tblratings.prods_id",
                [results[0].prod_categories, "Active"],
                (error, RelatedResults) => {
                  if (error) {
                    console.log(error);
                  } else {
                    db.query(
                      "SELECT tblproduct.prod_id, prod_name, price, prod_img, prod_qty, quantity FROM tblproduct JOIN tblcart ON tblproduct.prod_id = tblcart.prod_id WHERE tblcart.customer_id = ?",
                      [user.customer_id],
                      (error, cart) => {
                        if (error) {
                          console.log(error);
                        } else {
                          db.query(
                            "SELECT * FROM tblratings WHERE customers_id = ? AND prods_id = ?",
                            [user.customer_id, params],
                            (error, userCurrentRate) => {
                              if (error) {
                                console.log(error);
                              } else {
                                //the product details page will render and show all the query results from above
                                let gaga = RelatedResults;

                                const index = gaga.findIndex(
                                  (item) => item.prod_id == params
                                );
                                gaga.splice(index, 1);

                                res.render("client/product_details", {
                                  title: "Product Details",
                                  user: user,
                                  products: results,
                                  comment: RateResults,
                                  related: gaga,
                                  cartTotal: cart,
                                  userCurrentRate: userCurrentRate,
                                });
                              }
                            }
                          );
                        }
                      }
                    );
                  }
                }
              );
            }
          }
        );
        // --------------
      }
    }
  );
};

//Get
exports.get_details = (req, res) => {
  const params = req.params.id;
  try {
    if (req.user) {
      //the product details page will render and the user now can order and write reviews
      detailsFunction(params, req.user, res);
    } else {
      //if the user are not log in, the product details page will still render but they can't order and write reviews
      detailsFunction(params, "", res);
    }
  } catch (error) {
    console.log(error);
  }
};

//Post = For Writing reviews
exports.post_details = (req, res) => {
  try {
    const { rate, remarks } = req.body;
    if (req.user) {
      db.query(
        //the user reviews will insert to the tablratings table from database
        "INSERT INTO tblratings SET prods_id = ?, score = ?, remarks = ?,  customers_id = ?",
        [params, rate, remarks, req.user.customer_id],
        (error, insert) => {
          if (error) {
            console.log(error);
          } else {
            //if there's no error the page will reload
            res.redirect(`/sleekskincare/product-details/${req.params.id}`);
          }
        }
      );
    } else {
      //if the user are not login the page will direct to login page
      res.redirect("/sleekskincare/login");
    }
  } catch (error) {
    console.log(error);
  }
};

//Post = Adding Item to cart
exports.post_details = (req, res) => {
  try {
    const { quantity } = req.body;
    //if the user are already log in. the item will add to their cart
    if (req.user) {
      db.query(
        //check if the item are already exist from tblcart table
        "SELECT * FROM tblcart WHERE prod_id = ? AND customer_id = ?",
        [req.params.id, req.user.customer_id],
        (error, insert) => {
          if (error) {
            console.log(error);
          }
          //if the item are already exist, Add the new quantity from that item
          if (insert.length > 0) {
            const newQuantity =
              parseInt(insert[0].quantity) + parseInt(quantity);
            db.query(
              "UPDATE tblcart SET quantity = ? WHERE prod_id = ?",
              [newQuantity, req.params.id],
              (error, insert) => {
                if (error) {
                  console.log(error);
                } else {
                  res.redirect(
                    `/sleekskincare/product-details/${req.params.id}`
                  );
                }
              }
            );
          }
          //if the item are not exist, Add it to tblcart table
          else {
            db.query(
              "INSERT INTO tblcart SET customer_id = ?, prod_id = ?, quantity = ?",
              [req.user.customer_id, req.params.id, quantity],
              (error, insert) => {
                if (error) {
                  console.log(error);
                } else {
                  res.redirect(
                    `/sleekskincare/product-details/${req.params.id}`
                  );
                }
              }
            );
          }
        }
      );
    } else {
      //If user are not login. the page will direct to login page
      res.redirect("/sleekskincare/login");
    }
  } catch (error) {
    console.log(error);
  }
};
/*-- ========================== --*/

/*-- ======== Cart Page ======= --*/

//Get
exports.get_cart = (req, res) => {
  try {
    //if the user are log in. the cart page will render with their cart item
    if (req.user) {
      db.query(
        "SELECT prod_id, prod_name, price, prod_img, prod_status, score, SUM(score) AS No_Of_Reviews, COUNT(*) AS Total_No_Of_Reviews  FROM tblproduct JOIN tblratings ON tblproduct.prod_id = tblratings.prods_id GROUP BY tblratings.prods_id",
        (error, results) => {
          if (error) {
            console.log(error);
          } else {
            //if the user have already item on their cart, show it all
            if (req.cart.length > 0) {
              res.render("client/cart", {
                title: "Your Order",
                user: req.user,
                cartTotal: req.cart,
                cartShow: req.cart,
                products: results,
              });
            } else {
              //if they don't have any item on their cart, still show the table but with message empty basket
              res.render("client/cart", {
                title: "Your Order",
                user: req.user,
                cartTotal: "",
                cartShow: "",
                products: results,
              });
            }
          }
        }
      );
    } else {
      //if the user are not log in. it will still render the cart page but empty
      res.render("client/cart", {
        title: "Your Order",
        user: "",
        cartTotal: "",
        cartShow: "",
      });
    }
  } catch (error) {
    console.log(error);
  }
};

// exports.post_order = async (req, res, next) => {
//   try {
//     const { prodsId, quantity } = req.body;

//     console.log(prodsId);
//     // db.query(
//     //   "SELECT * FROM tblproduct WHERE prod_id IN (" + prodsId + ")",
//     //   function (err, rows) {
//     //     if (err) throw err;
//     //     console.log(rows);
//     //   }
//     // );
//   } catch (error) {
//     console.log(error);
//   }
// };

exports.delete_cart = (req, res) => {
  try {
    //deleting cart item
    db.query(
      "DELETE FROM tblcart WHERE prod_id = ?",
      [req.params.id],
      (error, cart) => {
        if (error) {
          console.log(error);
        } else {
          res.redirect("/sleekskincare/your-order");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};

exports.update_cart = (req, res) => {
  try {
    //update cart item
    db.query(
      "UPDATE tblcart SET quantity = ? WHERE prod_id = ?",
      [req.params.quantity, req.params.id],
      (error, cart) => {
        if (error) {
          console.log(error);
        } else {
          res.redirect("/sleekskincare/your-order");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};
let orderss;

exports.post_cart = (req, res) => {
  try {
    const { ordersIdFromCart, amount } = req.body;
    orderss = ordersIdFromCart;
    if (!ordersIdFromCart) {
      res.send({ status: "null" });
    } else if (req.user.customer_position == "Distributor") {
      if (20000 > parseInt(amount)) {
        res.send({ status: "kulang" });
      } else {
        res.send({ status: "success" });
      }
    } else if (req.user.customer_position == "Seller") {
      if (5000 > parseInt(amount)) {
        res.send({ status: "kulang" });
      } else {
        res.send({ status: "success" });
      }
    } else {
      res.redirect("/sleekskincare/checkout");
    }
  } catch (error) {
    console.log(error);
  }
};

/*-- ========================== --*/

/*-- ======== Home Page ======= --*/

//Render The Home Page
exports.get_home = (req, res) => {
  db.query(
    "SELECT prod_id, prod_name, price, prod_img, prod_status, score, SUM(score) AS No_Of_Reviews, COUNT(*) AS Total_No_Of_Reviews  FROM tblproduct JOIN tblratings ON tblproduct.prod_id = tblratings.prods_id WHERE prod_status=? GROUP BY tblratings.prods_id",
    ["Active"],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        db.query(
          "SELECT prod_img, score, remarks, customer_fname, customer_lname, customer_position, DATE_FORMAT(date_recorded, '%m/%d/%Y') AS date FROM tblcustomer JOIN tblratings ON tblcustomer.customer_id = tblratings.customers_id JOIN tblproduct ON tblproduct.prod_id = tblratings.prods_id ORDER BY date_recorded DESC",
          (error, resultsForRealReviews) => {
            if (error) {
              console.log(error);
            } else {
              //if there's cookies exist. the home page will render some info of the user including their cart item
              if (req.user) {
                res.render("client/index", {
                  title: "Home",
                  user: req.user,
                  products: results,
                  cartTotal: req.cart,
                  reviews: resultsForRealReviews,
                });
              } else {
                // if there's no cookies exist. the home page will still render
                res.render("client/index", {
                  title: "Home",
                  user: "",
                  products: results,
                  cartTotal: "",
                  reviews: resultsForRealReviews,
                });
              }
            }
          }
        );
      }
    }
  );
};

exports.post_home = (req, res) => {
  const { search } = req.body;

  db.query(
    "SELECT prod_id, prod_name, price, prod_img, prod_status, score, SUM(score) AS No_Of_Reviews, COUNT(*) AS Total_No_Of_Reviews  FROM tblproduct JOIN tblratings ON tblproduct.prod_id = tblratings.prods_id  WHERE prod_name LIKE ? OR prod_categories LIKE ? GROUP BY tblratings.prods_id",
    ["%" + search + "%", "%" + search + "%"],
    (error, resultsForSearch) => {
      if (error) {
        console.log(error);
      } else {
        if (req.user) {
          res.render("client/search", {
            title: "Search",
            user: req.user,
            products: resultsForSearch,
            cartTotal: req.cart,
            searchValue: search,
          });
        } else {
          // if there's no cookies exist. the home page will still render
          res.render("client/search", {
            title: "Search",
            user: "",
            products: resultsForSearch,
            cartTotal: "",
            searchValue: search,
          });
        }
      }
    }
  );
};

/*-- ========================== --*/

/*-- ======== Search Page ======= --*/

exports.get_search = (req, res) => {
  db.query(
    "SELECT prod_id, prod_name, price, prod_img, prod_status, score, SUM(score) AS No_Of_Reviews, COUNT(*) AS Total_No_Of_Reviews  FROM tblproduct JOIN tblratings ON tblproduct.prod_id = tblratings.prods_id GROUP BY tblratings.prods_id",
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        //if there's cookies exist. the home page will render some info of the user including their cart item
        if (req.user) {
          res.render("client/search", {
            title: "All Products",
            user: req.user,
            products: results,
            cartTotal: req.cart,
          });
        } else {
          // if there's no cookies exist. the home page will still render
          res.render("client/search", {
            title: "All Products",
            user: "",
            products: results,
            cartTotal: "",
          });
        }
      }
    }
  );
};
/*-- ========================== --*/

/*-- ======== Checkout Page ======= --*/

exports.get_checkout = (req, res) => {
  try {
    db.query(
      "SELECT cart_id, tblproduct.prod_id, prod_name,prod_categories, price, prod_img, prod_qty, quantity FROM tblproduct JOIN tblcart ON tblproduct.prod_id = tblcart.prod_id WHERE cart_id IN (?)",
      [orderss.split(",").map(Number)],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          db.query(
            "Select * FROM tbladdress JOIN tblcustomer ON tbladdress.customer_id = tblcustomer.customer_id WHERE tbladdress.customer_id=? ",
            [req.user.customer_id],
            (error, allDefault) => {
              if (error) {
                console.log(error);
              } else {
                res.render("client/checkout", {
                  title: "Checkout",
                  user: req.user,
                  cartTotal: req.cart,
                  cartShow: insert,
                  allDefault: allDefault,
                });
              }
            }
          );
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};

exports.get_address = (req, res) => {
  db.query(
    "SELECT * FROM tbladdress WHERE customer_id=?",
    [req.user.customer_id],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ results });
      }
    }
  );
};

exports.post_checkout = (req, res) => {
  try {
    const {
      cartId,
      qty,
      message,
      receivedDate,
      radio,
      totalp,
      prodAmount,
      prodssId,
    } = req.body;

    function randomString(strlength) {
      let random_string = "";
      let chrac = "QWERTYUIOPASDFGHJKLZXCVBNM0123456789";
      for (let i = 0; i < strlength; i++) {
        random_string += chrac.charAt(Math.floor(Math.random() * chrac.length));
      }
      return random_string;
    }

    let orderID = randomString(15);
    let query;
    let values;

    db.query(
      "DELETE FROM tblcart WHERE cart_id IN (?)",
      [prodssId],
      (error, insert) => {
        if (error) {
          console.log(error);
        }
      }
    );
    db.query(
      "INSERT INTO tblorders SET order_id = ?, customer_id =?, total_amount = ?",
      [orderID, req.user.customer_id, totalp],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          if (typeof cartId == "object") {
            query =
              "INSERT INTO tblorderdetails (order_id, prod_id, quantity, prod_amount, message) VALUES ?";
            values = Object.keys(cartId).map(function (v, i) {
              return [orderID, cartId[i], qty[i], prodAmount[i], message];
            });
            db.query(query, [values]),
              (error, insert) => {
                if (error) {
                  console.log(error);
                }
              };
          } else {
            db.query(
              "INSERT INTO tblorderdetails SET order_id=?, prod_id=?, quantity=?, prod_amount=?, message=?",
              [orderID, cartId, qty, prodAmount, message],
              (error, insert) => {
                if (error) {
                  console.log(error);
                }
              }
            );
          }

          res.redirect("/sleekskincare/mypurchase");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};

exports.post_address = (req, res) => {
  const {
    region,
    province,
    city,
    barangay,
    phonenumber,
    fullname,
    street,
    zipcode,
  } = req.body;
  if (
    !region ||
    !province ||
    !city ||
    !barangay ||
    !phonenumber ||
    !fullname ||
    !street ||
    !zipcode
  ) {
    res.send({ status: "err", msg: "All fields are required" });
  } else if (
    region == "Region" ||
    province == "Province" ||
    city == "City" ||
    barangay == "Barangay"
  ) {
    res.send({ status: "err", msg: "All fields are required" });
  } else {
    db.query(
      "INSERT INTO tbladdress SET customer_id = ?, fullname =?, phonenumber = ?, region = ?, province = ?, city =?, barangay = ?, zipcode=?, street =?",
      [
        req.user.customer_id,
        fullname,
        phonenumber,
        region,
        province,
        city,
        barangay,
        zipcode,
        street,
      ],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          db.query(
            "Select * FROM tbladdress WHERE customer_id=?",
            [req.user.customer_id],
            (error, body) => {
              if (error) {
                console.log(error);
              } else {
                res.send({
                  status: "success",
                  body,
                });
              }
            }
          );
        }
      }
    );
  }
};

/*-- ======== Payment Page ======= --*/
//Get
exports.get_payment = (req, res) => {
  res.render("client/payment", {
    title: "Payment",
    user: req.user,
    cartTotal: req.cart,
  });
};

/*-- ========================== --*/

/*-- ======== Account Page ======= --*/
//Get
exports.get_account = (req, res) => {
  res.render("client/account", {
    title: "My Account",
    user: req.user,
    cartTotal: req.cart,
  });
};

exports.post_account = async (req, res) => {
  const { fname, lname, area, email } = req.body;

  let prof_img;
  let uploadPath;
  prof_img = req.files.profile;
  //all the info that the user put from the input fields will insert to tblcustomer table
  if (!prof_img) {
    db.query(
      "UPDATE tblcustomer SET  customer_fname = ?, customer_lname= ?, customer_email = ?, customer_area = ? WHERE customer_id=?",
      [fname, lname, email, area, req.user.customer_id],
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          res.redirect("/sleekskincare/myaccount");
        }
      }
    );
  } else {
    //this will get the user profile and put it to the upload folder

    uploadPath = "upload/profiles/" + prof_img.name;

    prof_img.mv(uploadPath, function (err) {
      if (err) return res.status(500).send(err);
    });

    console.log(prof_img);

    db.query(
      "UPDATE tblcustomer SET  customer_fname = ?, customer_lname= ?, customer_email = ?, customer_area = ?, customer_img = ? WHERE customer_id=?",
      [fname, lname, email, area, prof_img.name, req.user.customer_id],
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          res.redirect("/sleekskincare/myaccount");
        }
      }
    );
  }
};

exports.post_valid = async (req, res) => {
  const { fname, lname, area, email, file1 } = req.body;
  if (
    fname == req.user.customer_fname &&
    lname == req.user.customer_lname &&
    area == req.user.customer_area &&
    email == req.user.customer_email &&
    !file1
  ) {
    res.send({ msg: "wala" });
  } else {
    res.send({ msg: "" });
  }
};
/*-- ========================== --*/

// "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE customer_id=? ORDER BY tblorderdetails.created_at DESC",

/*-- ======== Purchase Page ======= --*/
//Get

exports.get_purchase = (req, res) => {
  db.query(
    "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE customer_id=? ORDER BY tblorderdetails.created_at DESC",
    [req.user.customer_id],
    (error, insert) => {
      if (error) {
        console.log(error);
      } else {
        results = insert.reduce(function (r, a) {
          r[a.order_id] = r[a.order_id] || [];
          r[a.order_id].push(a);
          return r;
        }, Object.create(insert));

        res.render("client/purchase", {
          title: "My Purchase",
          user: req.user,
          cartTotal: req.cart,
          allOrders: results,
        });
      }
    }
  );
};

exports.post_purchase = (req, res) => {
  const { ords } = req.body;
  db.query(
    "UPDATE tblorders SET order_status = ? WHERE order_id = ?",
    ["Cancelled", ords],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ status: "success" });
      }
    }
  );
};

exports.post_toship = (req, res) => {
  const { ords } = req.body;
  db.query(
    "UPDATE tblorders SET order_status = ? WHERE order_id = ?",
    ["Cancelled", ords],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ status: "success" });
      }
    }
  );
};
exports.get_toship = (req, res) => {
  db.query(
    "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? && customer_id=? ORDER BY tblorderdetails.created_at DESC",
    ["Pending", req.user.customer_id],
    (error, insert2) => {
      if (error) {
        console.log(error);
      } else {
        results2 = insert2.reduce(function (r, a) {
          r[a.order_id] = r[a.order_id] || [];
          r[a.order_id].push(a);
          return r;
        }, Object.create(insert2));

        res.render("client/toship", {
          title: "My Purchase",
          user: req.user,
          cartTotal: req.cart,
          allPending: results2,
        });
      }
    }
  );
};

exports.get_toreceive = (req, res) => {
  db.query(
    "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? && customer_id=? ORDER BY tblorderdetails.created_at DESC",
    ["Accept", req.user.customer_id],
    (error, insert2) => {
      if (error) {
        console.log(error);
      } else {
        results2 = insert2.reduce(function (r, a) {
          r[a.order_id] = r[a.order_id] || [];
          r[a.order_id].push(a);
          return r;
        }, Object.create(insert2));

        res.render("client/toreceive", {
          title: "My Purchase",
          user: req.user,
          cartTotal: req.cart,
          allPending: results2,
        });
      }
    }
  );
};

exports.get_completed = (req, res) => {
  db.query(
    "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? && customer_id=? ORDER BY tblorderdetails.created_at DESC",
    ["Completed", req.user.customer_id],
    (error, insert2) => {
      if (error) {
        console.log(error);
      } else {
        results2 = insert2.reduce(function (r, a) {
          r[a.order_id] = r[a.order_id] || [];
          r[a.order_id].push(a);
          return r;
        }, Object.create(insert2));

        res.render("client/completed", {
          title: "My Purchase",
          user: req.user,
          cartTotal: req.cart,
          allPending: results2,
        });
      }
    }
  );
};
exports.get_cancelled = (req, res) => {
  db.query(
    "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? && customer_id=? ORDER BY tblorderdetails.created_at DESC",
    ["Cancelled", req.user.customer_id],
    (error, insert2) => {
      if (error) {
        console.log(error);
      } else {
        results2 = insert2.reduce(function (r, a) {
          r[a.order_id] = r[a.order_id] || [];
          r[a.order_id].push(a);
          return r;
        }, Object.create(insert2));

        res.render("client/cancelled", {
          title: "My Purchase",
          user: req.user,
          cartTotal: req.cart,
          allPending: results2,
        });
      }
    }
  );
};
/*-- ========================== --*/

/*-- ======== Logout ======= --*/
exports.get_logout = (req, res) => {
  res.cookie("jwt", "logout", {
    expires: new Date(Date.now() + 2 * 1000),
    httpOnly: true,
  });

  res.redirect("/sleekskincare/login");
};
/*-- ========================== --*/

/*-- ======== Check if there's cookies exist ======= --*/
exports.isLoggedIn = async (req, res, next) => {
  // See if there's someone currently log in
  if (req.cookies.jwt) {
    try {
      //1) verify the token
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );
      //2) Check if the user still exists
      db.query(
        "SELECT * FROM tblcustomer WHERE customer_id = ?",
        [decoded.id],
        (error, result) => {
          if (!result) {
            //there is no user
            return next();
          }
          //get the user info
          req.user = result[0];
          db.query(
            "SELECT cart_id, tblproduct.prod_id, prod_name, price, prod_img, prod_qty, quantity FROM tblproduct JOIN tblcart ON tblproduct.prod_id = tblcart.prod_id WHERE tblcart.customer_id = ? ORDER BY cart_id DESC",
            [req.user.customer_id],
            async (error, resultsForCart) => {
              if (error) {
                console.log(error);
              } else {
                req.cart = resultsForCart;
                return next();
              }
            }
          );
        }
      );
    } catch (error) {
      console.log(error);
      return next();
    }
  } else {
    next();
  }
};
/*-- ========================== --*/
