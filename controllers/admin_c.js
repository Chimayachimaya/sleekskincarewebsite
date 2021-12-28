const db = require("../models/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");

/*-- ======== Reusable Function ======= --*/

let createCookies = (id, res, to) => {
  const token = jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  res.cookie("jwt", token, cookieOptions);
  res.redirect(to);
};

/*-- ========================== --*/

/*-- ======== Home Page ======= --*/

//Create
exports.prod_create = (req, res) => {
  const { prod_name, price, prod_qty, prod_details, category, expiration } =
    req.body;
  let prod_img;
  let uploadPath;

  // for images
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send("No files were uploaded.");
  }

  prod_img = req.files.prod_imgs;
  uploadPath = "upload/products/" + prod_img.name;

  prod_img.mv(uploadPath, function (err) {
    if (err) return res.status(500).send(err);
  });

  // --------

  db.query(
    "INSERT INTO tblproduct SET prod_name = ?, price = ?, prod_qty = ?, prod_img = ?, prod_details = ?, prod_categories = ?, expiration = ?",
    [
      prod_name,
      price,
      prod_qty,
      prod_img.name,
      prod_details,
      category,
      expiration,
    ],
    (err, rowsProd) => {
      if (!err) {
        db.query(
          "INSERT INTO tblratings SET prods_id = ?",
          [rowsProd.insertId],
          (err, rows) => {
            if (!err) {
              res.render("admin/product", {
                title: "Admin | Product",
              });
            } else {
              console.log(err);
            }
          }
        );
      } else {
        console.log(err);
      }
    }
  );
};

// Get
/*-- ========================== --*/

// Get
exports.get_product = async (req, res) => {
  if (req.user) {
    res.render("admin/addproduct", {
      title: "Admin | Add Product",
    });
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.post_product = (req, res) => {
  const {
    prod_name,
    prod_details,
    category,
    price,
    prod_qty,
    expiration,
    prod_status,
  } = req.body;

  let prod_img;
  let uploadPath;

  // for images
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send("No files were uploaded.");
  }

  prod_img = req.files.prod_imgs;
  uploadPath = "upload/products/" + prod_img.name;

  prod_img.mv(uploadPath, function (err) {
    if (err) return res.status(500).send(err);
  });

  // --------

  db.query(
    "INSERT INTO tblproduct SET prod_name = ?, price = ?, prod_qty = ?, prod_img = ?, prod_details = ?, prod_categories = ?, expiration = ?,prod_status=? ",
    [
      prod_name,
      price,
      prod_qty,
      prod_img.name,
      prod_details,
      category,
      expiration,
      prod_status,
    ],
    (err, rowsProd) => {
      if (!err) {
        db.query(
          "INSERT INTO tblratings SET prods_id = ?",
          [rowsProd.insertId],
          (err, rows) => {
            if (!err) {
              res.redirect("/admin/add-product");
            } else {
              console.log(err);
            }
          }
        );
      } else {
        console.log(err);
      }
    }
  );
};
exports.delete_product = (req, res) => {
  try {
    //deleting cart item
    db.query(
      "DELETE FROM tblratings WHERE prods_id = ?",
      [parseInt(req.params.id)],
      (error, cart) => {
        if (error) {
          console.log(error);
        } else {
          db.query(
            "DELETE FROM tblproduct WHERE prod_id = ?",
            [parseInt(req.params.id)],
            (error, cart) => {
              if (error) {
                console.log(error);
              } else {
                res.redirect("/admin/all-product");
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

exports.get_all = (req, res) => {
  if (req.user) {
    db.query(
      "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct",
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          res.render("admin/allproducts", {
            title: "Admin | All Product",
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_edit_prod = (req, res) => {
  if (req.user) {
    db.query(
      "SELECT * FROM tblproduct WHERE prod_id = ?",
      [req.params.id],
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          res.render("admin/editproduct", {
            title: "Admin | Edit Product",
            editProd: results,
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};
exports.get_delete_prod = (req, res) => {
  db.query(
    "DELETE FROM tblproduct WHERE prod_id = ?",
    [req.params.id],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ status: "success" });
      }
    }
  );
};

exports.get_active_prod = (req, res) => {
  if (req.user) {
    const { radioValue } = req.body;

    if (radioValue == "all") {
      db.query(
        "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct",
        (error, body) => {
          if (error) {
            console.log(error);
          } else {
            res.send({ body });
            console.log(body);
          }
        }
      );
    } else {
      db.query(
        "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct WHERE prod_status= ?",
        [radioValue],
        (error, body) => {
          if (error) {
            console.log(error);
          } else {
            res.send({ body });
          }
        }
      );
    }
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_active_orders = (req, res) => {
  if (req.user) {
    const { radioValue } = req.body;

    if (radioValue == "all") {
      db.query(
        "SELECT * FROM tblorders JOIN tblcustomer ON tblorders.customer_id =tblcustomer.customer_id ORDER BY order_date DESC",
        (error, body) => {
          if (error) {
            console.log(error);
          } else {
            res.send({ body });
          }
        }
      );
    } else {
      db.query(
        "SELECT * FROM tblproduct WHERE prod_status= ?",
        [radioValue],
        (error, body) => {
          if (error) {
            console.log(error);
          } else {
            res.send({ body });
          }
        }
      );
    }
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_all_prod = (req, res) => {
  if (req.user) {
    db.query(
      "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct",
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          res.send({ results });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.post_rows = (req, res) => {
  const { rows, sort } = req.body;

  let sql =
    "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct " +
    sorting(sort) +
    " LIMIT ?";
  sql = sql.replace(/"/g, "");
  db.query(sql, [parseInt(rows)], (error, body) => {
    if (error) {
      console.log(error);
    } else {
      res.send({ body });
    }
  });
};

exports.post_sort = (req, res) => {
  let { sort, rows } = req.body;
  let sql;
  if (!rows) {
    sql =
      "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct " +
      sorting(sort);
  } else {
    sql =
      "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct " +
      sorting(sort) +
      " LIMIT " +
      parseInt(rows);
  }

  sql = sql.replace(/"/g, "");
  db.query(sql, (error, body) => {
    if (error) {
      console.log(error);
    } else {
      res.send({ body });
    }
  });
};

exports.post_search = (req, res) => {
  let { search } = req.body;
  db.query(
    "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct WHERE prod_name LIKE ? OR prod_categories LIKE ?",
    ["%" + search + "%", "%" + search + "%"],
    (error, body) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ body });
      }
    }
  );
};
exports.post_search_nav = (req, res) => {
  let { search, radioValue } = req.body;
  db.query(
    "SELECT *, DATE_FORMAT(expiration, '%m/%d/%Y') AS exp FROM tblproduct WHERE prod_name LIKE ? OR prod_categories LIKE ?",
    ["%" + search + "%", "%" + search + "%"],
    (error, body) => {
      if (error) {
        console.log(error);
      } else {
        let bodys = body.filter(function (bod) {
          return bod.prod_status == radioValue;
        });

        res.send({ body: bodys });
      }
    }
  );
};

function sorting(sort) {
  let order = "";
  if (sort == "Product name A-Z") {
    order = "ORDER BY prod_name ASC";
  } else if (sort == "Product name Z-A") {
    order = "ORDER BY prod_name DESC";
  } else if (sort == "Product category (face only)") {
    order = "WHERE prod_categories = 'face'";
  } else if (sort == "Product category (body only)") {
    order = "WHERE prod_categories = 'body'";
  }
  return order;
}

exports.get_orders = (req, res) => {
  if (req.user) {
    db.query(
      "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblcustomer ON tblcustomer.customer_id = tblorders.customer_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id ORDER BY tblorderdetails.created_at DESC",
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          results = insert.reduce(function (r, a) {
            r[a.order_id] = r[a.order_id] || [];
            r[a.order_id].push(a);
            return r;
          }, Object.create(insert));
          // Object.entries(results).forEach(([key, value]) => {
          //   console.log(value[0].order_id);
          // });

          res.render("admin/order", {
            title: "Admin | All Orders",
            allOrders: results,
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_users = (req, res) => {
  if (req.user) {
    db.query("SELECT * FROM tbladmin", (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.render("admin/user", {
          title: "Admin | All Users",
        });
      }
    });
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_add_user = (req, res) => {
  if (req.user) {
    db.query("SELECT * FROM tbladmin", (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.render("admin/addUser", {
          title: "Admin | Add User",
        });
      }
    });
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.post_add_user = async (req, res) => {
  const { name, contact, email, password } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  db.query(
    "INSERT INTO tbladmin SET full_name=?, contact=?, email_address=?, password=?",
    [name, contact, email, hashedPassword],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        const id = results.insertId;
        db.query(
          "INSERT INTO roles SET admin_id=?, roles=?",
          [id, "Admin"],
          (error, results) => {
            if (error) {
              console.log(error);
            } else {
              createCookies(id, res, "/admin/users");
            }
          }
        );
      }
    }
  );
};

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
        "SELECT * FROM tbladmin WHERE admin_id = ?",
        [decoded.id],
        (error, result) => {
          if (!result) {
            //there is no user
            return next();
          }
          //get the user info
          req.user = result[0];
          return next();
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

/*-- ======== Logout ======= --*/
exports.get_logout = (req, res) => {
  res.cookie("jwt", "logout", {
    expires: new Date(Date.now() + 2 * 1000),
    httpOnly: true,
  });

  login(res);
};
/*-- ========================== --*/

function login(res) {
  res.render("client/login", {
    title: "Log In",
    user: "",
    message: "",
    cartTotal: "",
  });
}

// "UPDATE tblorders SET order_status = ?, confirm_date=? WHERE order_id = ?",
// ["Accept", Math.floor(Date.now() / 1000), ords],
exports.post_accept = (req, res) => {
  const { ords } = req.body;
  db.query(
    "UPDATE tblorders SET order_status = ? WHERE order_id = ?",
    ["Accept", ords],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ status: "success" });
        // db.query(
        //   "SELECT * FROM tblorderdetails JOIN tblproduct ON tblproduct.prod_id = tblorderdetails.prod_id WHERE order_id = ?",
        //   [ords],
        //   (error, results2) => {
        //     if (error) {
        //       console.log(error);
        //     } else {

        //     }
        //   }
        // );
      }
    }
  );
};

exports.post_toreceive = (req, res) => {
  const { ords } = req.body;
  db.query(
    "UPDATE tblorders SET order_status = ? WHERE order_id = ?",
    ["Completed", ords],
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        res.send({ status: "success" });
        // db.query(
        //   "SELECT * FROM tblorderdetails JOIN tblproduct ON tblproduct.prod_id = tblorderdetails.prod_id WHERE order_id = ?",
        //   [ords],
        //   (error, results2) => {
        //     if (error) {
        //       console.log(error);
        //     } else {

        //     }
        //   }
        // );
      }
    }
  );
};
exports.get_all_orders = (req, res) => {
  if (req.user) {
    db.query(
      "SELECT * FROM tblorders JOIN tblcustomer ON tblorders.customer_id =tblcustomer.customer_id ORDER BY order_date DESC",
      (error, results) => {
        if (error) {
          console.log(error);
        } else {
          res.send({ results });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_toship = (req, res) => {
  if (req.user) {
    db.query(
      "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblcustomer ON tblcustomer.customer_id = tblorders.customer_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? ORDER BY tblorderdetails.created_at DESC",
      ["Pending"],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          results = insert.reduce(function (r, a) {
            r[a.order_id] = r[a.order_id] || [];
            r[a.order_id].push(a);
            return r;
          }, Object.create(insert));

          res.render("admin/toship", {
            title: "Admin | All Orders",
            allOrders: results,
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_toreceive = (req, res) => {
  if (req.user) {
    db.query(
      "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblcustomer ON tblcustomer.customer_id = tblorders.customer_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? ORDER BY tblorderdetails.created_at DESC",
      ["Accept"],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          results = insert.reduce(function (r, a) {
            r[a.order_id] = r[a.order_id] || [];
            r[a.order_id].push(a);
            return r;
          }, Object.create(insert));

          res.render("admin/toreceive", {
            title: "Admin | All Orders",
            allOrders: results,
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};

exports.get_completed = (req, res) => {
  if (req.user) {
    db.query(
      "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblcustomer ON tblcustomer.customer_id = tblorders.customer_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? ORDER BY tblorderdetails.created_at DESC",
      ["Completed"],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          results = insert.reduce(function (r, a) {
            r[a.order_id] = r[a.order_id] || [];
            r[a.order_id].push(a);
            return r;
          }, Object.create(insert));

          res.render("admin/completed", {
            title: "Admin | All Orders",
            allOrders: results,
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};
exports.get_cancelled = (req, res) => {
  if (req.user) {
    db.query(
      "Select * FROM tblorders JOIN tblorderdetails ON tblorders.order_id = tblorderdetails.order_id JOIN tblcustomer ON tblcustomer.customer_id = tblorders.customer_id JOIN tblproduct ON tblorderdetails.prod_id = tblproduct.prod_id WHERE order_status=? ORDER BY tblorderdetails.created_at DESC",
      ["Cancelled"],
      (error, insert) => {
        if (error) {
          console.log(error);
        } else {
          results = insert.reduce(function (r, a) {
            r[a.order_id] = r[a.order_id] || [];
            r[a.order_id].push(a);
            return r;
          }, Object.create(insert));

          res.render("admin/cancelled", {
            title: "Admin | All Orders",
            allOrders: results,
          });
        }
      }
    );
  } else {
    // if there's no cookies exist. the home page will still render
    login(res);
  }
};
