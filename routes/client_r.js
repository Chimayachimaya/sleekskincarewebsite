const express = require("express");
const router = express.Router();
const client = require("../controllers/client_c");

/*-- ======== Account Page ======= --*/
router.get("/sleekskincare/myaccount", client.isLoggedIn, client.get_account);
router.post("/sleekskincare/myaccount", client.isLoggedIn, client.post_account);
router.post("/sleekskincare/validation", client.isLoggedIn, client.post_valid);
/*-- ========================== --*/

/*-- ======== Login Page ======= --*/
router.get("/sleekskincare/login", client.get_login);
router.get("/sleekskincare/forgot-password", client.get_forgot);
router.post("/sleekskincare/login", client.post_login);
router.post("/sleekskincare/forgot-password", client.post_forgot);
/*-- ========================== --*/

/*-- ======== Signup Page ======= --*/
router.get("/sleekskincare/signup", client.get_signup);
router.post("/sleekskincare/signup", client.post_signup);
/*-- ========================== --*/

/*-- ======== Signup OTP Page ======= --*/
router.get("/sleekskincare/signup-details", client.get_signupDetails);
router.post("/sleekskincare/signup-details1", client.post_signupDetails1);
router.post("/sleekskincare/signup-details2", client.post_signupDetails2);
router.post("/sleekskincare/signup-details3", client.post_signupDetails3);
router.post("/sleekskincare/resend", client.post_resend);
/*-- ========================== --*/

/*-- ======== Product Details Page ======= --*/
router.get(
  "/sleekskincare/product-details/:id",
  client.isLoggedIn,
  client.get_details
);
router.post(
  "/sleekskincare/product-details/:id",
  client.isLoggedIn,
  client.post_details
);

router.post(
  "/sleekskincare/product-details/cart/:id",
  client.isLoggedIn,
  client.post_details
);
/*-- ========================== --*/

/*-- ======== Cart Page ======= --*/
router.get("/sleekskincare/your-order", client.isLoggedIn, client.get_cart);
// router.post("/sleekskincare/your-order", client.isLoggedIn, client.post_order);
router.get(
  "/sleekskincare/your-order/delete/:id",
  client.isLoggedIn,
  client.delete_cart
);
router.get(
  "/sleekskincare/your-order/update/:id/:quantity",
  client.isLoggedIn,
  client.update_cart
);
router.post("/sleekskincare/your-order", client.isLoggedIn, client.post_cart);

/*-- ========================== --*/

/*-- ======== Home Page ======= --*/
router.get("/sleekskincare", client.isLoggedIn, client.get_home);
router.post("/sleekskincare", client.isLoggedIn, client.post_home);

/*-- ========================== --*/

/*-- ======== Search Page ======= --*/
router.get("/sleekskincare/search", client.isLoggedIn, client.get_search);

/*-- ========================== --*/

/*-- ======== Checkout Page ======= --*/
router.get("/sleekskincare/checkout", client.isLoggedIn, client.get_checkout);
router.get(
  "/sleekskincare/checkout-render-address",
  client.isLoggedIn,
  client.get_address
);
router.post("/sleekskincare/checkout", client.isLoggedIn, client.post_checkout);
router.post("/sleekskincare/address", client.isLoggedIn, client.post_address);
/*-- ========================== --*/

/*-- ======== Payment Page ======= --*/
router.get("/sleekskincare/payment", client.isLoggedIn, client.get_payment);
/*-- ========================== --*/

/*-- ======== Purchase Page ======= --*/
router.get("/sleekskincare/mypurchase", client.isLoggedIn, client.get_purchase);
router.get(
  "/sleekskincare/mypurchase/toship",
  client.isLoggedIn,
  client.get_toship
);
router.get(
  "/sleekskincare/mypurchase/toreceive",
  client.isLoggedIn,
  client.get_toreceive
);
router.get(
  "/sleekskincare/mypurchase/completed",
  client.isLoggedIn,
  client.get_completed
);
router.get(
  "/sleekskincare/mypurchase/cancelled",
  client.isLoggedIn,
  client.get_cancelled
);
router.post(
  "/sleekskincare/mypurchase",
  client.isLoggedIn,
  client.post_purchase
);
router.post(
  "/sleekskincare/mypurchase/toship",
  client.isLoggedIn,
  client.post_toship
);
/*-- ========================== --*/

/*-- ======== Logout ======= --*/
router.get("/sleekskincare/logout", client.get_logout);
/*-- ========================== --*/

module.exports = router;
