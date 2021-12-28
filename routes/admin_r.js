const express = require("express");
const router = express.Router();
const admin = require("../controllers/admin_c");

// ----------------CRUD Product------------------
/*-- ======== Read ======= --*/

router.get("/admin/add-product", admin.isLoggedIn, admin.get_product);
router.post("/admin/add-product", admin.isLoggedIn, admin.post_product);

router.get("/admin/delete/:id", admin.isLoggedIn, admin.delete_product);

/*-- ======== All products ======= --*/

router.get("/admin/all-product", admin.isLoggedIn, admin.get_all);
router.get("/admin/all-product-render", admin.isLoggedIn, admin.get_all_prod);
router.get("/admin/edit-product/:id", admin.isLoggedIn, admin.get_edit_prod);
router.post("/admin/active-product", admin.isLoggedIn, admin.get_active_prod);
router.post("/admin/number-rows", admin.isLoggedIn, admin.post_rows);
router.post("/admin/sort-by", admin.isLoggedIn, admin.post_sort);
router.post("/admin/search", admin.isLoggedIn, admin.post_search);
router.delete("/admin/delete/:id", admin.isLoggedIn, admin.get_delete_prod);

router.post("/admin/search-nav", admin.isLoggedIn, admin.post_search_nav);
/*-- ======== All products ======= --*/
router.get("/admin/all-orders", admin.isLoggedIn, admin.get_orders);

router.get("/admin/users", admin.isLoggedIn, admin.get_users);
router.get("/admin/add-user", admin.isLoggedIn, admin.get_add_user);
router.post("/admin/add-user", admin.isLoggedIn, admin.post_add_user);
// router.post("/admin/number-rows", admin.rows);
/*-- ======== Create ======= --*/
router.post("/admin/product", admin.isLoggedIn, admin.prod_create);

router.get("/admin/all-orders-render", admin.isLoggedIn, admin.get_all_orders);
router.post("/admin/active-order", admin.isLoggedIn, admin.get_active_orders);
router.get("/admin/all-toship", admin.isLoggedIn, admin.get_toship);
router.get("/admin/all-toreceive", admin.isLoggedIn, admin.get_toreceive);
router.get("/admin/all-completed", admin.isLoggedIn, admin.get_completed);
router.get("/admin/all-cancelled", admin.isLoggedIn, admin.get_cancelled);

/*-- ========================== --*/

router.post("/admin/accept-order", admin.isLoggedIn, admin.post_accept);
router.post("/admin/toreceive-order", admin.isLoggedIn, admin.post_toreceive);
/*-- ======== Logout ======= --*/
router.get("/sleekskincare/logout", admin.get_logout);
/*-- ========================== --*/

module.exports = router;
