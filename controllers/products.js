// const pool = require("../models/db");

// /*-----------------Create---------------*/
// exports.create = (req, res) => {
//   pool.getConnection((err, connection) => {
//     if (err) throw err;

//     const params = req.body;
//     connection.query(
//       "INSERT INTO sleek_products SET ?",
//       params,
//       (err, rows) => {
//         connection.release();
//         if (!err) {
//           res.send(`Successfully added.`);
//         } else {
//           console.log(err);
//         }

//         console.log("The data from sleek products table are: \n", rows);
//       }
//     );
//   });
// };
// /*--------------------------------------*/

// /*-----------------Read-----------------*/
// exports.read = (req, res) => {
//   pool.getConnection((err, connection) => {
//     if (err) throw err;
//     console.log("connected as id " + connection.threadId);
//     connection.query("SELECT * from sleek_products", (err, rows) => {
//       connection.release(); // return the connection to pool

//       if (!err) {
//         res.send(rows);
//       } else {
//         console.log(err);
//       }

//       // if(err) throw err
//       console.log("The data from sleek products table are: \n", rows);
//     });
//   });
// };

// /*--------------------------------------*/

// /*-----------------Read by ID-----------*/
// exports.read_id = (req, res) => {
//   pool.getConnection((err, connection) => {
//     if (err) throw err;
//     connection.query(
//       "SELECT * FROM sleek_products WHERE product_id = ?",
//       [req.params.id],
//       (err, rows) => {
//         connection.release();
//         if (!err) {
//           res.send(rows);
//         } else {
//           console.log(err);
//         }

//         console.log("The data from sleek products table are: \n", rows);
//       }
//     );
//   });
// };
// /*--------------------------------------*/

// /*-----------------Update---------------*/
// exports.update = (req, res) => {
//   pool.getConnection((err, connection) => {
//     if (err) throw err;
//     console.log(`connected as id ${connection.threadId}`);

//     const { product_id, product_name, price, quantity } = req.body;

//     connection.query(
//       "UPDATE sleek_products SET product_name = ?, price = ?, quantity = ? WHERE product_id = ?",
//       [product_name, price, quantity, product_id],
//       (err, rows) => {
//         connection.release();

//         if (!err) {
//           res.send(`The record ID ${product_id} has been update.`);
//         } else {
//           console.log(err);
//         }
//       }
//     );

//     console.log(req.body);
//   });
// };
// /*--------------------------------------*/

// /*-----------------Delete by ID---------*/
// exports.delete = (req, res) => {
//   pool.getConnection((err, connection) => {
//     if (err) throw err;
//     connection.query(
//       "DELETE FROM sleek_products WHERE product_id = ?",
//       [req.params.id],
//       (err, rows) => {
//         connection.release();
//         if (!err) {
//           res.send(`The record ID ${[req.params.id]} has been removed.`);
//         } else {
//           console.log(err);
//         }
//         console.log("The data from sleek products table are: \n", rows);
//       }
//     );
//   });
// };
// /*--------------------------------------*/
