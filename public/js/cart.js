// // const buttonsPlus = document.querySelectorAll(".plus-btn");
// // let ins = document.getElementsByTagName("input");

// // let valueCount;
// // for (const btnPlus of buttonsPlus) {
// //   btnPlus.addEventListener("click", function () {
// //     for (const inss of ins) {
// //       if (btnPlus.name == inss.id) {
// //         valueCount = inss.value;
// //         valueCount++;
// //         inss.value = valueCount;
// //       }
// //       if (inss.value > 1) {
// //         for (const btnMinus of buttonsMinus) {
// //           if (inss.id == btnMinus.name) {
// //             btnMinus.removeAttribute("disabled");
// //           }
// //         }
// //       }
// //     }
// //     let links = btnPlus.getAttribute("href");
// //     btnPlus.setAttribute("href", links + `/${valueCount}`);
// //   });
// // }

// // let checkboxes = document.querySelectorAll(".prod-pricee");
// // let selectAll = document.getElementById("selectAll");
// // document.getElementById("item").innerHTML = "0";
// // document.getElementById("info").innerHTML = "₱ 0";
// // const checkout = document.querySelector(".checkout");

// // let orderId = [];
// // let amount = 0;
// // let howManyCheck = 0;

// // for (const checkbox of checkboxes) {
// //   checkbox.addEventListener("change", function () {
// //     if (this.checked) {
// //       amount = amount + parseInt(checkbox.value);
// //       howManyCheck++;
// //       orderId.push(checkbox.name);
// //     } else {
// //       amount = amount - parseInt(checkbox.value);
// //       howManyCheck--;
// //       orderId = orderId.filter((item) => item !== checkbox.name);
// //     }
// //     info.innerHTML = "₱ " + amount;
// //     item.innerHTML = howManyCheck;
// //     document.getElementById("IdOrdersCart").value = orderId;

// //     if (howManyCheck == checkboxes.length) {
// //       selectAll.checked = true;
// //     } else {
// //       selectAll.checked = false;
// //     }
// //   });
// // }
// // const modalBg = document.querySelector(".null-modal");
// // const modalBg2 = document.querySelector(".kulng-modal");
// // $(document).ready(function () {
// //   $(".proceed-cart").click(function () {
// //     const ordersIdFromCart = $("#IdOrdersCart").val();

// //     $.ajax({
// //       url: "/sleekskincare/your-order",
// //       contentType: "application/json",
// //       data: JSON.stringify({ ordersIdFromCart, amount }),
// //       method: "POST",
// //       success: function (res) {
// //         if (res.status == "null") {
// //           modalBg.classList.add("bg-active");
// //         } else if (res.status == "kulang") {
// //           modalBg2.classList.add("bg-active2");
// //         } else {
// //           window.location.href = "/sleekskincare/checkout";
// //         }
// //       },
// //     });
// //   });
// // });

// // const modalClose1 = document.querySelector(".done1");
// // modalClose1.addEventListener("click", function () {
// //   modalBg.classList.remove("bg-active");
// // });

// // const modalClose2 = document.querySelector(".done2");
// // modalClose2.addEventListener("click", function () {
// //   modalBg2.classList.remove("bg-active2");
// // });
// // -----------------------------------------------------------

// $(document).ready(function () {
//   $(".cart-table").on("click", "#t-delete", function (e) {
//     e.preventDefault();
//     const delProd = this.value;
//     $.ajax({
//       url: "/sleekskincare/your-order/delete",
//       contentType: "application/json",
//       data: JSON.stringify({ delProd }),
//       method: "DELETE",
//       success: function (res) {
//         let tbody = $(".cart-table");
//         tbody.html("");
//         let tbody2 = $(".cart-btns");
//         tbody2.html("");
//         if (res.cart.length == 0) {
//           tbody.append(emptyCart());
//           tbody2.append("");
//         } else {
//           let tbody = $(".cart-table");
//           tbody.html("");
//           res.cart.forEach(function (bod) {
//             tbody.append(htmlBody(bod));
//           });
//           tbody2.append(proceedBtn());
//         }
//       },
//     });
//   });
// });

// const btnP = document.querySelectorAll(".plus-btn");
// const btnM = document.querySelectorAll(".minus-btn");
// const qty = document.querySelectorAll("#quantity");
// let valueCount;

// $(document).ready(function () {
//   for (const m of btnM) {
//     $(m).on("click", function (e) {
//       e.preventDefault();
//       const prodId = m.value;
//       for (const q of qty) {
//         if (q.value <= 1) {
//           btnM.disabled = true;
//         } else {
//           if (m.value == q.name) {
//             valueCount = q.value;
//             valueCount--;
//             q.value = valueCount;
//             $.ajax({
//               url: "/sleekskincare/your-order/update",
//               contentType: "application/json",
//               data: JSON.stringify({ valueCount, prodId }),
//               method: "post",
//               success: function (res) {},
//             });
//           }
//         }
//       }
//     });
//   }
// });

// $(document).ready(function () {
//   for (const p of btnP) {
//     $(p).on("click", function (e) {
//       e.preventDefault();
//       const prodId = p.value;
//       for (const q of qty) {
//         if (p.value == q.name) {
//           valueCount = q.value;
//           valueCount++;
//           q.value = valueCount;
//           $.ajax({
//             url: "/sleekskincare/your-order/update",
//             contentType: "application/json",
//             data: JSON.stringify({ valueCount, prodId }),
//             method: "post",
//             success: function (res) {},
//           });
//         }
//       }
//     });
//   }
// });

// function htmlBody(bod) {
//   let tBody;

//   return (tBody =
//     `<div class="t-head">\
//           <div class="t-prod">Product</div>\
//           <div class="t-up">Unit Price</div>\
//           <div class="t-qty t-center">Quantity</div>\
//           <div class="t-total">Total</div>\
//           <div>Actions</div>\
//         </div>\
//         <div class="t-body">\
//           <div>\
//             <form>\
//             <input type="checkbox" name="${bod.cart_id}" class="prod-pricee" value="" />\
//            </form>\
//           </div>\
//           <div class="t-prod tflex"> \
//             <div>\
//             <a href="#">\
//             <img class="t-img" \
//                  src="/products/${bod.prod_img}"
//                  alt="${bod.prod_img}"/>
//             </a>\
//           </div>\
//             <div>\
//               <a href="#">Sleek ${bod.prod_name}</a>\
//             </div>\
//           </div>\
//             <div class="t-up">₱` +
//     bod.price +
//     `</div>\
//           <div class="t-qty tflex quantity">\
//             <div>\
//             <button class="btn minus-btn" value="${bod.prod_id}">-</button>\
//            </div>\
//            <div>\
//             <input type="text" id="quantity" value="${bod.quantity}" name="${bod.prod_id}">\
//             <input type="text" name="prodsId" value="${bod.prod_id}" hidden>\
//           </div>\
//           <div>\
//             <button  class="btn plus-btn" value="${bod.prod_id}">+</button>\
//           </div>\
//           </div>\
//             <div class="t-total t-color">\
//             <span class="new__price">₱</span>\
//           </div>\
//           <button type="button" id="t-delete" value="${bod.prod_id}">Delete</button>\
//         </div>`);
// }

// function emptyCart() {
//   let tBody;

//   return (tBody = `<div class="t-empty-basket">\
//                 <div class="cart-empty-icon">\
//                   <i class="bx bx-cart"></i>\
//                 </div>\
//                 <div class="cart-empty-section">\
//                   <p class="cart-heading">\
//                     Your basket is empty!\
//                   </p>\
//                   <div class="cart-btns">\
//                     <div class="continue__shopping">\
//                       <a href="/sleekskincare">Go Shopping Now</a>\
//                     </div>\
//                   </div>\
//               </div>\
//               </div`);
// }

// function proceedBtn() {
//   let tBody;
//   return (tBody = `
//                 <div class="t-select">\
//                   {/* <input type="checkbox" id="selectAll">\
//                   <a href="#">Select All</a>  */}\
//                 </div>\
//                 <div>\
//                    {/* <a href="#">Delete</a>  */}\
//                 </div>\
//                <div class="t-total-all">\
//                 <p>Total (<span id="item"></span> item): <span id="info"></span></p>\
//               </div>\
//                 <div class="continue__shopping">  \
//                   <input type="text" name="ordersIdFromCart" id="IdOrdersCart"  hidden> \
//                   <button class="proceed-cart"> Proceed to checkout</button>\
//                 </div>\
//               `);
// }

const buttonsPlus = document.querySelectorAll(".plus-btn");
let ins = document.getElementsByTagName("input");
const buttonsMinus = document.querySelectorAll(".minus-btn");

let valueCount;
for (const btnPlus of buttonsPlus) {
  btnPlus.addEventListener("click", function () {
    for (const inss of ins) {
      if (btnPlus.name == inss.id) {
        valueCount = inss.value;
        valueCount++;
        inss.value = valueCount;
      }
      if (inss.value > 1) {
        for (const btnMinus of buttonsMinus) {
          if (inss.id == btnMinus.name) {
            btnMinus.removeAttribute("disabled");
          }
        }
      }
    }
    let links = btnPlus.getAttribute("href");
    btnPlus.setAttribute("href", links + `/${valueCount}`);
  });
}

for (const btnMinus of buttonsMinus) {
  btnMinus.addEventListener("click", function () {
    for (const inss of ins) {
      if (inss.value <= 1) {
        if (inss.id == btnMinus.name) {
          btnMinus.removeAttribute("href");
        }
      } else {
        if (btnMinus.name == inss.id) {
          valueCount = inss.value;
          valueCount--;
          inss.value = valueCount;
          let links = btnMinus.getAttribute("href");
          btnMinus.setAttribute("href", links + `/${valueCount}`);
        }
      }
    }
  });
}

let checkboxes = document.querySelectorAll(".prod-pricee");
let selectAll = document.getElementById("selectAll");
document.getElementById("item").innerHTML = "0";
document.getElementById("info").innerHTML = "₱ 0";
const checkout = document.querySelector(".checkout");

let orderId = [];
let amount = 0;
let howManyCheck = 0;

for (const checkbox of checkboxes) {
  checkbox.addEventListener("change", function () {
    if (this.checked) {
      amount = amount + parseInt(checkbox.value);
      howManyCheck++;
      orderId.push(checkbox.name);
    } else {
      amount = amount - parseInt(checkbox.value);
      howManyCheck--;
      orderId = orderId.filter((item) => item !== checkbox.name);
    }
    info.innerHTML = "₱ " + amount;
    item.innerHTML = howManyCheck;
    document.getElementById("IdOrdersCart").value = orderId;

    if (howManyCheck == checkboxes.length) {
      selectAll.checked = true;
    } else {
      selectAll.checked = false;
    }
  });
}
const modalBg = document.querySelector(".null-modal");
const modalBg2 = document.querySelector(".kulng-modal");
$(document).ready(function () {
  $(".proceed-cart").click(function () {
    const ordersIdFromCart = $("#IdOrdersCart").val();

    $.ajax({
      url: "/sleekskincare/your-order",
      contentType: "application/json",
      data: JSON.stringify({ ordersIdFromCart, amount }),
      method: "POST",
      success: function (res) {
        if (res.status == "null") {
          modalBg.classList.add("bg-active");
        } else if (res.status == "kulang") {
          modalBg2.classList.add("bg-active2");
        } else {
          window.location.href = "/sleekskincare/checkout";
        }
      },
    });
  });
});

const modalClose1 = document.querySelector(".done1");
modalClose1.addEventListener("click", function () {
  modalBg.classList.remove("bg-active");
});

const modalClose2 = document.querySelector(".done2");
modalClose2.addEventListener("click", function () {
  modalBg2.classList.remove("bg-active2");
});
