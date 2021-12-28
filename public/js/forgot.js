const slidePage = document.querySelector(".slide-page");
const nextBtnSec = document.querySelector(".next-1");
const prevBtnThird = document.querySelector(".prev-2");
const submitBtn = document.querySelector(".submit");

let current = 2;
let counter = 0;
$(".err-msg").css("display", "none");
$(".err-msg3").css("display", "none");

$(document).ready(function () {
  $(".firstNext").on("click", function (e) {
    e.preventDefault();
    const eORp = $("#eORp").val();

    $.ajax({
      url: "/sleekskincare/forgot-password",
      contentType: "application/json",
      method: "POST",
      data: JSON.stringify({ eORp }),
      success: function (res) {
        if (res.msg.length > 0) {
          $("#err").html(res.msg);
          $(".err-msg").css("display", "block");
        } else {
          slidePage.style.marginLeft = "-37%";
          current += 1;
          counter = 5;
        }
      },
    });
  });
});

// $(".next-1").on("click", function (e) {
//   e.preventDefault();
//   const email = $("#email").val(),
//     area = $("#area").val(),
//     position = $("#position").val(),
//     fname = $("#fname").val(),
//     lname = $("#lname").val();

//   $.ajax({
//     url: "/sleekskincare/signup-details2",
//     method: "POST",
//     contentType: "application/json",
//     enctype: "multipart/form-data",
//     data: JSON.stringify({ email, area, position, fname, lname }),
//     success: function (res) {
//       if (res.status == "err") {
//         $("#err-all").html(res.msg);
//         $(".err-msg3").css("display", "block");
//       } else {
//         slidePage.style.marginLeft = "-70%";
//         bullet[current - 1].classList.add("active");
//         progressText[current - 1].classList.add("active");
//         current += 1;
//       }
//     },
//   });
// });

// $(document).ready(function () {
//   $(".next-2").on("click", function (e) {
//     e.preventDefault();
//     const email = $("#email").val(),
//       area = $("#area").val(),
//       phoneno = $("#phoneno").val(),
//       position = $("#position").val(),
//       pass1 = $("#pass1").val(),
//       pass2 = $("#pass2").val(),
//       fname = $("#fname").val(),
//       lname = $("#lname").val();

//     $.ajax({
//       method: "POST",
//       data: {
//         email,
//         area,
//         phoneno,
//         position,
//         pass1,
//         pass2,
//         lname,
//         fname,
//       },
//       url: "/sleekskincare/signup-details3",
//       success: function (res) {
//         if (res.msg.length > 0) {
//           $("#err-pass").html(res.msg);
//           $(".err-msg4").css("display", "block");
//         } else {
//           window.location.href = "/sleekskincare";
//         }
//       },
//     });
//   });
// });

const hide2 = document.querySelector(".hidden-notrecive");
const hide = document.querySelector(".hidden-resend");
const timer = document.getElementById("timer");
const hid = document.querySelector(".enter-label3");

hide.classList.add("hide");
hide2.classList.add("hide");
setInterval(function () {
  counter--;
  if (counter >= 0) {
    timer.innerHTML = counter;
  }
  if (counter === 0) {
    hid.remove();
    hide.classList.remove("hide");
    hide2.classList.remove("hide");
  }
}, 1000);
// const noneClose = document.querySelector(".modal-close2");
// const modalNone = document.querySelector(".modal-none");
// $(document).ready(function () {
//   $("#resend").on("click", function (e) {
//     e.preventDefault();
//     const pho = $("#phoneno").val();
//     $.ajax({
//       method: "POST",
//       data: { pho },
//       url: "/sleekskincare/resend",
//       success: function (res) {
//         modalNone.classList.add("bg-active2");
//       },
//     });
//   });
// });

// noneClose.addEventListener("click", function () {
//   modalNone.classList.remove("bg-active2");
// });
