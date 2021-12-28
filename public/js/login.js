$(".err-login").css("display", "none");

$(".btn").on("click", function (e) {
  e.preventDefault();
  const email = $("#email").val(),
    password = $("#password").val();

  $.ajax({
    url: "/sleekskincare/login",
    method: "POST",
    contentType: "application/json",
    data: JSON.stringify({ email, password }),
    success: function (res) {
      if (res.msg.length > 0) {
        $("#err-show").html(res.msg);
        $(".err-login").css("display", "block");
      } else {
        if (res.admin == "false") {
          window.location.href = "/sleekskincare";
        } else {
          window.location.href = "/admin/all-product";
        }
      }
    },
  });
});
