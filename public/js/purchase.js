const ord = document.querySelectorAll("#bcancel");

for (const o of ord) {
  $(o).on("click", function (e) {
    e.preventDefault();
    const ords = o.value;

    $.ajax({
      url: "/sleekskincare/mypurchase",
      method: "POST",
      contentType: "application/json",
      data: JSON.stringify({ ords }),
      success: function (res) {
        window.location.href = "/sleekskincare/mypurchase";
      },
    });
  });
}
