const ord = document.querySelectorAll("#ordID");

for (const o of ord) {
  $(o).on("click", function (e) {
    e.preventDefault();
    const ords = o.value;
    const ods = o.textContent;
    if (ods.includes("Receive")) {
      $.ajax({
        url: "/admin/toreceive-order",
        method: "POST",
        contentType: "application/json",
        data: JSON.stringify({ ords }),
        success: function (res) {
          window.location.href = "/admin/all-orders";
        },
      });
    } else if (ods.includes("Accept")) {
      $.ajax({
        url: "/admin/accept-order",
        method: "POST",
        contentType: "application/json",
        data: JSON.stringify({ ords }),
        success: function (res) {
          window.location.href = "/admin/all-orders";
        },
      });
    }
  });
}
