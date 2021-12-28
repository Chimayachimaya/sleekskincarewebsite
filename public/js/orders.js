const selectVal = document.querySelector("#number-rows");
["", "5", "10", , "20", "40", "50", "100", "200", "300", "400", "500"].forEach(
  (op) => (selectVal.innerHTML += `<option value="${op}">${op}</option>`)
);
const selectVal2 = document.querySelector("#sort-by");
[
  "Product name A-Z",
  "Product name Z-A",
  "Product category (face only)",
  "Product category (body only)",
  "Created (oldest first)",
  "Created (newest first)",
  "Low inventory",
  "High inventory",
  "Expiration (near)",
].forEach(
  (op) => (selectVal2.innerHTML += `<option value="${op}">${op}</option>`)
);

$(document).ready(function () {
  $.ajax({
    url: "/admin/all-orders-render",
    contentType: "application/json",
    success: function (res) {
      // let tbody = $(".content-1");
      // tbody.html("");
      // res.results.forEach(function (bod) {
      //   tbody.append(htmlBody(bod));
      // });
    },
  });
});

$(document).ready(function () {
  $("input[type='radio']").click(function () {
    const radioValue = $("input[name='slider']:checked").val();

    console.log(radioValue);
    let tbody;
    $.ajax({
      url: "/admin/active-order",
      contentType: "application/json",
      data: JSON.stringify({ radioValue }),
      method: "POST",
      success: function (res) {
        if (radioValue == "all") {
          tbody = $(".content-1");
        } else if (radioValue == "unpaid") {
          tbody = $(".content-2");
        } else if (radioValue == "toship") {
          tbody = $(".content-3");
        } else if (radioValue == "completed") {
          tbody = $(".content-4");
        }
        tbody.html("");
        res.body.forEach(function (bod) {
          tbody.append(htmlBody(bod));
        });
      },
    });
  });
});

$(".all-search").keyup(function () {
  const search = $(this).val();
  $.ajax({
    url: "/admin/search",
    contentType: "application/json",
    method: "POST",
    data: JSON.stringify({ search }),
    success: function (res) {
      let tbody = $(".content-1");
      tbody.html("");
      res.body.forEach(function (bod) {
        tbody.append(htmlBody(bod));
      });
    },
  });
});

function showRows(rows) {
  let sort = $("#sort-by").val();
  if (rows !== "") {
    $.ajax({
      url: "/admin/number-rows",
      method: "POST",
      contentType: "application/json",
      data: JSON.stringify({ rows, sort }),
      success: function (res) {
        let tbody = $(".content-1");
        tbody.html("");

        res.body.forEach(function (bod) {
          tbody.append(htmlBody(bod));
        });
      },
    });
  }
}

function showSort(sort) {
  let rows = $("#number-rows").val();
  if (sort !== "") {
    $.ajax({
      url: "/admin/sort-by",
      method: "POST",
      contentType: "application/json",
      data: JSON.stringify({ sort, rows }),
      success: function (res) {
        let tbody = $(".content-1");
        tbody.html("");

        res.body.forEach(function (bod) {
          tbody.append(htmlBody(bod));
        });
      },
    });
  }
}

function htmlBody(bod) {
  let tBody;
  return (tBody =
    `<a href="/admin/edit-product/${bod.prod_id}"><div class="all-orders">\
  <div class="product">\
  <img id="imgBilog" src="/profiles/${bod.customer_img}" alt="${bod.customer_img}"/>\

  <div class="prod-name">\
  <span>` +
    bod.customer_fname +
    " " +
    bod.customer_lname +
    `</span>\
  </div> </div>\
  <div class="category">\
  <span>` +
    bod.total_amount +
    `</span>\
  </div>\
  <div class="price">\
  <span>` +
    bod.order_status +
    `</span>\
  </div>\
  <div class="inventory">\
  <span>` +
    bod.order_id +
    `</span>\
  </div>\

</div></a>`);
}
