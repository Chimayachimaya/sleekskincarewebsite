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

//if the all product page render, this function will occur

$(document).ready(function () {
  $.ajax({
    url: "/admin/all-product-render",
    contentType: "application/json",
    success: function (res) {
      let tbody = $(".content-1");
      tbody.html("");
      if (res.results.length > 0) {
        res.results.forEach(function (bod) {
          tbody.append(htmlBody(bod));
        });
      } else {
        tbody.append(LengthIsZero(""));
      }
    },
  });
});

//output for each item of navigation: all, active, draft, archive
$(document).ready(function () {
  $("input[type='radio']").click(function () {
    const radioValue = $("input[name='slider']:checked").attr("id");
    let tbody;
    if (radioValue == "all") {
      window.location.href = "/admin/all-product";
    } else {
      $.ajax({
        url: "/admin/active-product",
        contentType: "application/json",
        data: JSON.stringify({ radioValue }),
        method: "POST",
        success: function (res) {
          if (radioValue == "Active") {
            tbody = $(".content-2");
          } else if (radioValue == "Draft") {
            tbody = $(".content-3");
          } else if (radioValue == "Archive") {
            tbody = $(".content-4");
          }
          tbody.html("");
          if (res.body.length > 0) {
            res.body.forEach(function (bod) {
              tbody.append(htmlBody(bod));
            });
          } else {
            tbody.append(LengthIsZero(radioValue));
          }
        },
      });
    }
  });
});

// search item for all tab only
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

      if (res.body.length > 0) {
        res.body.forEach(function (bod) {
          tbody.append(htmlBody(bod));
        });
      } else {
        tbody.append(noresult(search));
      }
    },
  });
});

//limiting rows for all tab only
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

//sorting rows for all tab only
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

//search item for active, draft and archive tab
$(document).ready(function () {
  $("input[type='radio']").click(function () {
    const radioValue = $("input[name='slider']:checked").attr("id");
    let tbody;
    $(".all-search").keyup(function () {
      const search = $(this).val();

      if (radioValue == "all") {
        window.location.href = "/admin/all-product";
      } else {
        $.ajax({
          url: "/admin/search-nav",
          contentType: "application/json",
          data: JSON.stringify({ radioValue, search }),
          method: "POST",
          success: function (res) {
            if (radioValue == "Active") {
              tbody = $(".content-2");
            } else if (radioValue == "Draft") {
              tbody = $(".content-3");
            } else if (radioValue == "Archive") {
              tbody = $(".content-4");
            }
            tbody.html("");
            if (res.body.length > 0) {
              res.body.forEach(function (bod) {
                tbody.append(htmlBody(bod));
              });
            } else {
              tbody.append(noresult(search));
            }
          },
        });
      }
    });
  });
});

function htmlBody(bod) {
  let tBody;
  return (tBody =
    `<a href="/admin/edit-product/${bod.prod_id}">\
              <div class="prod-body">\
                <div class="prod-div">\
                  <div>\
                  <img src="/products/${bod.prod_img}" alt="${bod.prod_img}" />\
                </div>\
                <div>\
                  <span>` +
    bod.prod_name +
    `</span>\
                </div>\
                </div>\
                <div class="category-div">` +
    bod.prod_categories +
    `</div>\
                <div class="price-div">` +
    "₱" +
    bod.price +
    `</div>\
                <div class="inventory-div">` +
    bod.prod_qty +
    `</div>\
                <div class="expiration-div">` +
    bod.exp +
    `</div>\
                <div class="status-div">` +
    bod.prod_status +
    `</div>\
              </div>\
            </a>`);
}

function LengthIsZero(bod) {
  let tBody;
  return (tBody =
    `<div class="all-row-prod noprod">\
                <img src="/img/prod.png" alt="product icon" />\
                <div>\
                  <div class="header-prod">Manage products</div>\
                  <span class="text-noprod">\
                  Your ` +
    bod +
    ` products will show here</span>\
                </div>\
              </div>`);
}

function noresult(bod) {
  let tBody;
  return (tBody =
    `<div class="all-row-prod noprod searchicon">\
                <img src="/img/searchicon.png" alt="search icon" />\
                <div>\
                  <div class="header-prod">No products found</div>\
                  <span class="text-noprod">\
                  There's no <span id="searchresult">'` +
    bod +
    `'</span> product exist in your inventory</span>\
                </div>\
              </div>`);
}
