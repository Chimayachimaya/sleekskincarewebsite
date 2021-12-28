// Star Tab

var tabs = document.querySelectorAll(".tabs_wrap ul li");
var five = document.querySelectorAll(".five");
var four = document.querySelectorAll(".four");
var three = document.querySelectorAll(".three");
var two = document.querySelectorAll(".two");
var one = document.querySelectorAll(".one");

var all = document.querySelectorAll(".item_wrap");

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((tab) => {
      tab.classList.remove("active");
    });
    tab.classList.add("active");
    var tabval = tab.getAttribute("data-tabs");

    all.forEach((item) => {
      item.style.display = "none";
    });

    if (tabval == "five") {
      five.forEach((fiv) => {
        fiv.style.display = "block";
      });
    } else if (tabval == "four") {
      four.forEach((fou) => {
        fou.style.display = "block";
      });
    } else if (tabval == "three") {
      three.forEach((thre) => {
        thre.style.display = "block";
      });
    } else if (tabval == "two") {
      two.forEach((tw) => {
        tw.style.display = "block";
      });
    } else if (tabval == "one") {
      one.forEach((on) => {
        on.style.display = "block";
      });
    } else {
      all.forEach((item) => {
        item.style.display = "block";
      });
    }
  });
});

// Quantity Button

//setting default attribute to disabled of minus button
document.querySelector(".minus-btn").setAttribute("disabled", "disabled");

//taking value to increment decrement input value
var valueCount;

//plus button
document.querySelector(".plus-btn").addEventListener("click", function () {
  //getting value of input
  valueCount = document.getElementById("quantity").value;

  //input value increment by 1
  valueCount++;

  //setting increment input value
  document.getElementById("quantity").value = valueCount;

  if (valueCount > 1) {
    document.querySelector(".minus-btn").removeAttribute("disabled");
    document.querySelector(".minus-btn").classList.remove("disabled");
  }
});

//minus button
document.querySelector(".minus-btn").addEventListener("click", function () {
  //getting value of input
  valueCount = document.getElementById("quantity").value;

  //input value increment by 1
  valueCount--;

  //setting increment input value
  document.getElementById("quantity").value = valueCount;

  if (valueCount == 1) {
    document.querySelector(".minus-btn").setAttribute("disabled", "disabled");
  }
});

// Product Description
const parentContainer = document.querySelector(".read-more-container");

parentContainer.addEventListener("click", (event) => {
  const current = event.target;

  const isReadMoreBtn = current.className.includes("read-more-btn");

  if (!isReadMoreBtn) return;

  const currentText = event.target.parentNode.querySelector(".read-more-text");

  currentText.classList.toggle("read-more-text--show");

  current.textContent = current.textContent.includes("Read More")
    ? "Read Less..."
    : "Read More...";
});
