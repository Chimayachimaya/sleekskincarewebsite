const imgDiv = document.querySelector(".media-div");
const img = document.querySelector("#photo");
const file = document.querySelector("#file");
const uploadBtn = document.querySelector("#uploadBtn");

//if user hover on img div

imgDiv.addEventListener("mouseenter", function () {
  uploadBtn.style.display = "block";
});

//if we hover out from img div

imgDiv.addEventListener("mouseleave", function () {
  uploadBtn.style.display = "none";
});

file.addEventListener("change", function () {
  //this refers to file
  const choosedFile = this.files[0];

  if (choosedFile) {
    const reader = new FileReader(); //FileReader is a predefined function of JS

    reader.addEventListener("load", function () {
      img.setAttribute("src", reader.result);
    });

    reader.readAsDataURL(choosedFile);
  }
});

const selectVal2 = document.querySelector("#prod-categ");
["Face", "Lips", "Body", "Scent"].forEach(
  (op) => (selectVal2.innerHTML += `<option value="${op}">${op}</option>`)
);
