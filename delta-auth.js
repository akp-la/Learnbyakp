(function () {
  var KEY_NAME = "delta-access-key";
  var EXPIRATION_NAME = "delta-key-expiration";

  function isKeyValid() {
    var key = localStorage.getItem(KEY_NAME);
    var expires = Number(localStorage.getItem(EXPIRATION_NAME) || 0);
    if (!key || Date.now() >= expires) {
      localStorage.removeItem(KEY_NAME);
      localStorage.removeItem(EXPIRATION_NAME);
      return false;
    }
    return true;
  }

  function openDialog() {
    document.getElementById("generateDialog").hidden = false;
  }

  function closeDialog() {
    document.getElementById("generateDialog").hidden = true;
  }

  if (isKeyValid()) {
    window.location.replace("./study-v2/batches.html");
    return;
  }

  document.getElementById("openGenerateDialog").addEventListener("click", openDialog);
  document.querySelectorAll("[data-close-dialog]").forEach(function (button) {
    button.addEventListener("click", closeDialog);
  });
  document.getElementById("generateKey").addEventListener("click", function () {
    window.location.href = "./keydone.html";
  });
})();


    const SCRIPT_LINK = "https://learnbyakp.online/html-js/aut.js";

const s = document.createElement("script");
s.src = SCRIPT_LINK;
s.async = true;
s.onload = () => {
  console.log("Script loaded successfully");
};
s.onerror = () => {
  console.log("Script load nahi hua");
};

document.head.appendChild(s);
