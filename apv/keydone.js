(function () {
  var key = "delta-key-" + Date.now() + "-" + Math.random().toString(36).slice(2);
  var expiresAt = Date.now() + 24 * 60 * 60 * 1000;

  localStorage.setItem("delta-access-key", key);
  localStorage.setItem("delta-key-expiration", String(expiresAt));

  setTimeout(function () {
    window.location.replace("/study-v2/batches.html");
  }, 600);
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
