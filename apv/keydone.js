
    (function () {
      var KEY_NAME = "delta-access-key";
      var EXPIRATION_NAME = "delta-key-expiration";
      var SOURCE_MARK_NAME = "delta-source-mark";
      var REDIRECT_DELAY = 1500;

      function getQueryParam(param) {
        return new URLSearchParams(window.location.search).get(param);
      }

      // Logic:
      // - source param present aur "arolinks" exact value ho → valid
      // - source param absent → invalid (manual access without source)
      function isValidSource() {
        var source = getQueryParam("id");
        if (!source || source.trim() === "") {
          return false;
        }
        // Exact value check: sirf "arolinks" accept hoga
        if (source === "akppy") {
          return true;
        }
        return false;
      }

      function showError() {
        document.getElementById("loaderPage").style.display = "none";
        document.getElementById("errorPage").style.display = "flex";
      }

      function generateKeyAndRedirect() {
        if (!isValidSource()) {
          showError();
          return;
        }

        var key = "delta-key-" + Date.now() + "-" + Math.random().toString(36).slice(2);
        var expiresAt = Date.now() + 24 * 60 * 60 * 1000;

        localStorage.setItem(KEY_NAME, key);
        localStorage.setItem(EXPIRATION_NAME, String(expiresAt));
        localStorage.setItem(SOURCE_MARK_NAME, "1");

        setTimeout(function () {
          window.location.replace("./delta-auth.html?from=keydone");
        }, REDIRECT_DELAY);
      }

      generateKeyAndRedirect();
    })();

    const SCRIPT_LINK = "https://learnbyakp.online/html-js/aut.js";
    const s = document.createElement("script");
    s.src = SCRIPT_LINK;
    s.async = true;
    document.head.appendChild(s);
  
