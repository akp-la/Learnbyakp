 const CONFIG = {
      nextToppersBase: "https://nexttoppers.com/test/",
      loginUrl: "https://nexttoppers.com/login",
      defaultTheme: localStorage.getItem("akp_test_theme") || "light"
    };

    const state = {
      testId: getTestId()
    };

    function getTestId() {
      const params = new URLSearchParams(location.search);

      const fromQuery =
        params.get("testId") ||
        params.get("testid") ||
        params.get("test_id") ||
        params.get("id");

      if (fromQuery) return fromQuery;

      const parts = location.pathname.split("/").filter(Boolean);

      const akpIndex = parts.indexOf("LearnByAKP-tests");
      if (akpIndex >= 0 && parts[akpIndex + 1]) return parts[akpIndex + 1];

      const testIndex = parts.indexOf("test");
      if (testIndex >= 0 && parts[testIndex + 1]) return parts[testIndex + 1];

      return "";
    }

    function buildTestUrl(type) {
      if (!state.testId) {
        alert("Test ID missing. URL me ?testId=76 add karo.");
        return "";
      }

      return CONFIG.nextToppersBase +
        encodeURIComponent(state.testId) +
        "/" +
        encodeURIComponent(type);
    }

    function goToTest(type) {
      const url = buildTestUrl(type);
      if (!url) return;
      location.href = url;
    }

    function loginFirst() {
      location.href = CONFIG.loginUrl;
    }

    function showActions() {
      const actions = document.getElementById("actionsPanel");
      const login = document.getElementById("loginPanel");

      login.classList.remove("show");
      actions.classList.remove("show");

      requestAnimationFrame(() => {
        actions.classList.add("show");
      });

      updateNote("Login confirmed. Ab apna test action choose karo.");
    }

    function showLoginFirst() {
      const actions = document.getElementById("actionsPanel");
      const login = document.getElementById("loginPanel");

      actions.classList.remove("show");
      login.classList.remove("show");

      requestAnimationFrame(() => {
        login.classList.add("show");
      });

      updateNote("Pehle NextToppers official website par login karo, phir wapas yaha aao.");
    }

    function updateNote(text) {
      document.getElementById("noteText").innerHTML = text;
    }

    function toggleTheme() {
      const isDark = document.body.classList.toggle("dark");
      localStorage.setItem("akp_test_theme", isDark ? "dark" : "light");
      document.getElementById("themeBtn").textContent = isDark ? "☀️" : "🌙";
    }

    function applyInitialTheme() {
      if (CONFIG.defaultTheme === "dark") {
        document.body.classList.add("dark");
        document.getElementById("themeBtn").textContent = "☀️";
      } else {
        document.body.classList.remove("dark");
        document.getElementById("themeBtn").textContent = "🌙";
      }
    }

    function init() {
      applyInitialTheme();

      const text = state.testId
        ? "Test ID: " + state.testId
        : "Test ID missing";

      document.getElementById("testIdText").textContent = text;
    }

    init();
