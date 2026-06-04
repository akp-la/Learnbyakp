const classes = ["Class 9", "Class 10", "Class 11", "Class 12"];
const subjects = {
  "Class 9": ["Maths", "Science", "English", "Hindi", "Information technology", "Sanskrit", "SST"],
  "Class 9 abhay": ["Maths", "Science", "English", "Hindi", "Information technology", "Sanskrit", "SST"],
  "Class 10 abhay": ["Maths", "Science", "SST", "English", "Information technology", "Sanskrit", "Hindi"],
  "Class 10": ["Maths", "Science", "SST", "English", "Information technology", "Sanskrit", "Hindi"],
  "Class 11": ["Physics", "Chemistry", "Maths", "Biology", "English"],
  "Class 12": ["Physics", "Chemistry", "Maths", "Biology", "English"]
};
const options = ["Video", "Notes", "DPP", "DPP Solution"];

const unlogin = "unlogin.png";
const boy = "boy.jpeg";

const API_URL = "";
const LS_KEY = "api_cache_data";
const LS_TIME_KEY = "api_cache_time";

let flow = "";
let cClass = "";
let cSubject = "";
let chosenOption = "";
let visitedOption = false;
let backTapTime = 0;
let deferredPrompt = null;
let loaderTimer = null;
const THEME_KEY = "learnbyakp_theme";

const $ = (id) => document.getElementById(id);
const show = (el) => el && el.classList.remove("hidden");
const hide = (el) => el && el.classList.add("hidden");

function showPageLoader() {
  loaderTimer = window.setTimeout(() => {
    $("pageLoader")?.classList.add("show");
  }, 180);
}

function hidePageLoader() {
  clearTimeout(loaderTimer);
  $("pageLoader")?.classList.remove("show");
}

function dismissStartupOverlay() {
  const overlay = $("startupOverlay");
  if (!overlay) return;
  overlay.classList.add("fade-out");
  window.setTimeout(() => overlay.remove(), 500);
}

function resetNavigationState() {
  hidePageLoader();
  dismissStartupOverlay();
}

function withLoader(action) {
  showPageLoader();
  try {
    const result = action();
    if (result && typeof result.then === "function") {
      return result.finally(hidePageLoader);
    }
    hidePageLoader();
    return result;
  } catch (error) {
    hidePageLoader();
    throw error;
  }
}

function navigateTo(url, newTab = false) {
  if (!url) return;
  showPageLoader();
  if (newTab) {
    window.open(url, "_blank", "noopener");
    window.setTimeout(hidePageLoader, 350);
    return;
  }
  window.location.href = url;
}

function applyDefaultMode() {
  const savedTheme = localStorage.getItem(THEME_KEY) || (window.innerWidth <= 768 ? "day" : "night");
  applyTheme(savedTheme);
}

function applyTheme(mode) {
  const useNight = mode !== "day";
  document.body.classList.toggle("desktop-mode", useNight);
  document.body.classList.toggle("mobile-mode", !useNight);
  localStorage.setItem(THEME_KEY, useNight ? "night" : "day");
  updateThemeToggle();
}

function updateThemeToggle() {
  const isNight = (localStorage.getItem(THEME_KEY) || "night") === "night";
  const toggle = $("themeToggle");
  if (!toggle) return;
  toggle.textContent = isNight ? "🌙" : "☀️";
  toggle.setAttribute("aria-label", isNight ? "Switch to day mode" : "Switch to night mode");
}

function getCachedData() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (error) {
    return [];
  }
}

function saveCachedData(data) {
  localStorage.setItem(LS_KEY, JSON.stringify(data));
  localStorage.setItem(LS_TIME_KEY, Date.now().toString());
}

async function refreshDataInBackground() {
  try {
    const res = await fetch(API_URL);
    if (!res.ok) throw new Error("API failed");
    const fresh = await res.json();
    const map = new Map();
    fresh.forEach((item) => {
      if (item?.id) map.set(item.id, item);
    });
    saveCachedData(Array.from(map.values()));
  } catch (error) {
    console.error("Background refresh error:", error);
  }
}

async function getApiData() {
  const cached = getCachedData();
  if (cached.length) {
    refreshDataInBackground();
    return cached;
  }

  try {
    const res = await fetch(API_URL);
    if (!res.ok) throw new Error("API failed");
    const data = await res.json();
    saveCachedData(data);
    return data;
  } catch (error) {
    console.error("API Error:", error);
    return [];
  }
}

function build(list, gridId, stage) {
  const grid = $(gridId);
  if (!grid) return;

  grid.innerHTML = "";
  const arr = [...list];

  if (stage === "subject" && (flow === "Topper" || flow === "PW")) {
    arr.unshift("Live Lecture");
  } else if (stage === "class" && flow === "Topper") {
    arr.unshift("Class 9 abhay");
    arr.unshift("Class 10 abhay");
  }

  arr.forEach((txt, i) => {
    const d = document.createElement("div");
    d.className = `sm-card${txt === "Live Lecture" ? " live-card" : ""}`;
    d.style.animationDelay = `${i * 50}ms`;
    const icon = txt === "Live Lecture"
      ? "https://img.icons8.com/color/96/video-call.png"
      : "https://img.icons8.com/fluency/96/list.png";

    d.innerHTML = `<img src="${icon}" alt=""><h4>${txt}</h4>`;
    d.onclick = () => select(stage, txt);
    grid.appendChild(d);
  });
}

function start(batch) {
  flow = batch;
  hide($("homeGrid"));
  build(classes, "classGrid", "class");
  show($("step-class"));
}

function setupSubBack() {
  if (flow === "AKP") {
    hide($("backToClass"));
    show($("backToHomeAKP"));
  } else {
    show($("backToClass"));
    hide($("backToHomeAKP"));
  }
}

function setupOptBack() {
  if (flow === "AKP") {
    hide($("backToSubTopper"));
    show($("backToSubAKP"));
  } else {
    show($("backToSubTopper"));
    hide($("backToSubAKP"));
  }
}

function pushDummy() {
  history.pushState(null, "", location.href);
}

function backHome() {
  ["step-class", "step-subject", "step-option", "step-res"].forEach((id) => hide($(id)));
  show($("homeGrid"));
  flow = "";
  cClass = "";
  cSubject = "";
  chosenOption = "";
  visitedOption = false;
}

function backToClass() {
  hide($("step-subject"));
  show($("step-class"));
}

function backToSubject() {
  hide($("step-option"));
  hide($("step-res"));
  show($("step-subject"));
}

function backToOption() {
  hide($("step-res"));
  show($("step-option"));
}

function doSearch() {
  const q = $("search")?.value?.trim();
  if (q) alert(`Search: ${q}`);
}

async function select(stage, val) {
  if (stage === "class") {
    cClass = val;
    build(subjects[val], "subjectGrid", "subject");
    setupSubBack();
    hide($("step-class"));
    show($("step-subject"));
    return;
  }

  if (stage === "subject") {
    cSubject = val;
    build(options, "optionGrid", "option");
    setupOptBack();
    hide($("step-subject"));
    show($("step-option"));
    visitedOption = true;
    pushDummy();
    return;
  }

  if (stage === "option") {
    chosenOption = val;
    await fetchRes();
    hide($("step-option"));
    show($("step-res"));
    pushDummy();
  }
}

async function fetchRes() {
  $("resHead").innerText = `${chosenOption} • ${cClass} • ${cSubject}`;
  const grid = $("resGrid");
  grid.innerHTML = `
    <div class="loader-shell" style="margin: 0 auto;">
      <div class="loader-orbit"></div>
      <img src="lo.png" alt="Loading" class="loader-logo">
      <p>Loading resources</p>
    </div>
  `;

  try {
    const rows = await withLoader(() => getApiData());
    const fil = rows.filter((r) =>
      r.batch?.toLowerCase() === flow.toLowerCase() &&
      r.className?.toLowerCase() === cClass.toLowerCase() &&
      r.subject?.toLowerCase() === cSubject.toLowerCase() &&
      r.category?.toLowerCase() === chosenOption.toLowerCase()
    );

    grid.innerHTML = "";

    if (!fil.length) {
      grid.innerHTML = '<p class="info-panel" style="margin:0;">No items found. Please contact admin.</p>';
      return;
    }

    const completedCards = [];
    fil.forEach((r) => {
      const card = document.createElement("div");
      card.className = "res-card";
      const cardId = btoa(unescape(encodeURIComponent(`${r.title || ""}|${r.link || ""}`)));

      card.innerHTML = `
        <div class="card-inner video-card" data-id="${cardId}">
          <div class="thumb-wrap">
            <div class="thumb-overlay"></div>
            <img class="thumb-img" src="${r.thumbnail || "https://img.icons8.com/fluency/96/no-image.png"}" alt="" loading="lazy">
            <button class="tick-btn" aria-label="Mark completed" type="button">
              <svg viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10" fill="none" stroke="#7f8cfd" stroke-width="2"></circle>
                <path d="M6 12l4 4 8-8" stroke="#45dd1f" stroke-width="2" fill="none"></path>
              </svg>
            </button>
          </div>
          <div class="card-body">
            <h5 class="card-title">${r.title || "Untitled"}</h5>
          </div>
        </div>
      `;

      const tickBtn = card.querySelector(".tick-btn");
      let completed = localStorage.getItem(`video_completed_${cardId}`) === "true";

      if (completed) {
        tickBtn.classList.add("completed");
        completedCards.push(card);
      } else {
        grid.appendChild(card);
      }

      tickBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        completed = !completed;
        if (completed) {
          tickBtn.classList.add("completed");
          localStorage.setItem(`video_completed_${cardId}`, "true");
          const popup = $("completePopup");
          popup.textContent = `Completed: ${r.title}`;
          popup.classList.add("show");
          setTimeout(() => popup.classList.remove("show"), 2500);
          setTimeout(() => grid.appendChild(card), 250);
        } else {
          tickBtn.classList.remove("completed");
          localStorage.removeItem(`video_completed_${cardId}`);
          grid.insertBefore(card, grid.firstChild);
        }
      });

      card.onclick = () => {
        if (r.link) navigateTo(r.link, true);
        else Swal.fire("No Link Found", "This resource does not have a link.", "error");
      };
    });

    completedCards.forEach((c) => grid.appendChild(c));
    setupResourceSearch(fil);
  } catch (error) {
    console.error(error);
    grid.innerHTML = '<p class="info-panel" style="margin:0;">Error loading resources. Please contact admin.</p>';
  }
}

function setupResourceSearch(items) {
  const searchInput = $("resSearch");
  const searchBtn = $("resSearchBtn");
  const datalistBox = $("titleSuggestions");
  const gridBox = $("resGrid");
  const fuse = new Fuse(items, { keys: ["title"], threshold: 0.4, distance: 100 });

  datalistBox.innerHTML = "";
  items.forEach((item) => {
    if (!item.title) return;
    const opt = document.createElement("option");
    opt.value = item.title;
    datalistBox.appendChild(opt);
  });

  function doResSearch() {
    const q = searchInput.value.trim();
    if (!q) return;

    const fuseResults = fuse.search(q);
    const rankMap = new Map(fuseResults.map((res, idx) => [res.item.title.toLowerCase().trim(), idx]));
    const cards = Array.from(gridBox.children);

    cards.sort((a, b) => {
      const aTitle = a.querySelector("h5")?.innerText.toLowerCase().trim() || "";
      const bTitle = b.querySelector("h5")?.innerText.toLowerCase().trim() || "";
      return (rankMap.get(aTitle) ?? 9999) - (rankMap.get(bTitle) ?? 9999);
    });

    cards.forEach((c) => gridBox.appendChild(c));
    cards[0]?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  searchInput.onkeydown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      doResSearch();
    }
  };
  searchBtn.onclick = doResSearch;
}

function unlockContac(e) {
  e.preventDefault();
  const pwd = prompt("Only for Admin:");
  if (pwd === "992jaan") navigateTo("upload.html");
  else alert("Wrong password");
}

function renderProfile(user) {
  $("profileBtn").querySelector("img").src = boy;
  $("profileAvatar").src = boy;
  $("profileName").innerText = user.displayName || "Unnamed";
  $("profileEmail").innerText = user.email || "";
  $("profilePhone").innerText = user.phoneNumber || "";
  hide($("nameEdit"));
  hide($("saveBtn"));
  hide($("cancelBtn"));
  show($("editBtn"));
}

function openProfile() {
  $("profileModal").style.display = "flex";
}

function enableNameEdit() {
  $("nameEdit").value = $("profileName").innerText;
  hide($("profileName"));
  show($("nameEdit"));
  hide($("editBtn"));
  show($("saveBtn"));
  show($("cancelBtn"));
}

function cancelNameEdit() {
  show($("profileName"));
  hide($("nameEdit"));
  show($("editBtn"));
  hide($("saveBtn"));
  hide($("cancelBtn"));
}

async function checkUserLogin() {
  return new Promise((resolve) => {
    if (!window.firebase?.auth) {
      resolve(null);
      return;
    }
    const unsubscribe = firebase.auth().onAuthStateChanged((user) => {
      unsubscribe();
      resolve(user);
    });
  });
}

async function saveName() {
  const newName = $("nameEdit").value.trim();
  if (!newName) return alert("Name cannot be empty.");
  const user = await checkUserLogin();
  if (!user) return alert("Not logged in.");

  user.updateProfile({ displayName: newName })
    .then(() => {
      renderProfile(user);
      show($("profileName"));
      alert("Name updated");
    })
    .catch(() => alert("Error updating name."));
}

async function handleQuizCardClick() {
  const user = await checkUserLogin();
  if (user) navigateTo("quiz.html");
  else {
    showToast("Please log in to access the quiz.");
    setTimeout(() => navigateTo("login.html"), 800);
  }
}

function showToast(txt) {
  let toast = $("toastMsg");
  if (toast) toast.remove();

  toast = document.createElement("div");
  toast.id = "toastMsg";
  toast.textContent = txt;
  toast.style.cssText = `
    position:fixed;left:50%;bottom:110px;transform:translateX(-50%);
    background:rgba(7,17,31,0.92);color:#fff;padding:11px 18px;border-radius:999px;
    z-index:100;box-shadow:0 16px 32px rgba(0,0,0,.22)
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2200);
}

function togglePopup(id) {
  document.querySelectorAll(".popup-box").forEach((box) => {
    if (box.id !== id) box.style.display = "none";
  });
  const popup = $(id);
  if (!popup) return;
  popup.style.display = popup.style.display === "block" ? "none" : "block";
}

function setupMenuToggle() {
  $("menuToggle")?.addEventListener("click", () => {
    togglePopup("menuPopup");
  });
}

function setupThemeSwitcher() {
  $("themeToggle")?.addEventListener("click", () => {
    const current = localStorage.getItem(THEME_KEY) || "night";
    applyTheme(current === "night" ? "day" : "night");
  });
  updateThemeToggle();
}

function openOverlay() {
  $("notifOverlay").style.display = "flex";
}

async function pollNotifSheet() {
  const SHEET_URL = "https://opensheet.elk.sh/1dyjS6Im6bejI29K6RutDoCmXBWmsPynmXqOwezLgP8o/Sheet1";
  const AVATAR_SRC = "lo.png";
  const TS_STORE = "sheetNotifTs";
  const notifList = $("notifList");

  if (!notifList) return;

  const tsMap = JSON.parse(localStorage.getItem(TS_STORE) || "{}");
  const makeTimeline = (ms) => new Date(+ms).toLocaleString("default", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit"
  });

  function createCard({ key, heading, message, time }) {
    const div = document.createElement("div");
    div.className = "notif-card";
    div.dataset.key = key;
    div.innerHTML = `
      <img src="${AVATAR_SRC}" class="notif-avatar" alt="">
      <div>
        <div class="notif-title">${heading}</div>
        <div>${message}</div>
        <div class="notif-time">${makeTimeline(time)}</div>
      </div>
    `;
    notifList.prepend(div);
  }

  try {
    const rows = await fetch(SHEET_URL, { cache: "no-cache" }).then((r) => r.json());
    const parsedRows = rows
      .map((r) => ({ heading: r.Heading || "", message: r.Message || "" }))
      .filter((r) => r.heading || r.message);

    const currentKeys = new Set();
    parsedRows.forEach((row) => {
      const parts = row.message.split(/[,|\n]/).map((t) => t.trim()).filter(Boolean);
      parts.forEach((msg) => {
        const key = `${row.heading}|${msg}`;
        currentKeys.add(key);
        if (!document.querySelector(`[data-key="${CSS.escape(key)}"]`)) {
          if (!tsMap[key]) tsMap[key] = Date.now();
          createCard({ key, heading: row.heading, message: msg, time: tsMap[key] });
        }
      });
    });

    document.querySelectorAll(".notif-card").forEach((card) => {
      if (!currentKeys.has(card.dataset.key)) {
        card.remove();
        delete tsMap[card.dataset.key];
      }
    });
    localStorage.setItem(TS_STORE, JSON.stringify(tsMap));
  } catch (error) {
    console.error("Notification sheet fetch error:", error);
  }
}

function setupInstallPrompt() {
  const installModal = $("installModal");
  const installBtn = $("installBtn");
  const closeModal = $("closeModal");

  function openInstallModal() {
    if (!installModal) return;
    installModal.style.display = "block";
    document.body.classList.add("install-popup-open");
  }

  function closeInstallModal() {
    if (!installModal) return;
    installModal.style.display = "none";
    document.body.classList.remove("install-popup-open");
  }

  function isAppInstalled() {
    return window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone;
  }

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    if (!isAppInstalled()) openInstallModal();
  });

  window.addEventListener("load", () => {
    setTimeout(() => {
      if (!isAppInstalled()) openInstallModal();
    }, 700);
  });

  installBtn?.addEventListener("click", async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      await deferredPrompt.userChoice;
      closeInstallModal();
      deferredPrompt = null;
      return;
    }
    showToast("Install from browser menu: Add to Home screen");
  });

  closeModal?.addEventListener("click", () => {
    closeInstallModal();
  });

  window.addEventListener("appinstalled", () => {
    closeInstallModal();
  });
}

function setupNavigationLoader() {
  window.addEventListener("pageshow", resetNavigationState);
  window.addEventListener("pagehide", hidePageLoader);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      hidePageLoader();
    }
  });

  document.addEventListener("click", (e) => {
    const navCard = e.target.closest(".nav-card[data-href], .nav-link[data-href]");
    if (navCard) {
      e.preventDefault();
      navigateTo(navCard.dataset.href || navCard.getAttribute("href"), navCard.target === "_blank");
      return;
    }

    const anchor = e.target.closest("a.nav-link[href]");
    if (!anchor) return;
    const href = anchor.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:")) return;
    e.preventDefault();
    navigateTo(href, anchor.target === "_blank");
  });
}

function setupProfileModal() {
  $("profileModal")?.addEventListener("click", (e) => {
    if (e.target.id === "profileModal") $("profileModal").style.display = "none";
  });
}

function setupResultModal() {
  $("resBtn")?.addEventListener("click", () => {
    $("resModal").style.display = "flex";
    const arr = JSON.parse(localStorage.getItem("quizResults") || "[]").reverse();
    const resList = $("resList");
    resList.innerHTML = "";
    if (!arr.length) {
      resList.textContent = "No quiz results yet.";
      return;
    }

    arr.forEach((r) => {
      const div = document.createElement("div");
      div.innerHTML = `<strong>${r.quiz}</strong> • ${r.time}<br>Correct: ${r.correct}/${r.total}, Wrong: ${r.wrong}`;
      resList.appendChild(div);
    });
  });

  $("closeModal1")?.addEventListener("click", () => {
    $("resModal").style.display = "none";
  });

  $("resModal")?.addEventListener("click", (e) => {
    if (e.target.id === "resModal") $("resModal").style.display = "none";
  });
}

function setupNotifications() {
  $("bellLink")?.addEventListener("click", openOverlay);
  $("bellLinks")?.addEventListener("click", openOverlay);
  $("notifOverlay")?.addEventListener("click", (e) => {
    if (e.target.id === "notifOverlay" || e.target.dataset.closeOverlay) {
      $("notifOverlay").style.display = "none";
    }
  });
}

function setupBatchSearch() {
  const input = $("batchSearch");
  const clearBtn = $("batchSearchClear");
  const cards = () => Array.from(document.querySelectorAll("#homeGrid .card"));

  if (!input) return;

  const runFilter = () => {
    const query = input.value.trim().toLowerCase();
    cards().forEach((card) => {
      const text = card.innerText.toLowerCase();
      card.style.display = !query || text.includes(query) ? "" : "none";
    });
  };

  input.addEventListener("input", runFilter);
  clearBtn?.addEventListener("click", () => {
    input.value = "";
    runFilter();
  });
}

function setupBackHandling() {
  window.addEventListener("load", pushDummy);
  window.addEventListener("popstate", () => {
    const isVisible = (id) => !$(id).classList.contains("hidden");

    if (isVisible("step-res")) {
      if (visitedOption) backToOption();
      else backToSubject();
      pushDummy();
      return;
    }

    if (isVisible("step-option")) {
      backToSubject();
      pushDummy();
      return;
    }

    if (isVisible("step-subject") || isVisible("step-class")) {
      backHome();
      pushDummy();
      return;
    }

    const now = Date.now();
    if (now - backTapTime < 1500) {
      history.go(-2);
    } else {
      showToast("Tap again to exit");
      backTapTime = now;
      pushDummy();
    }
  });
}

function setupAuthButtons() {
  $("logoutBtn")?.addEventListener("click", () => {
    localStorage.removeItem("authToken");
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigateTo("login.html");
  });
}

function setupCookieBanner() {
  if (localStorage.getItem("cookieAck")) return;
  const bar = document.createElement("div");
  bar.innerHTML = `This site uses cookies for personalised ads. <button id="okBtn" class="ghost-btn" type="button">Got it!</button>`;
  bar.style.cssText = `
    position:fixed;left:16px;right:16px;bottom:16px;z-index:95;padding:14px 16px;
    border-radius:18px;background:rgba(7,17,31,0.92);border:1px solid rgba(255,255,255,.1);color:#fff
  `;
  document.body.appendChild(bar);
  $("okBtn").onclick = () => {
    localStorage.setItem("cookieAck", "1");
    bar.remove();
  };
}

function setupStartupLoader() {
  if (document.readyState === "complete") {
    window.setTimeout(dismissStartupOverlay, 1200);
    return;
  }

  window.addEventListener("load", () => {
    window.setTimeout(dismissStartupOverlay, 1200);
  });
}

function registerServiceWorker() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/service-worker.js").catch((error) => {
      console.error("Service Worker Failed", error);
    });
  }
}

document.addEventListener("click", (e) => {
  if (
    !e.target.closest(".popup-box") &&
    !e.target.closest(".popup-btn") &&
    !e.target.closest(".plain-tab") &&
    !e.target.closest(".menu-toggle")
  ) {
    document.querySelectorAll(".popup-box").forEach((box) => {
      box.style.display = "none";
    });
  }
});

document.addEventListener("DOMContentLoaded", async () => {
  applyDefaultMode();
  setupNavigationLoader();
  setupMenuToggle();
  setupThemeSwitcher();
  setupInstallPrompt();
  setupProfileModal();
  setupResultModal();
  setupNotifications();
  setupBatchSearch();
  setupBackHandling();
  setupAuthButtons();
  setupCookieBanner();
  setupStartupLoader();
  registerServiceWorker();
  pollNotifSheet();
  setInterval(pollNotifSheet, 60000);

  const user = await checkUserLogin();
  if (user) renderProfile(user);
});

    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag("js", new Date());
    gtag("config", "G-YMD7B9P560");

    if (window.firebaseConfig && !firebase.apps.length) {
      firebase.initializeApp(firebaseConfig);
    }

    

