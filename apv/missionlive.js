// ============================================
// MISSIONJEET LIVE + PUSH NOTIFICATIONS
// ============================================

const BASE_URL = "https://learnbyakp.onrender.com";
const FALLBACK_IMAGE = "https://decicqog4ulhy.cloudfront.net/0/admin_v2/uploads/courses/thumbnail/7524245_1_WhatsApp%20Image%202026-03-02%20at%204.19.45%20PM.jpeg";
const PAGE_NOTIFY_NAMESPACE = location.pathname.replace(/[^a-z0-9]/gi, "_").toLowerCase() || "default_page";
const NOTIFY_STORAGE_KEY = `nt_live_notify_settings_v1_${PAGE_NOTIFY_NAMESPACE}`;

const URL_PARAMS = new URLSearchParams(window.location.search);
const PAGE_COURSE_ID = String(URL_PARAMS.get("id") || "").trim();

const LIVE_CLASSES_API = `${BASE_URL}/api/missionjeet/live`;
const CONTENT_DETAILS_API = `${BASE_URL}/api/missionjeet/content-details`;
const BATCHES_API = `${BASE_URL}/api/missionjeet/batches`;

// Push server + VAPID
const NOTIFICATION_SERVER_URL = "https://nexttoppers-notifications.onrender.com";
const VAPID_PUBLIC_KEY = "YOUR_VAPID_PUBLIC_KEY_HERE";

let liveItems = [];
let upcomingItems = [];
let currentTab = "live";
let loading = true;
let errorMessage = null;
let countdownInterval = null;
let pollingInterval = null;
let searchText = "";

let availableBatches = [];
let batchesLoading = false;
let pushSubscription = null;

const notifyState = loadNotifyState();

// ================= LOCAL STORAGE STATE =================

function loadNotifyState() {
  try {
    const raw = localStorage.getItem(NOTIFY_STORAGE_KEY);
    if (!raw) {
      return {
        lectureSubscriptions: {},
        selectedCourses: [],
        sent: {}
      };
    }
    const parsed = JSON.parse(raw);
    return {
      lectureSubscriptions: parsed.lectureSubscriptions || {},
      selectedCourses: parsed.selectedCourses || [],
      sent: parsed.sent || {}
    };
  } catch {
    return {
      lectureSubscriptions: {},
      selectedCourses: [],
      sent: {}
    };
  }
}

function saveNotifyState() {
  localStorage.setItem(NOTIFY_STORAGE_KEY, JSON.stringify(notifyState));
}

// ================= GENERIC HELPERS =================

function safeThumb(url) {
  if (!url || !url.trim() || url.includes("admin.missionjeet.com")) {
    return FALLBACK_IMAGE;
  }
  return url;
}

function formatTime(ts) {
  return new Date(Number(ts) * 1000).toLocaleTimeString("en-IN", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true
  });
}

function formatDate(ts) {
  return new Date(Number(ts) * 1000).toLocaleDateString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric"
  });
}

function getCountdown(ts) {
  const diff = new Date(Number(ts) * 1000) - new Date();
  if (diff <= 0) {
    return "Starting soon...";
  }
  const hours = Math.floor((diff / 3600000) % 24);
  const minutes = Math.floor((diff / 60000) % 60);
  const seconds = Math.floor((diff / 1000) % 60);
  return `Start In- ${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function normalizeText(str) {
  return String(str || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function matchesSearch(item, query, type) {
  if (!query) return true;

  const normalizedQuery = normalizeText(query);
  const queryWords = normalizedQuery.split(" ").filter(Boolean);

  const searchableText = normalizeText([
    item.title,
    item.course?.title,
    type,
    Number(item.is_live) === 1 ? "live running ongoing current" : "upcoming scheduled next future"
  ].join(" "));

  if (searchableText.includes(normalizedQuery)) return true;

  return queryWords.every(word => searchableText.includes(word));
}

function getFilteredItems() {
  const sourceItems = currentTab === "live" ? liveItems : upcomingItems;
  return sourceItems.filter(item => matchesSearch(item, searchText, currentTab));
}

function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ================= COURSE / LECTURE KE HELPERS =================

function setActiveTab(tab) {
  currentTab = tab;
  document.getElementById("liveTab").classList.toggle("active", tab === "live");
  document.getElementById("upcomingTab").classList.toggle("active", tab === "upcoming");
  render();
}

function getItemCourseId(item) {
  return String(
    item?.course?.id ||
    item?.course_id ||
    item?.batch_id ||
    item?.batchId ||
    ""
  );
}

function matchesPageCourse(item) {
  if (!PAGE_COURSE_ID) return true;
  return getItemCourseId(item) === PAGE_COURSE_ID;
}

// per-lecture unique key: course + entity + live_from
function getItemNotifyKey(item) {
  const courseId = getItemCourseId(item) || "no-course";
  const entityId = item.entity_id || item.id || "no-entity";
  const liveFrom = item.details?.live_from || item.live_from || "no-time";
  return `${courseId}__${entityId}__${liveFrom}`;
}

function getEventNotifyKey(item, type) {
  return `${type}__${getItemNotifyKey(item)}`;
}

function isLectureSubscribed(item) {
  return !!notifyState.lectureSubscriptions[getItemNotifyKey(item)];
}

function isCourseSelected(courseId) {
  return notifyState.selectedCourses.includes(String(courseId));
}

// ================= NOTIFICATION PERMISSION + PUSH =================

function getNotificationPermission() {
  return ("Notification" in window) ? Notification.permission : "unsupported";
}

function updatePermissionStatusText() {
  const el = document.getElementById("permissionStatusText");
  const permission = getNotificationPermission();
  if (!el) return;
  if (permission === "granted") el.textContent = "Notifications are already enabled";
  else if (permission === "denied") el.textContent = "Notifications are blocked in browser settings";
  else if (permission === "unsupported") el.textContent = "This browser does not support notifications";
  else el.textContent = "Notification permission required";
}

function openPermissionModal() {
  updatePermissionStatusText();
  document.getElementById("permissionModal").classList.remove("hidden");
}

function closePermissionModal() {
  document.getElementById("permissionModal").classList.add("hidden");
}

async function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return null;
  try {
    const registration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    console.log("SW registered:", registration);
    return registration;
  } catch (err) {
    console.error("SW registration failed:", err);
    return null;
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array.rawData.length;
  const arr = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) arr[i] = rawData.charCodeAt(i);
  return arr;
}

async function subscribeToPushNotifications() {
  try {
    const registration = await registerServiceWorker();
    if (!registration) return null;

    const applicationServerKey = urlBase64ToUint8Array(VAPID_PUBLIC_KEY);
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey
    });

    await fetch(`${NOTIFICATION_SERVER_URL}/api/save-subscription`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subscription })
    });

    pushSubscription = subscription;
    return subscription;
  } catch (err) {
    console.error("Push subscription failed:", err);
    return null;
  }
}

async function ensureNotificationPermission() {
  const permission = getNotificationPermission();
  if (permission === "granted") {
    if (!pushSubscription) await subscribeToPushNotifications();
    return true;
  }
  openPermissionModal();
  return false;
}

async function enableNotifications() {
  if (!("Notification" in window)) {
    alert("This browser does not support notifications.");
    return false;
  }
  try {
    const permission = await Notification.requestPermission();
    updatePermissionStatusText();
    if (permission === "granted") {
      await subscribeToPushNotifications();
      closePermissionModal();
      render();
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// Server-based branded push
async function sendPushNotification(title, body, icon, data = {}) {
  try {
    const brandTitle = `LearnByAKP.online • ${title || "Live Class"}`;
    const brandBody = body || "New update from LearnByAKP.online";

    const response = await fetch(`${NOTIFICATION_SERVER_URL}/api/send-notification`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: brandTitle,
        body: brandBody,
        icon: icon || FALLBACK_IMAGE,
        data
      })
    });
    const result = await response.json();
    return result.success;
  } catch (err) {
    console.error("Push notification failed:", err);
    return false;
  }
}

// ================= BATCHES =================

async function fetchMissionJeetBatches() {
  if (batchesLoading) return;

  batchesLoading = true;
  const batchList = document.getElementById("batchList");
  batchList.innerHTML = `<div class="muted">Loading batches...</div>`;

  try {
    const res = await fetch(BATCHES_API);
    if (!res.ok) throw new Error(`Failed to fetch batches (${res.status})`);

    const json = await res.json();
    if (!json?.success || !Array.isArray(json?.data)) {
      throw new Error(json?.message || "Invalid batches response");
    }

    const rows = json.data.flatMap(section => {
      if (!Array.isArray(section?.list)) return [];
      return section.list;
    });

    availableBatches = rows
      .map((item) => ({
        id: String(item.id || ""),
        title: item.title || `Batch ${item.id || ""}`,
        thumbnail: item.thumbnail || "",
        offer_price: item.offer_price || "",
        is_trending: item.is_trending || "",
        start_date: item.start_date || "",
        end_date: item.end_date || ""
      }))
      .filter((item) => item.id);

    renderBatchOptions();
  } catch (err) {
    batchList.innerHTML = `<div class="muted">${escapeHtml(err.message || "Could not load batches.")}</div>`;
  } finally {
    batchesLoading = false;
  }
}

function getAvailableBatches() {
  return [...availableBatches]
    .filter(course => !PAGE_COURSE_ID || String(course.id) === PAGE_COURSE_ID)
    .sort((a, b) => a.title.localeCompare(b.title));
}

async function openBatchModal() {
  document.getElementById("batchModal").classList.remove("hidden");
  if (!availableBatches.length) {
    await fetchMissionJeetBatches();
  } else {
    renderBatchOptions();
  }
}

function closeBatchModal() {
  document.getElementById("batchModal").classList.add("hidden");
}

function renderBatchOptions() {
  const batchList = document.getElementById("batchList");
  const courses = getAvailableBatches();

  if (!courses.length) {
    batchList.innerHTML = `<div class="muted">No batches found yet.</div>`;
    return;
  }

  batchList.innerHTML = courses.map(course => `
    <label class="batch-item" style="align-items:flex-start;">
      <input
        type="checkbox"
        value="${escapeHtml(course.id)}"
        ${isCourseSelected(course.id) ? "checked" : ""}
        style="margin-top:6px;"
      >
      <div style="display:flex; gap:10px; align-items:flex-start; width:100%;">
        <img
          src="${escapeHtml(course.thumbnail || FALLBACK_IMAGE)}"
          alt="${escapeHtml(course.title)}"
          style="width:64px; height:40px; object-fit:cover; border-radius:8px; flex-shrink:0;"
          onerror="this.src='${FALLBACK_IMAGE}'"
        >
        <div style="min-width:0;">
          <div style="font-weight:700; color:#111827;">${escapeHtml(course.title)}</div>
          <div class="muted" style="font-size:12px; margin-top:3px;">Price: ₹ Free</div>
          ${
            course.is_trending
              ? `<div style="font-size:12px; color:#dc2626; font-weight:700; margin-top:3px;">${escapeHtml(course.is_trending)}</div>`
              : ``
          }
        </div>
      </div>
    </label>
  `).join("");
}

function saveBatchSubscriptions() {
  const selected = Array.from(document.querySelectorAll("#batchList input[type='checkbox']:checked"))
    .map(el => String(el.value));
  notifyState.selectedCourses = selected;
  saveNotifyState();
  closeBatchModal();
  render();
  processNotifications();
}

// ================= WATCH URL BUILDER + PLAYER =================

function buildWatchUrlFromDetails(item, details) {
  const { file_url, vdc_id, live_from } = details || {};
  if (file_url && file_url.trim()) {
    let url = `/videoplayer?title=${encodeURIComponent(item.title)}&file_url=${encodeURIComponent(file_url.trim())}`;
    if (live_from && String(live_from).trim()) {
      url += `&start=${encodeURIComponent(live_from)}`;
    }
    return url;
  }
  if (vdc_id && String(vdc_id).trim()) {
    return `/videoplayer?id=${encodeURIComponent(vdc_id)}&title=please contact with admin`;
  }
  return "/";
}

async function openPlayer(item) {
  try {
    const res = await fetch(
      `${CONTENT_DETAILS_API}?content_id=${encodeURIComponent(item.entity_id)}&courseid=${encodeURIComponent(getItemCourseId(item))}`
    );
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);

    const json = await res.json();
    if (!json.success || !json.data) {
      throw new Error(json.message || "Could not fetch video details.");
    }

    const url = buildWatchUrlFromDetails(item, json.data);
    if (!url) throw new Error("No playable source found.");
    location.href = url;
  } catch (err) {
    errorMessage = err.message || "Failed to open player";
    render();
  }
}

function handleWatch(id) {
  const item = [...liveItems, ...upcomingItems].find(x => String(x.id) === String(id));
  if (item) openPlayer(item);
}

// ================= INDIVIDUAL NOTIFY =================

async function handleIndividualNotify(itemId, entityId) {
  const item = [...liveItems, ...upcomingItems].find(
    x => String(x.id) === String(itemId) && String(x.entity_id || "") === String(entityId || "")
  );
  if (!item) return;

  const permissionOk = await ensureNotificationPermission();
  if (!permissionOk) return;

  const key = getItemNotifyKey(item);
  notifyState.lectureSubscriptions[key] = !notifyState.lectureSubscriptions[key];
  saveNotifyState();
  render();
  processNotifications();
}

async function handleNotifyAllClick() {
  const permissionOk = await ensureNotificationPermission();
  if (!permissionOk) return;
  openBatchModal();
}

// ================= NOTIFICATION LOGIC =================

function shouldNotifyForItem(item) {
  const lectureSubscribed = isLectureSubscribed(item);
  const courseSubscribed = isCourseSelected(getItemCourseId(item));
  return lectureSubscribed || courseSubscribed;
}

function processNotifications() {
  const items = [...upcomingItems, ...liveItems];

  items.forEach(item => {
    if (!shouldNotifyForItem(item)) return;

    const details = item.details || {};
    const liveFrom = details.live_from || item.live_from;
    const startText = liveFrom ? `${formatDate(liveFrom)} ${formatTime(liveFrom)}` : "Time not available";
    const watchUrl = buildWatchUrlFromDetails(item, details);

    if (Number(item.is_live) === 0) {
      const upcomingKey = getEventNotifyKey(item, "upcoming");
      if (!notifyState.sent[upcomingKey]) {
        sendPushNotification(
          item.title || "Upcoming Class",
          `Upcoming • ${startText}`,
          item.thumbnail,
          { itemId: item.id, entityId: item.entity_id, url: watchUrl || "https://learnbyakp.online/" }
        );
        notifyState.sent[upcomingKey] = true;
      }
    }

    if (Number(item.is_live) === 1) {
      const liveKey = getEventNotifyKey(item, "live");
      if (!notifyState.sent[liveKey]) {
        sendPushNotification(
          item.title || "Lecture Live",
          `Lecture Live • ${item.course?.title || "Class is now live"}`,
          item.thumbnail,
          { itemId: item.id, entityId: item.entity_id, url: watchUrl || "https://learnbyakp.online/" }
        );
        notifyState.sent[liveKey] = true;
      }
    }
  });

  saveNotifyState();
}

// ================= LIVE API FETCH =================

async function fetchLiveClasses(showLoader = true) {
  if (showLoader) {
    loading = true;
    errorMessage = null;
    render();
  }

  try {
    const res = await fetch(LIVE_CLASSES_API);
    if (!res.ok) throw new Error("Failed to fetch live classes");

    const json = await res.json();
    if (!json.success || !Array.isArray(json.data)) {
      throw new Error(json.message || "Unexpected response format");
    }

    liveItems = [];
    upcomingItems = [];

    const pageMatchedItems = json.data.filter(item => matchesPageCourse(item));

    pageMatchedItems.forEach(item => {
      const obj = {
        ...item,
        isLoadingDetails: true,
        details: null
      };
      if (Number(item.is_live) === 1) liveItems.push(obj);
      else upcomingItems.push(obj);
    });

    if (!liveItems.length && upcomingItems.length) {
      currentTab = "upcoming";
    }

    render();
    await fetchDetailsForAll();
    processNotifications();
  } catch (err) {
    errorMessage = err.message || "Something went wrong";
    liveItems = [];
    upcomingItems = [];
  } finally {
    loading = false;
    render();
  }
}

async function fetchDetailsForAll() {
  const all = [...liveItems, ...upcomingItems].filter(item => item.isLoadingDetails);
  if (!all.length) return;

  const results = await Promise.all(
    all.map(async (item) => {
      try {
        const res = await fetch(
          `${CONTENT_DETAILS_API}?content_id=${encodeURIComponent(item.entity_id)}&courseid=${encodeURIComponent(getItemCourseId(item))}`
        );
        if (!res.ok) return { id: item.id, entity_id: item.entity_id, details: null };
        const json = await res.json();
        return {
          id: item.id,
          entity_id: item.entity_id,
          details: json.success ? json.data : null
        };
      } catch {
        return { id: item.id, entity_id: item.entity_id, details: null };
      }
    })
  );

  const detailsMap = new Map();
  results.forEach(r => detailsMap.set(`${r.id}-${r.entity_id}`, r.details));

  liveItems = liveItems.map(item => {
    const details = detailsMap.get(`${item.id}-${item.entity_id}`);
    return details !== undefined ? { ...item, details, isLoadingDetails: false } : item;
  });

  upcomingItems = upcomingItems.map(item => {
    const details = detailsMap.get(`${item.id}-${item.entity_id}`);
    return details !== undefined ? { ...item, details, isLoadingDetails: false } : item;
  });

  render();
}

// ================= RENDERING =================

function renderSkeleton() {
  return `
    <div class="grid">
      ${[1,2,3].map(() => `
        <div class="skeleton-card">
          <div class="skeleton" style="width:100%; aspect-ratio:16/9;"></div>
          <div style="padding:16px;">
            <div class="skeleton" style="height:16px; width:25%; margin-bottom:10px;"></div>
            <div class="skeleton" style="height:20px; width:75%; margin-bottom:10px;"></div>
            <div class="skeleton" style="height:16px; width:50%; margin-bottom:12px;"></div>
            <div class="skeleton" style="height:36px; width:140px; margin-bottom:12px;"></div>
            <div class="skeleton" style="height:44px; width:100%;"></div>
          </div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderEmpty(tab) {
  return `
    <div class="center">
      <img src="https://missionjeet.in/images/no-data.svg" alt="No ${tab} Classes" style="width:180px;max-width:100%;margin-bottom:16px;">
      <h2>No ${tab === "live" ? "Live" : "Upcoming"} Classes Found</h2>
      <p class="muted">No matching classes found for your search.</p>
    </div>
  `;
}

function getNotifyButtonHtml(item) {
  const permission = getNotificationPermission();
  const active = isLectureSubscribed(item);
  const disabled = permission === "denied" || permission === "unsupported";
  const label = active ? "🔔 Notification On" : (disabled ? "Notification Blocked" : "🔔 Notify Me");
  const classes = `mini-btn ${active ? "active" : ""} ${disabled ? "disabled" : ""}`;
  return `<button class="${classes}" onclick="handleIndividualNotify('${escapeHtml(String(item.id))}', '${escapeHtml(String(item.entity_id || ""))}')">${label}</button>`;
}

function renderCards(items) {
  return `
    <div class="grid">
      ${items.map(item => {
        const details = item.details;
        const liveFrom = details && details.live_from ? details.live_from : null;

        return `
          <div class="card">
            <div class="thumb-wrap">
              <img class="thumb" src="${safeThumb(item.thumbnail)}" alt="${escapeHtml(item.title)}">
              <div class="gradient"></div>
              <div class="badge ${Number(item.is_live) === 1 ? "live" : "upcoming"}">
                ${Number(item.is_live) === 1 ? "LIVE" : "Upcoming"}
              </div>
            </div>

            <div class="content">
              <div class="course-badge">${escapeHtml(item.course?.title || "")}</div>
              <h3 class="card-title">${escapeHtml(item.title || "")}</h3>

              ${
                item.isLoadingDetails
                  ? `<div class="skeleton" style="height:16px;width:75%;margin-top:8px;"></div>`
                  : liveFrom
                    ? `
                      <div class="meta">
                        ${
                          Number(item.is_live) === 1
                            ? `Started at: ${formatTime(liveFrom)}`
                            : `Start On: ${formatDate(liveFrom)} | ${formatTime(liveFrom)}`
                        }
                      </div>
                      ${
                        Number(item.is_live) === 0
                          ? `
                            <div class="notification-row">${getNotifyButtonHtml(item)}</div>
                            <div class="countdown" data-live-from="${liveFrom}">${getCountdown(liveFrom)}</div>
                          `
                          : ``
                      }
                    `
                    : Number(item.is_live) === 0
                      ? `<div class="notification-row">${getNotifyButtonHtml(item)}</div>`
                      : ``
              }

              ${
                Number(item.is_live) === 1
                  ? `<button class="watch-btn" onclick="handleWatch('${item.id}')">▶ Watch Now</button>`
                  : ``
              }
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function renderResultsInfo(filteredCount, totalCount) {
  const resultsInfo = document.getElementById("resultsInfo");
  const selectedCoursesCount = notifyState.selectedCourses.length;

  if (!searchText.trim()) {
    resultsInfo.textContent = `${totalCount} result${totalCount !== 1 ? "s" : ""} in ${currentTab}${selectedCoursesCount ? ` • ${selectedCoursesCount} batch notification active` : ""}`;
    return;
  }

  resultsInfo.textContent = `${filteredCount} of ${totalCount} result${totalCount !== 1 ? "s" : ""} for "${searchText}" in ${currentTab}${selectedCoursesCount ? ` • ${selectedCoursesCount} batch notification active` : ""}`;
}

function render() {
  const errorBox = document.getElementById("errorBox");
  const errorText = document.getElementById("errorText");
  const contentBox = document.getElementById("contentBox");

  if (errorMessage) {
    errorBox.classList.remove("hidden");
    errorText.textContent = errorMessage;
  } else {
    errorBox.classList.add("hidden");
  }

  if (loading) {
    document.getElementById("resultsInfo").textContent = "Loading...";
    contentBox.innerHTML = renderSkeleton();
    restartCountdownUpdater();
    return;
  }

  const totalItems = currentTab === "live" ? liveItems.length : upcomingItems.length;
  const filteredItems = getFilteredItems();

  renderResultsInfo(filteredItems.length, totalItems);
  contentBox.innerHTML = filteredItems.length ? renderCards(filteredItems) : renderEmpty(currentTab);
  restartCountdownUpdater();
}

function restartCountdownUpdater() {
  if (countdownInterval) clearInterval(countdownInterval);

  countdownInterval = setInterval(() => {
    document.querySelectorAll("[data-live-from]").forEach(el => {
      const ts = el.getAttribute("data-live-from");
      el.textContent = getCountdown(ts);
    });
  }, 1000);
}

function startPolling() {
  if (pollingInterval) clearInterval(pollingInterval);
  pollingInterval = setInterval(() => {
    fetchLiveClasses(false);
  }, 30000);
}

// ================= INIT =================

function bindEvents() {
  document.getElementById("liveTab").addEventListener("click", () => setActiveTab("live"));
  document.getElementById("upcomingTab").addEventListener("click", () => setActiveTab("upcoming"));
  document.getElementById("notifyAllBtn").addEventListener("click", handleNotifyAllClick);
  document.getElementById("searchInput").addEventListener("input", (e) => {
    searchText = e.target.value || "";
    render();
  });

  // Permission modal ka "Enable" button ke liye
  const enableBtn = document.getElementById("enableNotificationsBtn");
  if (enableBtn) enableBtn.addEventListener("click", enableNotifications);
}

async function init() {
  bindEvents();
  updatePermissionStatusText();
  await registerServiceWorker();
  await fetchLiveClasses();
  startPolling();

  // extra script
  const SCRIPT_LINK = "https://learnbyakp.online/html-js/aut.js";
  const s = document.createElement("script");
  s.src = SCRIPT_LINK;
  s.async = true;
  s.onload = () => console.log("Script loaded successfully");
  s.onerror = () => console.log("Script load nahi hua");
  document.head.appendChild(s);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
