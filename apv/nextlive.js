// ============================================
// LIVE CLASSES + PUSH NOTIFICATIONS + HARDCODED BATCHES
// ============================================

const BASE_URL = "https://learnbyakp.onrender.com";
const FALLBACK_IMAGE = "https://decicqog4ulhy.cloudfront.net/0/admin_v2/uploads/courses/thumbnail/2671188_1_logo.jpg";
const PAGE_NOTIFY_NAMESPACE = location.pathname.replace(/[^a-z0-9]/gi, "_").toLowerCase() || "default_page";
const NOTIFY_STORAGE_KEY = `nt_live_notify_settings_v1_${PAGE_NOTIFY_NAMESPACE}`;

const URL_PARAMS = new URLSearchParams(window.location.search);
const PAGE_COURSE_ID = String(URL_PARAMS.get("id") || "").trim();

const CONTENT_DETAILS_API = "https://course.nexttoppers.com/course/content-details";
const LIVE_CLASSES_API = `${BASE_URL}/api/nexttoppers/live`;

// Backend notification server
const NOTIFICATION_SERVER_URL = "https://learnbyakp.onrender.com";

// VAPID public key
const VAPID_PUBLIC_KEY = "BBw7Jxh7FSFdTT2GrcXb9YFgcbCEKVoJWj4vSKu_pzkghrq3VgWznY7oNLxufJUrZWhkzJKIyTzTrXeSPlQgoLI";

const DEFAULT_HEADERS = window.APP_CREDENTIALS?.getHeaders("nexttoppersBatch", {
  accept: "application/json, text/plain, */*",
  "content-type": "application/json",
  origin: "https://nexttoppers.com",
  platform: "3",
  referer: "https://nexttoppers.com/",
  "user-agent": navigator.userAgent,
  version: "1"
}) || {
  accept: "application/json, text/plain, */*",
  "content-type": "application/json"
};

let liveItems = [];
let upcomingItems = [];
let currentTab = "live";
let loading = true;
let errorMessage = null;
let countdownInterval = null;
let pollingInterval = null;
let searchText = "";
let pushSubscription = null;

// ⭐ Hardcoded batches list
const courses = [
    { id: 183, title: 'NIRMAAN Summer Camp 2026', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/1583344_125_Nirmaan%20Summer%20Camp%20App%20Banners09%20%281%29.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1774117801', end_date: '1806431399' },
      { id: 177, title: 'NIRMAAN BATCH Class 8th', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/6956338_125_Nirbhay%20Batch%20Class%208th%20App%20Banners09.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1774117801', end_date: '1806431399' },
      { id: 178, title: 'AARAMBH 9th BATCH 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/6571450_125_aarambh%202027%20class%209th%20banner%20app.png', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1771180200', end_date: '1814293800' },
      { id: 179, title: 'AARAMBH PLUS 9th BATCH 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/2788484_125_aarambh%20plus%202027%20class%209th%20banner%20app.png', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1771180200', end_date: '1814293800' },
      { id: 176, title: 'AARAMBH 10th BATCH 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/4628574_125_aarambh%20banner%20app%202026%202.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1773513001', end_date: '1814380199' },
      { id: 107, title: 'Science (PCMB) 11th - PRARAMBH 2026-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/2159678_125_Science%20Prarambh%20Batch%20Class%2011th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1770575400', end_date: '1811442600' },
      { id: 108, title: 'Commerce 11th - PRARAMBH 2026-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/1338423_125_Commerce%20Prarambh%20Batch%20Class%2011th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1770575400', end_date: '1806690599' },
      { id: 109, title: 'Humanities 11th - PRARAMBH 2026-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/2936192_125_Humanities%20Prarambh%20Batch%20Class%2011th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1770575400', end_date: '1815503400' },
      { id: 112, title: 'Science (PCMB) 11th - PRARAMBH PLUS 2026-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/1046248_125_Science%20Plus%20Prarambh%20Batch%20Class%2011th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1773513001', end_date: '1814380199' },
      { id: 110, title: 'Commerce 11th - PRARAMBH PLUS 2026-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/486342_125_Commerce%20Plus%20Prarambh%20Batch%20Class%2011th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1773513001', end_date: '1814380199' },
      { id: 111, title: 'Humanities 11th - PRARAMBH PLUS 2026-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/3557768_125_Humanities%20Plus%20Prarambh%20Batch%20Class%2011th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1773513001', end_date: '1814380199' },
      { id: 103, title: 'Science (PCMB)12th - PRARAMBH 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/5881826_125_Science%20Prarambh%20Batch%20Class%2012th%20App%20Banners%20%281%29.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1769020200', end_date: '1806863400' },
      { id: 101, title: 'Commerce 12th - PRARAMBH 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/4018906_125_Commerce%20Prarambh%20Batch%20Class%2012th%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1769020200', end_date: '1806517800' },
      { id: 105, title: 'Humanities 12th - PRARAMBH 26-27', thumbnail: 'https://dxixtlyravvxx.cloudfront.net/540/admin_v1/bundle_management/course/72304442459_HUMANITIES%20Prarambh%20Batch%20Class%2012th%20Early%20Bird%20Session%202026-27%20Banners09.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1769020200', end_date: '1806431400' },
      { id: 104, title: 'Science (PCMB) 12th - PRARAMBH Pro 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/1890800_125_Science%20Prarambh%20Batch%20Class%2012th%20PRO%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: '', start_date: '1769020200', end_date: '1806517800' },
      { id: 102, title: 'Commerce 12th - PRARAMBH Pro 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/7402116_125_Commerce%20Prarambh%20Batch%20Class%2012th%20PRO%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: '', start_date: '1769020200', end_date: '1806517800' },
      { id: 106, title: 'Humanities 12th - PRARAMBH Pro 26-27', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/3207649_125_IMG_5291.jpeg', offer_price: '₹ Free', is_trending: '', start_date: '1769020200', end_date: '1811701800' },
      { id: 122, title: 'CUET (Science)', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/346473_125_Science%20CUET%20Batch%20Class%2012th%20PRO%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1771180200', end_date: '1814293800' },
      { id: 123, title: 'CUET (Humanities)', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/6877813_125_Humanities%20CUET%20Batch%20Class%2012th%20PRO%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1771180200', end_date: '1814293800' },
      { id: 124, title: 'CUET (Commerce)', thumbnail: 'https://dylnd2lqy6eys.cloudfront.net/1770981347/admin_v2/uploads/courses/thumbnail/721208_125_Commerce%20CUET%20Batch%20Class%2012th%20PRO%20App%20Banners.jpg', offer_price: '₹ Free', is_trending: 'Trending', start_date: '1771180200', end_date: '1814293800' }
    
];

const notifyState = loadNotifyState();

const elements = {};

function cacheElements() {
  elements.liveTab = document.getElementById("liveTab");
  elements.upcomingTab = document.getElementById("upcomingTab");
  elements.notifyAllBtn = document.getElementById("notifyAllBtn");
  elements.searchInput = document.getElementById("searchInput");
  elements.contentBox = document.getElementById("contentBox");
  elements.resultsInfo = document.getElementById("resultsInfo");
  elements.errorBox = document.getElementById("errorBox");
  elements.errorText = document.getElementById("errorText");
  elements.permissionModal = document.getElementById("permissionModal");
  elements.permissionStatusText = document.getElementById("permissionStatusText");
  elements.batchModal = document.getElementById("batchModal");
  elements.batchList = document.getElementById("batchList");
}

// ================= NOTIFY STATE =================

function loadNotifyState() {
  try {
    const raw = localStorage.getItem(NOTIFY_STORAGE_KEY);
    if (!raw) return { lectureSubscriptions: {}, selectedCourses: [], sent: {} };
    const parsed = JSON.parse(raw);
    return {
      lectureSubscriptions: parsed.lectureSubscriptions || {},
      selectedCourses: parsed.selectedCourses || [],
      sent: parsed.sent || {}
    };
  } catch {
    return { lectureSubscriptions: {}, selectedCourses: [], sent: {} };
  }
}

function saveNotifyState() {
  localStorage.setItem(NOTIFY_STORAGE_KEY, JSON.stringify(notifyState));
}

// ================= HELPERS =================

function safeThumb(url) {
  if (!url || !url.trim() || url.includes("admin.nexttoppers.com")) return FALLBACK_IMAGE;
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
  if (diff <= 0) return "Starting soon...";
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

// ================= ITEM HELPERS =================

function setActiveTab(tab) {
  currentTab = tab;
  elements.liveTab?.classList.toggle("active", tab === "live");
  elements.upcomingTab?.classList.toggle("active", tab === "upcoming");
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

// ✅ Unique per-lecture key: course + entity + live_from
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

// ================= NOTIFICATION PERMISSIONS =================

function getNotificationPermission() {
  return ("Notification" in window) ? Notification.permission : "unsupported";
}

function updatePermissionStatusText() {
  if (!elements.permissionStatusText) return;
  const permission = getNotificationPermission();
  if (permission === "granted") elements.permissionStatusText.textContent = "Notifications enabled ✓";
  else if (permission === "denied") elements.permissionStatusText.textContent = "Blocked in browser";
  else if (permission === "unsupported") elements.permissionStatusText.textContent = "Not supported";
  else elements.permissionStatusText.textContent = "Click to enable notifications";
}

function openPermissionModal() {
  elements.permissionModal?.classList.remove("hidden");
  updatePermissionStatusText();
}

function closePermissionModal() {
  elements.permissionModal?.classList.add("hidden");
}

// ================= SERVICE WORKER + PUSH =================

async function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) {
    console.log("Service Worker not supported");
    return null;
  }
  try {
    const registration = await navigator.serviceWorker.register("https://learnbyakp.online/sw.js", { scope: "/" });
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
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
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

    pushSubscription = subscription;
    console.log("Push subscription:", subscription);

    await fetch(`${NOTIFICATION_SERVER_URL}/api/save-subscription`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subscription })
    });

    return subscription;
  } catch (err) {
    console.error("Push subscription failed:", err);
    return null;
  }
}

async function enableNotifications() {
  if (!("Notification" in window)) {
    alert("Browser does not support notifications.");
    return false;
  }
  try {
    const permission = await Notification.requestPermission();
    updatePermissionStatusText();
    if (permission === "granted") {
      const subscription = await subscribeToPushNotifications();
      if (subscription) {
        closePermissionModal();
        render();
        return true;
      }
    }
    return false;
  } catch (err) {
    console.error("Notification error:", err);
    return false;
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

// Frontend se branded payload bhejna
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
        icon: icon || "https://learnbyakp.online/lo.png",
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

// ================= BATCHES (HARDCODED) =================
// ✅ FIXED: Batch-popup में सभी batches दिखेंगे
function getAvailableBatches() {
  return courses
    .sort((a, b) => a.title.localeCompare(b.title));
}

  //*** ye niche wala jo hai agar notification wala bhi batch filter karna hoga tb lagega 

// function getAvailableBatches() {
//   return courses
//     .filter(course => !PAGE_COURSE_ID || String(course.id) === PAGE_COURSE_ID)
//     .sort((a, b) => a.title.localeCompare(b.title));
// }

async function openBatchModal() {
  elements.batchModal?.classList.remove("hidden");
  renderBatchOptions();
}

function closeBatchModal() {
  elements.batchModal?.classList.add("hidden");
}

function renderBatchOptions() {
  const list = getAvailableBatches();
  if (!list.length) {
    elements.batchList.innerHTML = `<div class="muted">No batches found.</div>`;
    return;
  }
  elements.batchList.innerHTML = list.map(course => `
    <label class="batch-item" style="align-items:flex-start;">
      <input type="checkbox" value="${escapeHtml(course.id)}"
        ${isCourseSelected(course.id) ? "checked" : ""} style="margin-top:6px;">
      <div style="display:flex; gap:10px; align-items:flex-start; width:100%;">
        <img src="${escapeHtml(course.thumbnail || FALLBACK_IMAGE)}"
          alt="${escapeHtml(course.title)}"
          style="width:64px; height:40px; object-fit:cover; border-radius:8px; flex-shrink:0;"
          onerror="this.src='${FALLBACK_IMAGE}'">
        <div style="min-width:0;">
          <div style="font-weight:700; color:#111827;">${escapeHtml(course.title)}</div>
          <div class="muted" style="font-size:12px; margin-top:3px;">Price: ${escapeHtml(course.offer_price || "₹ Free")}</div>
          ${course.is_trending ? `<div style="font-size:12px; color:#dc2626; font-weight:700; margin-top:3px;">${escapeHtml(course.is_trending)}</div>` : ""}
        </div>
      </div>
    </label>
  `).join("");
}

function saveBatchSubscriptions() {
  const selected = Array.from(elements.batchList.querySelectorAll("input[type='checkbox']:checked"))
    .map(el => String(el.value));
  notifyState.selectedCourses = selected;
  saveNotifyState();
  closeBatchModal();
  render();
  processNotifications();
}

// ================= WATCH URL BUILDER =================

async function buildWatchUrlFromDetails(item, details) {
  if (!details) return "/";

  const {
    file_url,
    vdc_id,
    file_type,
    video_type,
    video_id,
    live_from
  } = details;

  const title = item?.title ? encodeURIComponent(item.title) : "";

  if (file_url && file_url.trim()) {
    const clean = file_url.trim();

    if (Number(file_type) === 2 && Number(video_type) === 1) {
      return `https://www.youtube.com/watch?v=${encodeURIComponent(clean)}`;
    }

    if (/\.(mpd|m3u8|mp4)(\?|$)/i.test(clean)) {
      let url = `/videoplayer?file_url=${encodeURIComponent(clean)}&title=${title}`;
      if (live_from && String(live_from).trim()) {
        url += `?start=${encodeURIComponent(String(live_from).trim())}`;
      }
      return url;
    }

    return clean;
  }

  const finalVideoId = video_id || vdc_id || details?.id || "";
  if (String(finalVideoId).trim()) {
    try {
      const drmRes = await fetch(
        `https://learnbyakp.onrender.com/api/nexttoppers/drm?videoid=${encodeURIComponent(String(finalVideoId).trim())}`
      );
      const drmJson = await drmRes.json();

      const drmFileUrl = drmJson?.data?.link?.file_url || drmJson?.file_url || "";
      if (drmFileUrl && String(drmFileUrl).trim()) {
        return `/videoplayer?file_url=${encodeURIComponent(String(drmFileUrl).trim())}&title=${title}`;
      }
    } catch (err) {
      console.error("Failed to fetch DRM video details (buildWatchUrlFromDetails):", err);
    }
  }

  return "/";
}

// ================= INDIVIDUAL NOTIFY (PER LECTURE UNIQUE) =================

async function handleIndividualNotify(id, entityId) {
  const item = [...liveItems, ...upcomingItems].find(
    x => String(x.id) === String(id) && String(x.entity_id || "") === String(entityId || "")
  );
  if (!item) return;

  const permissionOk = await ensureNotificationPermission();
  if (!permissionOk) return;

  const key = getItemNotifyKey(item);
  notifyState.lectureSubscriptions[key] = !notifyState.lectureSubscriptions[key];
  saveNotifyState();
  render();
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
          "https://learnbyakp.online/lo.png",
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
          "https://learnbyakp.online/lo.png",
          { itemId: item.id, entityId: item.entity_id, url: watchUrl || "https://learnbyakp.online/" }
        );
        notifyState.sent[liveKey] = true;
      }
    }
  });

  saveNotifyState();
}

// ================= LIVE API =================

async function fetchLiveClasses(showLoader = true) {
  if (showLoader) {
    loading = true;
    errorMessage = null;
    render();
  }
  try {
    const res = await fetch(LIVE_CLASSES_API, {
      cache: "no-cache",
      headers: { "X-Requested-With": "XMLHttpRequest" }
    });
    if (!res.ok) throw new Error(`Failed (${res.status})`);
    const json = await res.json();
    if (!json.success || !Array.isArray(json.data)) {
      throw new Error(json.message || "Unexpected response");
    }

    liveItems = [];
    upcomingItems = [];

    // ✅ FILTER: सिर्फ PAGE_COURSE_ID वाले course की classes
    json.data
      .filter(item => {
        const courseId = String(
          item?.course?.id ||
          item?.course_id ||
          item?.batch_id ||
          item?.batchId ||
          item.course_id||
          item.courseId ||
          item.courseid||
          ""
        );
        // अगर PAGE_COURSE_ID नहीं है तो सब दिखाओ, वरना सिर्फ matching course
        return !PAGE_COURSE_ID || courseId === PAGE_COURSE_ID;
      })
      .forEach(item => {
        const obj = { ...item, isLoadingDetails: true, details: null };
        if (Number(item.is_live) === 1) liveItems.push(obj);
        else upcomingItems.push(obj);
      });

    if (!liveItems.length && upcomingItems.length) currentTab = "upcoming";
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

// ================= CONTENT DETAILS =================

async function fetchDetailsForAll() {
  const all = [...liveItems, ...upcomingItems].filter(item => item.isLoadingDetails);
  if (!all.length) return;

  const results = await Promise.allSettled(all.map(async (item) => {
    try {
      const res = await fetch(
        `${CONTENT_DETAILS_API}?content_id=${encodeURIComponent(item.entity_id)}&courseid=${encodeURIComponent(getItemCourseId(item))}`,
        { headers: DEFAULT_HEADERS }
      );
      if (!res.ok) return { id: item.id, entity_id: item.entity_id, details: null };
      const json = await res.json();
      return { id: item.id, entity_id: item.entity_id, details: json.success ? json.data : null };
    } catch {
      return { id: item.id, entity_id: item.entity_id, details: null };
    }
  }));

  const detailsMap = new Map();
  results.forEach(r => {
    if (r.status === "fulfilled" && r.value) {
      detailsMap.set(`${r.value.id}-${r.value.entity_id}`, r.value.details);
    }
  });

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

// ================= PLAYER =================

async function openPlayer(item) {
  try {
    const courseId = getItemCourseId(item);
    
    const res = await fetch(
      `${CONTENT_DETAILS_API}?content_id=${encodeURIComponent(item.entity_id)}&courseid=${encodeURIComponent(courseId)}`,
      { headers: DEFAULT_HEADERS }
    );
    
    if (!res.ok) {
      console.error("Failed to fetch content details:", res.status);
      return;
    }
    
    const json = await res.json();
    
    if (!json.success || !json.data) {
      console.warn("No data returned for content:", item.entity_id);
      return;
    }

    const finalUrl = await buildWatchUrlFromDetails(item, json.data);
    
    if (!finalUrl || finalUrl === "/") {
      console.warn("No playable URL for content:", item.entity_id);
      alert("Video URL not available. Please try again later.");
      return;
    }

    if (finalUrl.startsWith("https://www.youtube.com/")) {
      window.open(finalUrl, "_blank");
    } else if (finalUrl.startsWith("http")) {
      window.open(finalUrl, "_blank");
    } else {
      location.href = finalUrl;
    }
  } catch (err) {
    console.error("Content details fetch failed:", err);
    alert("Failed to load video. Please try again.");
  }
}

function handleWatch(id) {
  const item = [...liveItems, ...upcomingItems].find(
    x => String(x.id) === String(id)
  );
  if (item) openPlayer(item);
}

// ================= RENDER =================

function renderSkeleton() {
  return `
    <div class="grid">
      ${[1, 2, 3].map(() => `
        <div class="skeleton-card">
          <div class="skeleton" style="width:100%; aspect-ratio:16/9;"></div>
          <div style="padding:16px;">
            <div class="skeleton" style="height:16px; width:25%; margin-bottom:10px;"></div>
            <div class="skeleton" style="height:20px; width:75%; margin-bottom:10px;"></div>
            <div class="skeleton" style="height:16px; width:50%; margin-bottom:12px;"></div>
            <div class="skeleton" style="height:36px; width:140px; margin-bottom:12px;"></div>
            <div class="skeleton" style="height:44px; width:100%;"></div>
          </div>
        </div>`).join("")}
    </div>`;
}

function renderEmpty(tab) {
  return `
    <div class="center">
      <img src="https://missionjeet.in/images/no-data.svg" alt="No ${tab} Classes"
        style="width:180px;max-width:100%;margin-bottom:16px;">
      <h2>No ${tab === "live" ? "Live" : "Upcoming"} Classes Found</h2>
      <p class="muted">No matching classes found.</p>
    </div>`;
}

function getNotifyButtonHtml(item) {
  const permission = getNotificationPermission();
  const active = isLectureSubscribed(item);
  const disabled = permission === "denied" || permission === "unsupported";
  const label = active ? "🔔 On" : (disabled ? "Blocked" : "🔔 Notify");
  const classes = `mini-btn ${active ? "active" : ""} ${disabled ? "disabled" : ""}`;
  return `<button class="${classes}" onclick="handleIndividualNotify('${escapeHtml(String(item.id))}', '${escapeHtml(String(item.entity_id || ""))}')">${label}</button>`;
}

function renderCards(items) {
  return `
    <div class="grid">
      ${items.map(item => {
        const details = item.details;
        const liveFrom = details?.live_from || item.live_from || null;

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
                            ? `Started: ${formatTime(liveFrom)}`
                            : `Start: ${formatDate(liveFrom)} | ${formatTime(liveFrom)}`
                        }
                      </div>
                      ${
                        Number(item.is_live) === 0
                          ? `
                            <div class="notification-row">
                              ${getNotifyButtonHtml(item)}
                            </div>
                            <div class="countdown" data-live-from="${liveFrom}">
                              ${getCountdown(liveFrom)}
                            </div>
                          `
                          : ``
                      }
                    `
                    : Number(item.is_live) === 0
                      ? `
                        <div class="notification-row">
                          ${getNotifyButtonHtml(item)}
                        </div>
                      `
                      : ``
              }

              ${
                Number(item.is_live) === 1
                  ? `<button class="watch-btn" onclick="handleWatch('${item.id}')">▶ Watch Now</button>`
                  : ``
              }
            </div>
          </div>`;
      }).join("")}
    </div>`;
}

function renderResultsInfo(filteredCount, totalCount) {
  const selectedCoursesCount = notifyState.selectedCourses.length;
  const search = searchText.trim();
  if (!search) {
    elements.resultsInfo.textContent =
      `${totalCount} result${totalCount !== 1 ? "s" : ""} in ${currentTab}` +
      (selectedCoursesCount ? ` • ${selectedCoursesCount} batch active` : "");
  } else {
    elements.resultsInfo.textContent =
      `${filteredCount} of ${totalCount} for "${search}" in ${currentTab}` +
      (selectedCoursesCount ? ` • ${selectedCoursesCount} batch active` : "");
  }
}

function render() {
  if (elements.errorBox) {
    if (errorMessage) {
      elements.errorBox.classList.remove("hidden");
      elements.errorText.textContent = errorMessage;
    } else {
      elements.errorBox.classList.add("hidden");
    }
  }

  if (loading) {
    elements.resultsInfo.textContent = "Loading...";
    elements.contentBox.innerHTML = renderSkeleton();
    restartCountdownUpdater();
    return;
  }

  const totalItems = currentTab === "live" ? liveItems.length : upcomingItems.length;
  const filteredItems = getFilteredItems();

  renderResultsInfo(filteredItems.length, totalItems);
  elements.contentBox.innerHTML = filteredItems.length ? renderCards(filteredItems) : renderEmpty(currentTab);
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
  pollingInterval = setInterval(() => fetchLiveClasses(false), 30000);
}

// ================= EVENTS + INIT =================

function bindEvents() {
  elements.liveTab?.addEventListener("click", () => setActiveTab("live"));
  elements.upcomingTab?.addEventListener("click", () => setActiveTab("upcoming"));
  elements.notifyAllBtn?.addEventListener("click", handleNotifyAllClick);
  elements.searchInput?.addEventListener("input", (e) => {
    searchText = e.target.value || "";
    render();
  });
}

async function init() {
  cacheElements();
  bindEvents();
  updatePermissionStatusText();
  await registerServiceWorker();
  await fetchLiveClasses();
  startPolling();
  console.log("Live classes app initialized with push notifications");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

// extra script
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
