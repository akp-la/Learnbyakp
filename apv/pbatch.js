const customStaticBatches = [
  {
    batchId: "akp",
    batchName: "Learn By AKP",
    batchImage: "https://learnbyakp.online/lo.png",
    customLink: "https://learnbyakp.online",
    isCustomBatch: true,
    isTrending: false,
    badgeText: "⭐ Custom",
    classTags: ["8", "9", "10", "11", "12", "12+"]
  },
  {
    batchId: "6920510a70e5cf316c9e3000",
    batchName: "NEEV 2026 (Class 9th) Bangla",
    batchImage: "https://static.pw.live/5eb393ee95fab7468a79d189/ADMIN/41842634-58dc-499c-bfc6-a823f9c20670.png",
    isCustomBatch: true,
    isTrending: true,
    badgeText: "🔥 Trending",
    classTags: ["9"]
  },
  {
    batchId: "6965fca6d66f9b9c382ae2ef",
    batchName: "Targeted Batch For NSEP Aspirants",
    batchImage: "https://static.pw.live/5eb393ee95fab7468a79d189/ADMIN/b0182df9-8837-4a4d-9c30-bf2f99e0b232.png",
    isCustomBatch: true,
    isTrending: true,
    badgeText: "🔥 Trending",
    classTags: ["12+"]
  }

  /*
  {
    batchId: "custom_unique_id_003",
    batchName: "Your Batch Title",
    batchImage: "https://example.com/banner.jpg",
    customLink: "https://example.com/batch-page",
    isCustomBatch: true,
    isTrending: true,
    badgeText: "🔥 Trending",
    classTags: ["11", "12"]
  }
  */
];

const API_BASE = "https://learnbyakp.onrender.com";

const CACHE_KEY = "pwBatchesCache";
const CACHE_TIME_KEY = "pwBatchesCacheTimestamp";
const ENROLLED_KEY = "enrolledBatches";
const CUSTOM_BATCHES_KEY = "akpCustomStaticBatches";

const DECRYPT_SECRET_KEY = "maggikhalo";

const isMobileDevice = window.innerWidth <= 620 || /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

const PAGE_SIZE = isMobileDevice ? 8 : 24;
const SEARCH_DELAY = isMobileDevice ? 420 : 180;

const trendingKeywords = [
  "Lakshya JEE 2027",
  "Lakshya NEET 2027",
  "AI & ChatGPT",
  "Mission 100 NEET",
  "Arjuna JEE 2027",
  "Arjuna NEET 2027",
  "Restart",
  "Udaan 2027",
  "Neev 2027",
  "Uday 2027",
  "Earn",
  "Parishram 2027"
].map(x => x.toLowerCase());

const blockedBatchNames = [
  "Little Masters 2026 (Class 5th)",
  "Summer Camp 2025 (Class 5th)",
  "Junoon (7th Class)",
  "Junoon 2025 (Class 7th)",
  "PW-NSAT Online -26 Nov (8th Foundation)",
  "NSAT 8th Foundation (13-Nov )",
  "Summer Camp 2025 (Class 8th)",
  "NMMSS Bihar 2025-26 (Class 8th)"
];

const blockedBatchSet = new Set(blockedBatchNames.map(x => x.toLowerCase()));

const fallbackImage = "https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png";

let allBatches = [];
let filteredBatches = [];
let selectedClasses = [];
let enrolledIds = [];
let currentPage = 1;
let isLoading = true;

let searchDebounceTimer = null;
let renderToken = 0;
let lastRenderedCount = 0;
let freshLoadStarted = false;

const $ = (id) => document.getElementById(id);

const batchGrid = $("batchGrid");
const statusArea = $("statusArea");
const loadWrap = $("loadWrap");
const loadMoreBtn = $("loadMoreBtn");
const searchInput = $("searchInput");
const clearSearch = $("clearSearch");

document.addEventListener("DOMContentLoaded", init);

function init(){
  injectMobilePerformanceCSS();
  setupEvents();
  loadTheme();
  showTelegramPopupOncePerSession();
  loadEnrolledIds();
  syncCustomBatchesToLocalStorage();

  const cacheLoaded = loadCacheInstant();

  if(!cacheLoaded){
    isLoading = true;
    renderSkeletons();
  }

  fetchFreshBatchesInBackground(cacheLoaded);
}

function injectMobilePerformanceCSS(){
  const style = document.createElement("style");
  style.textContent = `
    .card img{
      content-visibility:auto;
    }

    @media(max-width:620px){
      .app-header{
        backdrop-filter:none!important;
      }

      .grid{
        gap:14px!important;
      }

      .card{
        border-radius:18px!important;
        box-shadow:0 6px 14px rgba(15,23,42,.06)!important;
        transition:none!important;
      }

      .card:hover{
        transform:none!important;
        box-shadow:0 6px 14px rgba(15,23,42,.06)!important;
      }

      .thumb img{
        transform:none!important;
      }

      .btn,
      .icon-btn,
      .menu-panel,
      .drawer-panel,
      .toast{
        transition:none!important;
      }

      .toast{
        max-width:calc(100vw - 24px)!important;
        min-width:0!important;
      }

      .skeleton{
        animation:none!important;
      }
    }
  `;
  document.head.appendChild(style);
}

function setupEvents(){
  const searchToggle = $("searchToggle");
  const searchWrap = $("searchWrap");
  const menuToggle = $("menuToggle");
  const sideMenu = $("sideMenu");
  const filterBtn = $("filterBtn");
  const filterDrawer = $("filterDrawer");
  const copyReferral = $("copyReferral");
  const clearFilters = $("clearFilters");
  const themeToggle = $("themeToggle");
  const clearEnrollments = $("clearEnrollments");

  if(searchToggle){
    searchToggle.addEventListener("click", () => {
      searchWrap.classList.toggle("hidden");

      if(!searchWrap.classList.contains("hidden")){
        setTimeout(() => searchInput && searchInput.focus(), 50);
      }
    });
  }

  if(searchInput){
    searchInput.addEventListener("input", () => {
      clearSearch.classList.toggle("hidden", !searchInput.value.trim());

      clearTimeout(searchDebounceTimer);

      searchDebounceTimer = setTimeout(() => {
        currentPage = 1;
        resetGridRender();
        applyFiltersAndRender();
      }, SEARCH_DELAY);
    });
  }

  if(clearSearch){
    clearSearch.addEventListener("click", () => {
      searchInput.value = "";
      clearSearch.classList.add("hidden");
      currentPage = 1;
      resetGridRender();
      applyFiltersAndRender();
      searchInput.focus();
    });
  }

  if(menuToggle){
    menuToggle.addEventListener("click", () => {
      sideMenu.classList.add("open");
    });
  }

  document.querySelectorAll("[data-close-menu]").forEach(el => {
    el.addEventListener("click", () => sideMenu.classList.remove("open"));
  });

  if(filterBtn){
    filterBtn.addEventListener("click", () => {
      filterDrawer.classList.add("open");
    });
  }

  document.querySelectorAll("[data-close-filter]").forEach(el => {
    el.addEventListener("click", () => filterDrawer.classList.remove("open"));
  });

  document.querySelectorAll("[data-close-modal]").forEach(el => {
    el.addEventListener("click", () => $("telegramModal").classList.remove("show"));
  });

  if(copyReferral){
    copyReferral.addEventListener("click", copyReferralCode);
  }

  if(loadMoreBtn){
    loadMoreBtn.addEventListener("click", () => {
      currentPage++;
      renderVisibleBatches(false);
    });
  }

  if(clearFilters){
    clearFilters.addEventListener("click", () => {
      selectedClasses = [];
      currentPage = 1;
      renderClassFilters();
      resetGridRender();
      applyFiltersAndRender();
    });
  }

  if(themeToggle){
    themeToggle.addEventListener("click", toggleTheme);
  }

  if(clearEnrollments){
    clearEnrollments.addEventListener("click", () => {
      localStorage.removeItem(ENROLLED_KEY);
      enrolledIds = [];
      toast("Cleared", "All enrolled batches removed from this browser.");
      rerenderCurrentCards();
    });
  }

  if(batchGrid){
    batchGrid.addEventListener("click", handleBatchGridClick);
  }
}

function loadTheme(){
  const saved = localStorage.getItem("akpTheme");

  if(saved === "dark"){
    document.body.classList.add("dark");
  }

  const btn = $("themeToggle");
  if(btn){
    btn.textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
  }
}

function toggleTheme(){
  document.body.classList.toggle("dark");

  localStorage.setItem(
    "akpTheme",
    document.body.classList.contains("dark") ? "dark" : "light"
  );

  $("themeToggle").textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
}

function showTelegramPopupOncePerSession(){
  if(isMobileDevice) return;
  if(sessionStorage.getItem("telegramPopupSeen") === "1") return;

  setTimeout(() => {
    const modal = $("telegramModal");
    if(modal){
      modal.classList.add("show");
      sessionStorage.setItem("telegramPopupSeen", "1");
    }
  }, 900);
}

function loadEnrolledIds(){
  try{
    const saved = JSON.parse(localStorage.getItem(ENROLLED_KEY) || "[]");
    enrolledIds = saved.map(item => String(item.batchId || item.id || ""));
  }catch(err){
    console.error("Failed to parse enrolled batches", err);
    localStorage.removeItem(ENROLLED_KEY);
    enrolledIds = [];
  }
}

function syncCustomBatchesToLocalStorage(){
  const normalized = normalizeCustomBatches(customStaticBatches);
  localStorage.setItem(CUSTOM_BATCHES_KEY, JSON.stringify(normalized));
}

function getCustomStaticBatches(){
  try{
    const saved = JSON.parse(localStorage.getItem(CUSTOM_BATCHES_KEY) || "[]");

    if(Array.isArray(saved) && saved.length){
      return normalizeCustomBatches(saved);
    }
  }catch(err){
    console.error("Custom localStorage parse failed:", err);
  }

  return normalizeCustomBatches(customStaticBatches);
}

function loadCacheInstant(){
  try{
    const cached = localStorage.getItem(CACHE_KEY);

    if(!cached){
      return false;
    }

    const cacheBatches = JSON.parse(cached);

    if(!Array.isArray(cacheBatches) || !cacheBatches.length){
      return false;
    }

    allBatches = mergeCustomStaticBatches(cacheBatches);
    isLoading = false;
    currentPage = 1;
    resetGridRender();
    renderClassFilters();
    applyFiltersAndRender();

    return true;
  }catch(err){
    console.error("Cache instant load failed:", err);
    localStorage.removeItem(CACHE_KEY);
    localStorage.removeItem(CACHE_TIME_KEY);
    return false;
  }
}

async function fetchFreshBatchesInBackground(cacheAlreadyShown){
  if(freshLoadStarted) return;
  freshLoadStarted = true;

  try{
    const res = await fetch(`${API_BASE}/api/batches`, {
      method: "GET",
      headers: {
        "Accept": "application/json"
      },
      cache: "no-store"
    });

    if(!res.ok){
      throw new Error(`HTTP error! status: ${res.status}`);
    }

    const json = await res.json();
    const data = await extractBatchData(json);

    if(!Array.isArray(data)){
      throw new Error("Final batch data is not array.");
    }

    const normalizedApiBatches = normalizeBatches(data);
    const freshMerged = mergeCustomStaticBatches(normalizedApiBatches);

    localStorage.setItem(CACHE_KEY, JSON.stringify(normalizedApiBatches));
    localStorage.setItem(CACHE_TIME_KEY, Date.now().toString());

    allBatches = freshMerged;
    isLoading = false;
    currentPage = 1;
    resetGridRender();
    renderClassFilters();
    applyFiltersAndRender();

    if(cacheAlreadyShown){
      toast("Updated", "Fresh batches updated.");
    }else{
      toast("Success", "Batches loaded.");
    }
  }catch(err){
    console.error("Failed to fetch fresh batches:", err);
    isLoading = false;

    if(!allBatches.length){
      batchGrid.innerHTML = "";
      loadWrap.classList.add("hidden");

      statusArea.innerHTML = `
        <div class="empty">
          <h3>Unable to load batches</h3>
          <p>${escapeHtml(err.message)}</p>
          <br>
          <button class="btn primary" onclick="retryFreshLoad()">Retry</button>
        </div>
      `;
    }else{
      toast("Fresh load failed", err.message, "danger");
    }
  }
}

async function extractBatchData(json){
  if(Array.isArray(json)){
    return json;
  }

  if(json && Array.isArray(json.data)){
    return json.data;
  }

  if(json && typeof json.data === "string"){
    const decoded = await decryptBatchesData(json.data);

    if(decoded.success && Array.isArray(decoded.data)){
      return decoded.data;
    }

    throw new Error(decoded.error || "Failed to decrypt batch data.");
  }

  if(json && typeof json.result === "string"){
    const decoded = await decryptBatchesData(json.result);

    if(decoded.success && Array.isArray(decoded.data)){
      return decoded.data;
    }

    throw new Error(decoded.error || "Failed to decrypt result data.");
  }

  if(json && Array.isArray(json.batches)){
    return json.batches;
  }

  throw new Error("No batch data found in API response.");
}

async function makeAesGcmKey(secret){
  const encoded = new TextEncoder().encode(secret);
  const keyBytes = new Uint8Array(32);

  for(let i = 0; i < 32; i++){
    keyBytes[i] = i < encoded.length ? encoded[i] : 0;
  }

  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["decrypt"]
  );
}

function hexToUint8Array(hex){
  if(!hex || typeof hex !== "string"){
    throw new Error("Invalid hex string");
  }

  const cleanHex = hex.trim();

  if(cleanHex.length % 2 !== 0){
    throw new Error("Invalid hex length");
  }

  const parts = cleanHex.match(/.{1,2}/g);

  if(!parts){
    throw new Error("Invalid hex data");
  }

  return new Uint8Array(parts.map(byte => parseInt(byte, 16)));
}

async function decryptBatchesData(encryptedPayload){
  try{
    if(!encryptedPayload || typeof encryptedPayload !== "string"){
      throw new Error("Invalid encrypted payload");
    }

    if(!crypto || !crypto.subtle){
      throw new Error("Web Crypto API not available. Use HTTPS, localhost, or Live Server.");
    }

    const payload = encryptedPayload.trim();
    const [ivHex, encryptedHex] = payload.split(":");

    if(!ivHex || !encryptedHex){
      throw new Error("Invalid encrypted payload format.");
    }

    const iv = hexToUint8Array(ivHex);
    const encryptedBytes = hexToUint8Array(encryptedHex);
    const key = await makeAesGcmKey(DECRYPT_SECRET_KEY);

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      encryptedBytes
    );

    const decryptedText = new TextDecoder().decode(decryptedBuffer);
    return JSON.parse(decryptedText);
  }catch(error){
    console.error("Client-side decryption failed:", error);

    return {
      success:false,
      data:[],
      error:"Decryption failed: " + error.message
    };
  }
}

function normalizeBatches(data){
  return data.map(item => {
    const id =
      item.batchId ||
      item._id ||
      item.id ||
      item.batch_id ||
      item.batchID ||
      "";

    const name =
      item.batchName ||
      item.name ||
      item.title ||
      item.batch_name ||
      "Untitled Batch";

    const image =
      item.batchImage ||
      item.image ||
      item.previewImage ||
      item.thumbnail ||
      item.img ||
      fallbackImage;

    const normalized = {
      ...item,
      batchId: String(id),
      batchName: String(name),
      batchImage: String(image || fallbackImage),
      isCustomBatch: false,
      isTrending: Boolean(item.isTrending),
      badgeText: item.badgeText || "",
      customLink: item.customLink || "",
      classTags: Array.isArray(item.classTags) ? item.classTags.map(String) : []
    };

    normalized.searchText = createSearchText(normalized);
    normalized.sortText = normalized.batchName.toLowerCase();

    return normalized;
  }).filter(batch => batch.batchId && batch.batchName);
}

function normalizeCustomBatches(data){
  return data.map(item => {
    const id =
      item.batchId ||
      item._id ||
      item.id ||
      item.batch_id ||
      item.batchID ||
      "";

    const name =
      item.batchName ||
      item.name ||
      item.title ||
      item.batch_name ||
      "Untitled Custom Batch";

    const image =
      item.batchImage ||
      item.image ||
      item.previewImage ||
      item.thumbnail ||
      item.img ||
      fallbackImage;

    const normalized = {
      ...item,
      batchId: String(id),
      batchName: String(name),
      batchImage: String(image || fallbackImage),
      customLink: String(item.customLink || item.link || ""),
      isCustomBatch: true,
      isTrending: Boolean(item.isTrending),
      badgeText: String(item.badgeText || "⭐ Custom"),
      classTags: Array.isArray(item.classTags) ? item.classTags.map(String) : []
    };

    normalized.searchText = createSearchText(normalized);
    normalized.sortText = normalized.batchName.toLowerCase();

    return normalized;
  }).filter(item => item.batchId && item.batchName);
}

function mergeCustomStaticBatches(apiBatches){
  const map = new Map();

  normalizeBatches(apiBatches).forEach(batch => {
    map.set(String(batch.batchId || batch.id || ""), batch);
  });

  getCustomStaticBatches().forEach(batch => {
    map.set(String(batch.batchId || batch.id || ""), batch);
  });

  return Array.from(map.values());
}

function createSearchText(batch){
  const parts = [
    batch.batchId,
    batch.batchName,
    batch.name,
    batch.title,
    batch.batch_name,
    batch.badgeText,
    batch.customLink,
    Array.isArray(batch.classTags) ? batch.classTags.join(" ") : ""
  ];

  return parts
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function retryFreshLoad(){
  localStorage.removeItem(CACHE_KEY);
  localStorage.removeItem(CACHE_TIME_KEY);

  allBatches = [];
  filteredBatches = [];
  selectedClasses = [];
  currentPage = 1;
  lastRenderedCount = 0;
  freshLoadStarted = false;

  batchGrid.innerHTML = "";
  fetchFreshBatchesInBackground(false);
}

function getClasses(){
  const set = new Set();

  allBatches.forEach(batch => {
    const name = String(batch.batchName || "").toLowerCase();

    if(Array.isArray(batch.classTags)){
      batch.classTags.forEach(tag => set.add(String(tag)));
    }

    if(name.includes("class 6") || name.includes("6th")) set.add("6");
    if(name.includes("class 7") || name.includes("7th")) set.add("7");
    if(name.includes("class 8") || name.includes("8th")) set.add("8");
    if(name.includes("class 9") || name.includes("9th")) set.add("9");
    if(name.includes("class 10") || name.includes("10th")) set.add("10");
    if(name.includes("class 11") || name.includes("11th")) set.add("11");
    if(name.includes("class 12") || name.includes("12th")) set.add("12");
    if(name.includes("neet") || name.includes("jee") || name.includes("dropper")) set.add("12+");
  });

  const order = ["6","7","8","9","10","11","12","12+"];

  return [...set].sort((a,b) => {
    const ai = order.indexOf(a);
    const bi = order.indexOf(b);

    if(ai === -1 && bi === -1) return a.localeCompare(b);
    if(ai === -1) return 1;
    if(bi === -1) return -1;

    return ai - bi;
  });
}

function renderClassFilters(){
  const wrap = $("classFilters");
  if(!wrap) return;

  const classes = getClasses();

  wrap.innerHTML = classes.map(cls => `
    <label class="check-card">
      <input type="checkbox" value="${escapeAttr(cls)}" ${selectedClasses.includes(cls) ? "checked" : ""} />
      <span>Class ${escapeHtml(cls)}</span>
    </label>
  `).join("") || `<p style="color:var(--muted)">No class filters found.</p>`;

  wrap.querySelectorAll("input").forEach(input => {
    input.addEventListener("change", () => {
      if(input.checked){
        if(!selectedClasses.includes(input.value)){
          selectedClasses.push(input.value);
        }
      }else{
        selectedClasses = selectedClasses.filter(c => c !== input.value);
      }

      currentPage = 1;
      resetGridRender();
      applyFiltersAndRender();
    });
  });
}

function applyFiltersAndRender(){
  const token = ++renderToken;
  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";

  scheduleTask(() => {
    if(token !== renderToken) return;

    const result = [];

    for(let i = 0; i < allBatches.length; i++){
      const batch = allBatches[i];

      if(isBlockedBatch(batch)) continue;

      if(query && !batch.searchText.includes(query)) continue;

      if(selectedClasses.length && !selectedClasses.some(cls => batchMatchesClass(batch, cls))) continue;

      result.push(batch);
    }

    result.sort(sortBatches);

    if(token !== renderToken) return;

    filteredBatches = result;
    renderVisibleBatches(true);
  });
}

function isBlockedBatch(batch){
  if(batch.isCustomBatch) return false;

  const batchName = String(batch.batchName || "");
  const lower = batchName.toLowerCase();

  return (
    blockedBatchSet.has(lower) ||
    lower.includes("nsat") ||
    lower.includes("pw-sat") ||
    lower.includes("pw sat")
  );
}

function batchMatchesClass(batch, cls){
  const lower = String(batch.batchName || "").toLowerCase();

  if(Array.isArray(batch.classTags) && batch.classTags.map(String).includes(String(cls))){
    return true;
  }

  if(cls === "6") return lower.includes("class 6") || lower.includes("6th");
  if(cls === "7") return lower.includes("class 7") || lower.includes("7th");
  if(cls === "8") return lower.includes("class 8") || lower.includes("8th");
  if(cls === "9") return lower.includes("class 9") || lower.includes("9th");
  if(cls === "10") return lower.includes("class 10") || lower.includes("10th");
  if(cls === "11") return lower.includes("class 11") || lower.includes("11th");
  if(cls === "12") return lower.includes("class 12") || lower.includes("12th");
  if(cls === "12+") return lower.includes("neet") || lower.includes("jee") || lower.includes("dropper");

  return false;
}

function sortBatches(a,b){
  const aTrend = isBatchTrending(a);
  const bTrend = isBatchTrending(b);

  if(aTrend && !bTrend) return -1;
  if(!aTrend && bTrend) return 1;

  if(a.isCustomBatch && !b.isCustomBatch) return -1;
  if(!a.isCustomBatch && b.isCustomBatch) return 1;

  return String(a.sortText || a.batchName || "").localeCompare(String(b.sortText || b.batchName || ""));
}

function isBatchTrending(batch){
  if(batch.isTrending === true) return true;

  const name = String(batch.batchName || "").toLowerCase();
  return trendingKeywords.some(key => name.includes(key));
}

function resetGridRender(){
  lastRenderedCount = 0;
  if(batchGrid){
    batchGrid.innerHTML = "";
  }
}

function rerenderCurrentCards(){
  lastRenderedCount = 0;
  if(batchGrid){
    batchGrid.innerHTML = "";
  }
  renderVisibleBatches(true);
}

function renderVisibleBatches(reset){
  if(isLoading){
    renderSkeletons();
    return;
  }

  if(reset){
    lastRenderedCount = 0;
    batchGrid.innerHTML = "";
  }

  const totalToShow = Math.min(PAGE_SIZE * currentPage, filteredBatches.length);

  if(!filteredBatches.length){
    batchGrid.innerHTML = "";
    loadWrap.classList.add("hidden");

    statusArea.innerHTML = `
      <div class="empty">
        <h3>No batches found</h3>
        <p>Try another search or clear filters.</p>
      </div>
    `;
    return;
  }

  statusArea.innerHTML = "";

  const start = lastRenderedCount;
  const end = totalToShow;

  if(start >= end){
    loadWrap.classList.toggle("hidden", filteredBatches.length <= totalToShow);
    return;
  }

  const nextItems = filteredBatches.slice(start, end);
  const html = nextItems.map(batchCardTemplate).join("");

  requestAnimationFrame(() => {
    batchGrid.insertAdjacentHTML("beforeend", html);
    lastRenderedCount = end;
    loadWrap.classList.toggle("hidden", filteredBatches.length <= totalToShow);
  });
}

function batchCardTemplate(batch){
  const id = String(batch.batchId || batch.id || "");
  const name = String(batch.batchName || batch.name || "Untitled Batch");
  const image = String(batch.batchImage || batch.image || fallbackImage);

  const enrolled = enrolledIds.includes(id);
  const trending = isBatchTrending(batch);

  let leftBadge = "";

  if(trending){
    leftBadge = batch.badgeText || "🔥 Trending";
  }else if(batch.isCustomBatch && batch.badgeText){
    leftBadge = batch.badgeText;
  }else if(batch.isCustomBatch){
    leftBadge = "⭐ Custom";
  }

  return `
    <article class="card" data-batch-card="${escapeAttr(id)}">
      <div class="thumb">
        <img
          src="${escapeAttr(image)}"
          alt="${escapeAttr(name)}"
          loading="lazy"
          decoding="async"
          fetchpriority="low"
          onerror="this.src='${fallbackImage}'"
        />
        ${enrolled ? `<span class="badge right">Enrolled</span>` : ""}
        ${leftBadge ? `<span class="badge left">${escapeHtml(leftBadge)}</span>` : ""}
      </div>

      <div class="card-body">
        <h3 class="course-title">${escapeHtml(name)}</h3>

        <div class="card-actions">
          <button class="btn primary" data-action="study" data-id="${escapeAttr(id)}">▶ Study</button>

          ${enrolled
            ? `<button class="btn danger" data-action="unenroll" data-id="${escapeAttr(id)}">✕ Unenroll</button>`
            : `<button class="btn" data-action="enroll" data-id="${escapeAttr(id)}">＋ Enroll</button>`
          }
        </div>
      </div>
    </article>
  `;
}

function handleBatchGridClick(event){
  const btn = event.target.closest("[data-action]");
  if(!btn) return;

  const action = btn.dataset.action;
  const id = btn.dataset.id;

  const batch = allBatches.find(item => String(item.batchId || item.id || "") === String(id));

  if(!batch){
    toast("Batch missing", "Batch data not found.", "danger");
    return;
  }

  if(action === "study"){
    goToStudy(batch);
  }

  if(action === "enroll"){
    enrollBatch(batch);
  }

  if(action === "unenroll"){
    unenrollBatch(batch.batchId, batch.batchName);
  }
}

function goToStudy(batch){
  const batchId = String(batch.batchId || batch.id || "");
  const batchName = String(batch.batchName || batch.name || "");

  if(!batchId){
    toast("Missing batch ID", "This batch does not have a valid batchId.", "danger");
    return;
  }

  if(batch.isCustomBatch && batch.customLink){
    window.location.href = batch.customLink;
    return;
  }

  const query = `batchid=${encodeURIComponent(batchId)}&name=${encodeURIComponent(batchName || "")}`;

  if(location.protocol === "file:"){
    window.location.href = `batches/subject.html?${query}`;
  }else{
    window.location.href = `/study-v2/batches/subject?${query}`;
  }
}

function enrollBatch(batch){
  const id = String(batch.batchId || batch.id || "");

  if(!id){
    toast("Missing batch ID", "Cannot enroll this batch.", "danger");
    return;
  }

  let saved = [];

  try{
    saved = JSON.parse(localStorage.getItem(ENROLLED_KEY) || "[]");
  }catch(err){
    saved = [];
  }

  if(!saved.some(item => String(item.batchId || item.id || "") === id)){
    saved.push({
      ...batch,
      batchId:id
    });

    localStorage.setItem(ENROLLED_KEY, JSON.stringify(saved));
  }

  enrolledIds = saved.map(item => String(item.batchId || item.id || ""));

  toast(
    "Successfully Enrolled!",
    `You have enrolled in ${batch.batchName || batch.name || "this batch"}.`
  );

  rerenderCurrentCards();
}

function unenrollBatch(batchId, batchName){
  let saved = [];

  try{
    saved = JSON.parse(localStorage.getItem(ENROLLED_KEY) || "[]");
  }catch(err){
    saved = [];
  }

  saved = saved.filter(item => String(item.batchId || item.id || "") !== String(batchId));

  localStorage.setItem(ENROLLED_KEY, JSON.stringify(saved));
  enrolledIds = saved.map(item => String(item.batchId || item.id || ""));

  toast("Unenrolled", `You have unenrolled from ${batchName || "this batch"}.`, "danger");

  rerenderCurrentCards();
}

function renderSkeletons(){
  loadWrap.classList.add("hidden");
  statusArea.innerHTML = "";

  const count = isMobileDevice ? 3 : 6;

  batchGrid.innerHTML = Array.from({length:count}).map(() => `
    <div class="sk-card">
      <div class="skeleton sk-img"></div>
      <div class="skeleton sk-line w1"></div>
      <div class="skeleton sk-line w2"></div>
      <div class="skeleton sk-line w3"></div>
      <div class="skeleton sk-btn"></div>
    </div>
  `).join("");
}

async function copyReferralCode(){
  try{
    await navigator.clipboard.writeText("4964YRAZ");
    toast("Copied!", "Referral code copied to clipboard.");
  }catch(err){
    toast("Copy failed", "Referral code: 4964YRAZ", "danger");
  }
}

function openTelegramMain(){
  window.open("https://t.me/NT_PW_2027_free_lectures", "_blank", "noopener,noreferrer");
}

function openTelegramBackup(){
  window.open("https://t.me/NT_PW_2027_free_lectures", "_blank", "noopener,noreferrer");
}

function toast(title, description, type="normal"){
  const box = $("toastBox");
  if(!box) return;

  const item = document.createElement("div");

  item.className = `toast ${type === "danger" ? "danger" : ""}`;
  item.innerHTML = `
    <h4>${escapeHtml(title)}</h4>
    <p>${escapeHtml(description)}</p>
  `;

  box.appendChild(item);

  setTimeout(() => {
    item.remove();
  }, 2600);
}

function escapeHtml(value){
  return String(value || "").replace(/[&<>'"]/g, char => ({
    "&":"&amp;",
    "<":"&lt;",
    ">":"&gt;",
    "'":"&#39;",
    "\"":"&quot;"
  }[char]));
}

function escapeAttr(value){
  return escapeHtml(value).replace(/`/g, "&#96;");
}

function scheduleTask(callback){
  if("requestIdleCallback" in window){
    requestIdleCallback(callback, { timeout: 300 });
  }else{
    setTimeout(callback, 0);
  }
}
(function () {

    const allowedDomain = "learnbyakp.online";

    const ref = document.referrer || "";

    // Direct open detect
    if (ref === "") {

        document.body.innerHTML = "";

        throw new Error("Direct access blocked");

    }

    // Other domain detect
    if (!ref.includes(allowedDomain)) {

        document.body.innerHTML = "";

        throw new Error("Invalid domain");

    }

})();
/*
  Optional external script.
  Agar mobile me ab bhi lag aaye to is block ko comment kar dena.
*/
const SCRIPT_LINK = "https://learnbyakp.online/html-js/aut.js";

if(!isMobileDevice){
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
}
