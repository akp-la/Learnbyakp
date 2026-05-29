// Data Constants
const ENROLLED_KEY = "enrolledBatches";
const CACHE_KEY = "pwBatchesCache";
const fallbackImage = "https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png";

// Optimization Constants
const isMobileDevice = window.innerWidth <= 620 || /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
const PAGE_SIZE = isMobileDevice ? 12 : 24;
const SEARCH_DELAY = 100; // Super fast debounce

const blockedBatchSet = new Set([
  "little masters 2026 (class 5th)", "summer camp 2025 (class 5th)",
  "junoon (7th class)", "junoon 2025 (class 7th)", 
  "pw-nsat online -26 nov (8th foundation)", "nsat 8th foundation (13-nov )",
  "summer camp 2025 (class 8th)", "nmmss bihar 2025-26 (class 8th)"
]);

// TRENDING KEYWORDS ARRAY (Add words here, must be in lowercase)
const trendingKeywords = ["udaan","arjuna", "lakshya", "yakeen", "neev", "uday", "parishram", "khazana"];

// App State
let allBatches = [];
let filteredBatches = [];
let selectedClasses = [];
let enrolledIds = [];
let currentPage = 1;
let isLoading = true;
let currentTab = "all"; // 'all' or 'enrolled'

let searchDebounceTimer = null;
let lastRenderedCount = 0;

const $ = (id) => document.getElementById(id);

// DOM Elements
const batchGrid = $("batchGrid");
const statusArea = $("statusArea");
const loadWrap = $("loadWrap");
const loadMoreBtn = $("loadMoreBtn");
const searchInput = $("searchInput");
const clearSearch = $("clearSearch");
const tabAll = $("tabAll");
const tabEnrolled = $("tabEnrolled");

// Stats Elements
const elTotalBatches = $("totalBatchesCount");
const elFilteredBatches = $("filteredBatchesCount");
const elShowingCount = $("showingCount");
const elTotalFilteredCount = $("totalFilteredCount");

document.addEventListener("DOMContentLoaded", init);

function init(){
  injectMobilePerformanceCSS();
  setupEvents();
  loadTheme();
  showTelegramPopupOncePerSession();
  loadEnrolledIds();
  
  // Start Fetching Data
  renderSkeletons();
  fetchLocalJSONBatches();
}

function injectMobilePerformanceCSS(){
  const style = document.createElement("style");
  style.textContent = `
    .card img { content-visibility: auto; }
    @media(max-width:620px){
      .app-header { backdrop-filter: none!important; }
      .grid { gap: 14px!important; }
      .card { border-radius: 18px!important; box-shadow: 0 6px 14px rgba(15,23,42,.06)!important; transition: none!important; }
      .card:hover { transform: none!important; box-shadow: 0 6px 14px rgba(15,23,42,.06)!important; }
      .thumb img { transform: none!important; }
      .btn, .icon-btn, .menu-panel, .drawer-panel, .toast { transition: none!important; }
      .toast { max-width: calc(100vw - 24px)!important; min-width: 0!important; }
      .skeleton { animation: none!important; }
    }
  `;
  document.head.appendChild(style);
}

function setupEvents(){
  // Tabs Events
  if(tabAll && tabEnrolled){
    tabAll.addEventListener("click", () => switchTab("all"));
    tabEnrolled.addEventListener("click", () => switchTab("enrolled"));
  }

  // Search Events
  if($("searchToggle")){
    $("searchToggle").addEventListener("click", () => {
      $("searchWrap").classList.toggle("hidden");
      if(!$("searchWrap").classList.contains("hidden")){
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

  // Menus and Modals
  if($("menuToggle")) $("menuToggle").addEventListener("click", () => $("sideMenu").classList.add("open"));
  document.querySelectorAll("[data-close-menu]").forEach(el => el.addEventListener("click", () => $("sideMenu").classList.remove("open")));
  
  if($("filterBtn")) $("filterBtn").addEventListener("click", () => $("filterDrawer").classList.add("open"));
  document.querySelectorAll("[data-close-filter]").forEach(el => el.addEventListener("click", () => $("filterDrawer").classList.remove("open")));
  
  document.querySelectorAll("[data-close-modal]").forEach(el => el.addEventListener("click", () => $("telegramModal").classList.remove("show")));

  // Misc
  if($("copyReferral")) $("copyReferral").addEventListener("click", copyReferralCode);
  if($("themeToggle")) $("themeToggle").addEventListener("click", toggleTheme);

  if(loadMoreBtn){
    loadMoreBtn.addEventListener("click", () => {
      currentPage++;
      renderVisibleBatches(false);
    });
  }

  if($("clearFilters")){
    $("clearFilters").addEventListener("click", () => {
      selectedClasses = [];
      currentPage = 1;
      renderClassFilters();
      resetGridRender();
      applyFiltersAndRender();
    });
  }

  if($("clearEnrollments")){
    $("clearEnrollments").addEventListener("click", () => {
      localStorage.removeItem(ENROLLED_KEY);
      enrolledIds = [];
      toast("Cleared", "All enrolled batches removed from this browser.");
      resetGridRender();
      applyFiltersAndRender(); // Re-render to update UI instantly
    });
  }

  if(batchGrid) batchGrid.addEventListener("click", handleBatchGridClick);
}

function switchTab(tab) {
  currentTab = tab;
  
  if(tab === "all") {
    tabAll.classList.add("active");
    tabEnrolled.classList.remove("active");
  } else {
    tabEnrolled.classList.add("active");
    tabAll.classList.remove("active");
  }
  
  currentPage = 1;
  resetGridRender();
  applyFiltersAndRender();
}

function loadTheme(){
  const saved = localStorage.getItem("akpTheme");
  if(saved === "dark") document.body.classList.add("dark");
  const btn = $("themeToggle");
  if(btn) btn.textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
}

function toggleTheme(){
  document.body.classList.toggle("dark");
  localStorage.setItem("akpTheme", document.body.classList.contains("dark") ? "dark" : "light");
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
    enrolledIds = saved.map(item => String(item.id || item._id || item.batchId || ""));
  }catch(err){
    enrolledIds = [];
  }
}

// Fetch JSON Local
async function fetchLocalJSONBatches(){
  try{
    const res = await fetch("https://learnbyakp.onrender.com/batches.json");
    if(!res.ok) throw new Error("HTTP error! status: " + res.status);
    
    const json = await res.json();
    let dataArray = Array.isArray(json) ? json : (json.batches || json.data || []);
    
    // Normalization & Precomputation for speed
    allBatches = dataArray.map(item => {
      const id = String(item._id || item.id || item.batchId || "");
      const name = String(item.name || item.batchName || "Untitled Batch");
      const lowerName = name.toLowerCase();
      
      return {
        id: id,
        name: name,
        image: item.previewImage || item.batchImage || item.image || fallbackImage,
        classTags: item.classTags || [],
        // Pre-compute Search Key
        searchText: (id + " " + lowerName).toLowerCase()
      };
    }).filter(b => b.id && b.name);

    isLoading = false;
    currentPage = 1;
    resetGridRender();
    renderClassFilters();
    applyFiltersAndRender();

  } catch (err) {
    console.error("Failed to fetch JSON:", err);
    isLoading = false;
    statusArea.innerHTML = `
      <div class="empty">
        <h3>Unable to load batches</h3>
        <p>${escapeHtml(err.message)}</p>
        <button class="btn primary" onclick="location.reload()" style="margin-top:10px;">Retry</button>
      </div>
    `;
    batchGrid.innerHTML = "";
    loadWrap.classList.add("hidden");
  }
}

function getClasses(){
  const set = new Set();
  allBatches.forEach(batch => {
    const name = batch.name.toLowerCase();
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
        if(!selectedClasses.includes(input.value)) selectedClasses.push(input.value);
      } else {
        selectedClasses = selectedClasses.filter(c => c !== input.value);
      }
      currentPage = 1;
      resetGridRender();
      applyFiltersAndRender();
    });
  });
}

function applyFiltersAndRender(){
  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";

  filteredBatches = allBatches.filter(batch => {
    // 1. Check Enrolled Tab Status
    if(currentTab === "enrolled" && !enrolledIds.includes(batch.id)) return false;

    // 2. Blocked checks
    const lowerName = batch.name.toLowerCase();
    if(blockedBatchSet.has(lowerName) || lowerName.includes("nsat") || lowerName.includes("pw-sat")) return false;

    // 3. Search Query Check
    if(query && !batch.searchText.includes(query)) return false;

    // 4. Class Filters Check
    if(selectedClasses.length && !selectedClasses.some(cls => batchMatchesClass(batch, cls))) return false;

    return true;
  });

  renderVisibleBatches(true);
}

function batchMatchesClass(batch, cls){
  const lower = batch.name.toLowerCase();
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

function resetGridRender(){
  lastRenderedCount = 0;
  if(batchGrid) batchGrid.innerHTML = "";
}

function updateStatsUI(totalShowing) {
  if (elTotalBatches) elTotalBatches.textContent = allBatches.length;
  if (elFilteredBatches) elFilteredBatches.textContent = filteredBatches.length;
  if (elTotalFilteredCount) elTotalFilteredCount.textContent = filteredBatches.length;
  if (elShowingCount) elShowingCount.textContent = totalShowing;
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
  
  // Update Stats UI instantly
  updateStatsUI(totalToShow);

  if(!filteredBatches.length){
    batchGrid.innerHTML = "";
    loadWrap.classList.add("hidden");
    statusArea.innerHTML = `
      <div class="empty">
        <h3>No batches found</h3>
        <p>${currentTab === 'enrolled' ? "You haven't enrolled in any batches yet." : "Try another search or clear filters."}</p>
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

  // Use fast DOM insertion
  requestAnimationFrame(() => {
    batchGrid.insertAdjacentHTML("beforeend", html);
    lastRenderedCount = end;
    loadWrap.classList.toggle("hidden", filteredBatches.length <= totalToShow);
  });
}

function batchCardTemplate(batch){
  const enrolled = enrolledIds.includes(batch.id);
  const isTrending = trendingKeywords.some(keyword => batch.name.toLowerCase().includes(keyword));

  return `
    <article class="card" data-batch-card="${escapeAttr(batch.id)}">
      <div class="thumb">
        <img
          src="${escapeAttr(batch.image)}"
          alt="${escapeAttr(batch.name)}"
          loading="lazy"
          decoding="async"
          onerror="this.src='${fallbackImage}'"
        />
        ${isTrending ? `<span class="badge trending">📈 Trending</span>` : ""}
        ${enrolled ? `<span class="badge right">Enrolled</span>` : ""}
      </div>

      <div class="card-body">
        <h3 class="course-title">${escapeHtml(batch.name)}</h3>
        <div class="card-actions">
          <button class="btn primary" data-action="study" data-id="${escapeAttr(batch.id)}">▶ Study</button>
          ${enrolled
            ? `<button class="btn danger" data-action="unenroll" data-id="${escapeAttr(batch.id)}">✕ Unenroll</button>`
            : `<button class="btn" data-action="enroll" data-id="${escapeAttr(batch.id)}">＋ Enroll</button>`
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
  const batch = allBatches.find(item => item.id === id);

  if(!batch) return;

  if(action === "study") goToStudy(batch);
  if(action === "enroll") enrollBatch(batch);
  if(action === "unenroll") unenrollBatch(batch.id, batch.name);
}

function goToStudy(batch){
  const query = `batchid=${encodeURIComponent(batch.id)}&name=${encodeURIComponent(batch.name)}`;
  if(location.protocol === "file:"){
    window.location.href = `batches/subject.html?${query}`;
  }else{
    window.location.href = `/study-v2/batches/subject?${query}`;
  }
}

function enrollBatch(batch){
  let saved = [];
  try{ saved = JSON.parse(localStorage.getItem(ENROLLED_KEY) || "[]"); }catch(err){ saved = []; }

  if(!saved.some(item => item.id === batch.id)){
    saved.push(batch);
    localStorage.setItem(ENROLLED_KEY, JSON.stringify(saved));
  }
  enrolledIds = saved.map(item => String(item.id || ""));
  toast("Successfully Enrolled!", `You have enrolled in ${batch.name}.`);
  
  // instantly update UI
  resetGridRender();
  applyFiltersAndRender();
}

function unenrollBatch(batchId, batchName){
  let saved = [];
  try{ saved = JSON.parse(localStorage.getItem(ENROLLED_KEY) || "[]"); }catch(err){ saved = []; }

  saved = saved.filter(item => String(item.id || "") !== String(batchId));
  localStorage.setItem(ENROLLED_KEY, JSON.stringify(saved));
  enrolledIds = saved.map(item => String(item.id || ""));
  
  toast("Unenrolled", `You have unenrolled from ${batchName}.`, "danger");
  
  // instantly update UI
  resetGridRender();
  applyFiltersAndRender();
}

function renderSkeletons(){
  loadWrap.classList.add("hidden");
  statusArea.innerHTML = "";
  const count = isMobileDevice ? 4 : 6;
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

function openTelegramMain(){ window.open("https://t.me/NT_PW_2027_free_lectures", "_blank", "noopener,noreferrer"); }
function openTelegramBackup(){ window.open("https://t.me/NT_PW_2027_free_lectures", "_blank", "noopener,noreferrer"); }

function toast(title, description, type="normal"){
  const box = $("toastBox");
  if(!box) return;
  const item = document.createElement("div");
  item.className = `toast ${type === "danger" ? "danger" : ""}`;
  item.innerHTML = `<h4>${escapeHtml(title)}</h4><p>${escapeHtml(description)}</p>`;
  box.appendChild(item);
  setTimeout(() => item.remove(), 2600);
}

function escapeHtml(value){
  return String(value || "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[char]));
}

function escapeAttr(value){ return escapeHtml(value).replace(/`/g, "&#96;"); }
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
