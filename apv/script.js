const BASE_URL = "https://vibrantacademykotaapi.akamai.net.in";
const AES_KEY_TEXT = "638udh3829162018";
const AES_IV_TEXT = "fedcba9876543210";
const L = {
  "accept": "*/*",
  "accept-encoding": "gzip, deflate, br, zstd",
  "accept-language": "en-US,en;q=0.9",
  "auth-key": "appxapi",
  "client-service": "Appx",
  "device-type": "",
  "origin": "https://www.vibrantacademy.com",
  "priority": "u=1, i",
  "referer": "https://www.vibrantacademy.com/",
  "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
  "sec-ch-ua-mobile": "?1",
  "sec-ch-ua-platform": '"Android"',
  "sec-fetch-dest": "empty",
  "sec-fetch-mode": "cors",
  "sec-fetch-site": "cross-site",
  "source": "website",
  "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36"
};

const params = new URLSearchParams(window.location.search);
const courseId = params.get("course_id");
const givenTitle = params.get("title");

const state = {
  content: [],
  breadcrumb: [],
  loadingContent: false,
  rootFolderId: null,
  title: givenTitle || "",
  activeMainTab: "content",
  activeLiveTab: "live",
  live: [],
  upcoming: [],
  previousLives: [],
  loadingLive: false,
  loadingPrevious: false,
  contentError: null,
  previousError: null,
  loadedLiveOnce: false,
  loadedPreviousOnce: false,
};

const $ = (id) => document.getElementById(id);

const el = {
  courseTitle: $("courseTitle"),
  contentTab: $("contentTab"),
  liveTab: $("liveTab"),
  contentSection: $("contentSection"),
  liveSection: $("liveSection"),
  breadcrumb: $("breadcrumb"),
  contentLoader: $("contentLoader"),
  contentError: $("contentError"),
  emptyContent: $("emptyContent"),
  contentGrid: $("contentGrid"),
  liveUpcomingBtn: $("liveUpcomingBtn"),
  previousLiveBtn: $("previousLiveBtn"),
  liveUpcomingPanel: $("liveUpcomingPanel"),
  previousLivePanel: $("previousLivePanel"),
  liveLoader: $("liveLoader"),
  previousLoader: $("previousLoader"),
  noLive: $("noLive"),
  noPrevious: $("noPrevious"),
  liveGrid: $("liveGrid"),
  previousGrid: $("previousGrid"),
  previousError: $("previousError"),
  pdfModal: $("pdfModal"),
  pdfTitle: $("pdfTitle"),
  pdfFrame: $("pdfFrame"),
  closePdf: $("closePdf"),
  imageModal: $("imageModal"),
  previewImage: $("previewImage"),
  closeImage: $("closeImage"),
};

function setTitle(title) {
  state.title = title || "Course Content";
  if (el.courseTitle) el.courseTitle.textContent = state.title;
  document.title = `${state.title} - LearnByAKP`;
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDateTime(value) {
  if (!value || !value.includes(" at ")) return value || "";

  const [datePart, timePart] = value.split(" at ");
  const dateParts = datePart.split("-");
  if (dateParts.length !== 3) return value;

  const [day, monthText, year] = dateParts;
  const month = parseInt(monthText, 10);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  if (Number.isNaN(month) || month < 1 || month > 12) return value;
  return `${day} ${months[month - 1]} ${year}, ${String(timePart).toUpperCase()}`;
}

function getStartTime(value) {
  if (!value || !value.includes(" at ")) return value || "";
  return value.split(" at ")[1] || value;
}

function svgIcon(type) {
  const icons = {
    video: "▶️",
    image: "🖼️",
    folder: "📁",
    pdf: "📄",
    tv: "📺",
    file: "📦",
  };
  return icons[type] || icons.file;
}

function skeletonGrid(count = 3) {
  return Array.from({ length: count }).map(() => `
    <div class="skeleton-card">
      <div class="skeleton-thumb"></div>
      <div class="skeleton-line mid"></div>
      <div class="skeleton-line small"></div>
    </div>
  `).join("");
}

function skeletonList(count = 8) {
  return Array.from({ length: count }).map(() => `
    <div class="row-card">
      <div class="row-inner">
        <div class="skeleton-line" style="width:92px;height:68px;margin:0"></div>
        <div style="flex:1">
          <div class="skeleton-line mid"></div>
        </div>
      </div>
    </div>
  `).join("");
}

// Fix: fetchJson accepts options and forwards them to fetch
async function fetchJson(url, options = {}) {
  const effectiveOptions = {
    method: options.method || "GET",
    headers: { ...(options.headers || L) }, // default headers L, overridden by options.headers
    cache: options.cache || "no-store",
    // keep other fetch options if provided (body, mode, credentials etc.)
    ...options,
  };

  const response = await fetch(url, effectiveOptions);
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

async function decryptVibrantLink(encryptedText) {
  try {
    // original code used the first colon-separated part
    const firstPart = String(encryptedText).split(":")[0];
    const encryptedBinary = window.atob(firstPart);
    const encryptedBytes = new Uint8Array(encryptedBinary.length);

    for (let i = 0; i < encryptedBinary.length; i++) {
      encryptedBytes[i] = encryptedBinary.charCodeAt(i);
    }

    const keyBytes = new TextEncoder().encode(AES_KEY_TEXT);
    const ivBytes = new TextEncoder().encode(AES_IV_TEXT);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-CBC", length: 128 },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: ivBytes },
      cryptoKey,
      encryptedBytes.buffer
    );

    // decode as bytes first
    let text = new TextDecoder().decode(decrypted);

    // PKCS#7 padding removal — only if appears valid.
    // Many implementations leave the padding bytes at the end; this checks and strips safely.
    try {
      if (text.length > 0) {
        const padding = text.charCodeAt(text.length - 1);
        if (padding > 0 && padding <= 16 && padding <= text.length) {
          const paddingText = text.slice(-padding);
          const validPadding = Array.from(paddingText).every((ch) => ch.charCodeAt(0) === padding);
          if (validPadding) text = text.substring(0, text.length - padding);
        }
      }
    } catch (e) {
      // If padding-handling somehow fails, fall back to raw text (don't throw).
      console.warn("Padding strip failed, using raw decrypted text", e);
    }

    return text;
  } catch (error) {
    console.error("Client-side Vibrant decryption failed:", error);
    throw new Error("Decryption failed on client");
  }
}

async function loadFolder(folderId) {
  if (!courseId) {
    state.contentError = "course_id is missing in URL. Example: index.html?course_id=123";
    state.content = [];
    renderContent();
    return;
  }

  state.loadingContent = true;
  state.contentError = null;
  renderContent();

  try {
    const url = `${BASE_URL}/get/folder_contentsv3?course_id=${encodeURIComponent(courseId)}&parent_id=${encodeURIComponent(folderId)}&start=0`;
    const data = await fetchJson(url, {
      headers: L,
      cache: "no-store"
    });

    if (data.status === 200) {
      state.content = data.data || [];
    } else {
      throw new Error(data.message || "Could not fetch content");
    }
  } catch (error) {
    state.contentError = error.message || String(error);
  } finally {
    state.loadingContent = false;
    renderContent();
  }
}

async function loadInitialContent() {
  if (!courseId) {
    setTitle(givenTitle || "Course Content");
    state.contentError = "course_id is missing in URL. Example: index.html?course_id=123";
    renderContent();
    return;
  }

  setTitle(givenTitle || "Loading...");
  state.loadingContent = true;
  renderContent();

  try {
    // Important: parent_id=-1 for initial list (same as the original React code)
    const url = `${BASE_URL}/get/folder_contentsv3?course_id=${encodeURIComponent(courseId)}&parent_id=-1&start=0`;
    const data = await fetchJson(url, {
      headers: L,
      cache: "no-store"
    });

    if (data.status === 200 && Array.isArray(data.data) && data.data.length > 0) {
      const firstFolder = data.data[0];
      if (!givenTitle) setTitle(firstFolder.Title || "Course Content");
      state.rootFolderId = firstFolder.id;
      await loadFolder(firstFolder.id);
      return;
    }

    if (!givenTitle) await loadBatchTitleFallback();
    state.content = [];
  } catch (error) {
    state.contentError = error.message || String(error);
  } finally {
    state.loadingContent = false;
    renderContent();
  }
}

async function loadBatchTitleFallback() {
  try {
    const data = await fetchJson(`${BASE_URL}/api/vibrant/batches`, { headers: L, cache: "no-store" });
    if (data.status === 200 && Array.isArray(data.data)) {
      const batch = data.data.find((item) => String(item.id) === String(courseId));
      if (batch) setTitle(batch.title || batch.Title || "Course Content");
      else setTitle("Course Content");
    }
  } catch (error) {
    console.warn("Could not fetch batch title for fallback", error);
    setTitle("Course Content");
  }
}

async function loadLiveData() {
  if (!courseId || state.loadedLiveOnce) return;
  state.loadingLive = true;
  renderLive();

  try {
    const url = `${BASE_URL}/get/course_contents_by_live_status?course_id=${encodeURIComponent(courseId)}&start=0`;
    const data = await fetchJson(url, { headers: L, cache: "no-store" });
    if (data.status === 200) {
      state.upcoming = data.data?.upcoming || [];
      state.live = data.data?.live || [];
      state.loadedLiveOnce = true;
    } else {
      throw new Error(data.message || "Could not fetch live/upcoming sessions");
    }
  } catch (error) {
    console.error(error);
  } finally {
    state.loadingLive = false;
    renderLive();
  }
}

async function loadPreviousLives() {
  if (!courseId || state.loadedPreviousOnce) return;
  state.loadingPrevious = true;
  state.previousError = null;
  renderLive();

  try {
    const url = `${BASE_URL}/get/get_previous_live_videos?course_id=${encodeURIComponent(courseId)}&start=0&folder_wise_course=1`;
    const data = await fetchJson(url, { headers: L, cache: "no-store" });
    if (data.status === 200) {
      state.previousLives = data.data || [];
      state.loadedPreviousOnce = true;
    } else {
      throw new Error(data.message || "Could not fetch previous live sessions");
    }
  } catch (error) {
    state.previousError = error.message || String(error);
  } finally {
    state.loadingPrevious = false;
    renderLive();
  }
}

function renderBreadcrumb() {
  if (!el.breadcrumb) return;
  el.breadcrumb.innerHTML = "";

  const home = document.createElement("button");
  home.textContent = state.title || "Course";
  home.onclick = () => {
    state.breadcrumb = [];
    if (state.rootFolderId) loadFolder(state.rootFolderId);
  };
  el.breadcrumb.appendChild(home);

  state.breadcrumb.forEach((folder, index) => {
    const arrow = document.createElement("span");
    arrow.className = "arrow";
    arrow.textContent = "›";
    el.breadcrumb.appendChild(arrow);

    const btn = document.createElement("button");
    btn.textContent = folder.name;
    btn.disabled = index === state.breadcrumb.length - 1;
    btn.onclick = () => {
      state.breadcrumb = state.breadcrumb.slice(0, index + 1);
      loadFolder(folder.id);
    };
    el.breadcrumb.appendChild(btn);
  });
}

function contentItemCard(item) {
  const title = escapeHtml(item.Title || "Untitled");

  if (item.material_type === "VIDEO") {
    return `
      <article class="video-card" data-id="${escapeHtml(item.id)}" data-type="video">
        <div class="thumb-wrap">
          ${item.thumbnail ? `<img src="${escapeHtml(item.thumbnail)}" alt="${title}">` : `<div class="fallback-icon">${svgIcon("video")}</div>`}
        </div>
        <div class="card-body">
          <h3 class="card-title">${title}</h3>
          <div class="card-meta">
            <p>Created on: ${escapeHtml(formatDateTime(item.date_and_time))}</p>
            ${item.duration ? `<p>⏱ ${escapeHtml(item.duration)}</p>` : ""}
          </div>
          <div class="card-actions">
            <button class="action-btn" data-action="watch" data-id="${escapeHtml(item.id)}">Watch</button>
            ${item.pdf_link ? `<button class="action-btn" data-action="pdf-note" data-id="${escapeHtml(item.id)}">View PDF</button>` : ""}
          </div>
        </div>
      </article>
    `;
  }

  let thumb = `<div class="fallback-icon">${svgIcon("file")}</div>`;
  if (item.material_type === "FOLDER") {
    thumb = `<img src="https://www.vibrantacademy.com/icons/folder.svg" alt="Folder">`;
  } else if (item.material_type === "PDF" || item.material_type === "FILE") {
    thumb = `<img src="https://www.vibrantacademy.com/icons/pdf.svg" alt="PDF">`;
  } else if (item.material_type === "IMAGE" && item.thumbnail) {
    thumb = `<img src="${escapeHtml(item.thumbnail)}" alt="${title}">`;
  } else if (item.material_type === "IMAGE") {
    thumb = `<div class="fallback-icon">${svgIcon("image")}</div>`;
  }

  return `
    <article class="row-card" data-action="open-item" data-id="${escapeHtml(item.id)}">
      <div class="row-inner">
        <div class="row-thumb ${item.material_type === "FOLDER" || item.material_type === "PDF" || item.material_type === "FILE" ? "icon" : ""}">${thumb}</div>
        <div><h3 class="row-title">${title}</h3></div>
      </div>
    </article>
  `;
}

function renderContent() {
  renderBreadcrumb();
  if (el.contentLoader) el.contentLoader.innerHTML = "";
  if (el.contentGrid) el.contentGrid.innerHTML = "";
  if (el.contentError) el.contentError.classList.add("hidden");
  if (el.emptyContent) el.emptyContent.classList.add("hidden");

  if (state.loadingContent) {
    if (el.contentLoader) el.contentLoader.innerHTML = skeletonList(8);
    return;
  }

  if (state.contentError) {
    if (el.contentError) {
      el.contentError.innerHTML = `<div class="big-icon">⚠️</div><h2>Error Loading Content</h2><p>${escapeHtml(state.contentError)}</p>`;
      el.contentError.classList.remove("hidden");
    }
    return;
  }

  if (!state.content.length) {
    if (el.emptyContent) el.emptyContent.classList.remove("hidden");
    return;
  }

  if (el.contentGrid) el.contentGrid.innerHTML = state.content.map(contentItemCard).join("");
}

function liveCard(item, isPrevious = false) {
  const title = escapeHtml(item.Title || "Untitled");
  const isLive = item.live_status === 1;
  const liveText = item.live_status === 2
    ? `Live on: ${escapeHtml(item.date_and_time || "")}`
    : `Started at: ${escapeHtml(getStartTime(item.date_and_time))}`;

  return `
    <article class="${isPrevious ? "video-card" : "live-card"}" data-id="${escapeHtml(item.id)}" data-type="${isPrevious ? "previous" : "live"}">
      <div class="thumb-wrap">
        ${item.thumbnail ? `<img src="${escapeHtml(item.thumbnail)}" alt="${title}">` : `<div class="fallback-icon">${svgIcon(isPrevious ? "video" : "tv")}</div>`}
        ${isLive && !isPrevious ? `<span class="live-badge">LIVE</span>` : ""}
      </div>
      <div class="card-body">
        <h3 class="card-title">${title}</h3>
        <div class="card-meta"><p>${isPrevious ? `Created on: ${escapeHtml(formatDateTime(item.date_and_time))}` : liveText}</p>${isPrevious && item.duration ? `<p>⏱ ${escapeHtml(item.duration)}</p>` : ""}</div>
        ${isPrevious ? `<button class="action-btn" data-action="watch-previous" data-id="${escapeHtml(item.id)}">Watch</button>` : isLive ? `<button class="action-btn blue" data-action="watch-live" data-id="${escapeHtml(item.id)}">Watch Now</button>` : ""}
      </div>
    </article>
  `;
}

function renderLive() {
  if (el.liveLoader) el.liveLoader.innerHTML = "";
  if (el.previousLoader) el.previousLoader.innerHTML = "";
  if (el.liveGrid) el.liveGrid.innerHTML = "";
  if (el.previousGrid) el.previousGrid.innerHTML = "";
  if (el.noLive) el.noLive.classList.add("hidden");
  if (el.noPrevious) el.noPrevious.classList.add("hidden");
  if (el.previousError) el.previousError.classList.add("hidden");

  const isLiveTab = state.activeLiveTab === "live";
  if (el.liveUpcomingPanel) el.liveUpcomingPanel.classList.toggle("hidden", !isLiveTab);
  if (el.previousLivePanel) el.previousLivePanel.classList.toggle("hidden", isLiveTab);
  if (el.liveUpcomingBtn) el.liveUpcomingBtn.classList.toggle("active", isLiveTab);
  if (el.previousLiveBtn) el.previousLiveBtn.classList.toggle("active", !isLiveTab);

  if (isLiveTab) {
    if (state.loadingLive) {
      if (el.liveLoader) el.liveLoader.innerHTML = skeletonGrid(3);
      return;
    }

    const allLiveItems = [...state.live, ...state.upcoming];
    if (!allLiveItems.length) {
      if (el.noLive) el.noLive.classList.remove("hidden");
      return;
    }

    if (el.liveGrid) el.liveGrid.innerHTML = allLiveItems.map((item) => liveCard(item, false)).join("");
    return;
  }

  if (state.loadingPrevious) {
    if (el.previousLoader) el.previousLoader.innerHTML = skeletonGrid(3);
    return;
  }

  if (state.previousError) {
    if (el.previousError) {
      el.previousError.innerHTML = `<div class="big-icon">⚠️</div><h2>Error</h2><p>${escapeHtml(state.previousError)}</p>`;
      el.previousError.classList.remove("hidden");
    }
    return;
  }

  if (!state.previousLives.length) {
    if (el.noPrevious) el.noPrevious.classList.remove("hidden");
    return;
  }

  if (el.previousGrid) el.previousGrid.innerHTML = state.previousLives.map((item) => liveCard(item, true)).join("");
}

async function handleContentClick(event) {
  const actionEl = event.target.closest("[data-action]");
  const card = event.target.closest("[data-id]");
  if (!card && !actionEl) return;

  const id = (actionEl || card).dataset.id;
  const item = state.content.find((entry) => String(entry.id) === String(id));
  if (!item) return;

  if (actionEl?.dataset.action === "pdf-note") {
    event.stopPropagation();
    await openPdfFromItem(item, true);
    return;
  }

  await openContentItem(item);
}

async function openContentItem(item) {
  if (item.material_type === "FOLDER") {
    state.breadcrumb.push({ id: item.id, name: item.Title });
    await loadFolder(item.id);
    return;
  }

  if (item.material_type === "VIDEO") {
    if (/(?:https?:\/\/)?(?:www\.)?(?:youtube\.com|youtu\.be)\/(?:watch\?v=)?(.+)/.test(item.file_link || "")) {
      window.location.href = item.file_link;
      return;
    }
    window.location.href = `player?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(item.id)}`;
    return;
  }

  if (item.material_type === "IMAGE") {
    if (item.thumbnail) openImage(item.thumbnail, item.Title);
    else alert("No image available for this item.");
    return;
  }

  if (item.material_type === "PDF" || item.material_type === "FILE") {
    await openPdfFromItem(item, false);
    return;
  }

  alert("This content type is not yet supported.");
}

async function openPdfFromItem(item, usePdfLink) {
  const encryptedLink = usePdfLink ? item.pdf_link : item.file_link;
  if (!encryptedLink) {
    alert(usePdfLink ? "No PDF link available for this item." : "No file link available for this item.");
    return;
  }

  try {
    const finalUrl = await decryptVibrantLink(encryptedLink);
    if (finalUrl.includes("youtube.com") || finalUrl.includes("youtu.be")) {
      window.location.href = finalUrl;
      return;
    }
    openPdf(finalUrl, usePdfLink ? `${item.Title} - Notes` : item.Title);
  } catch (error) {
    console.error(error);
    alert(usePdfLink ? "Failed to decrypt and open the PDF." : "Failed to decrypt and open the file.");
  }
}

function openPdf(url, name) {
  if (el.pdfTitle) el.pdfTitle.textContent = name || "PDF";
  if (el.pdfFrame) el.pdfFrame.src = `https://pdfweb.classx.co.in/pdfjs/web/viewer-new.html?file=${encodeURIComponent(url)}&save_flag=1`;
  if (el.pdfModal) el.pdfModal.classList.remove("hidden");
}

function closePdf() {
  if (el.pdfFrame) el.pdfFrame.src = "";
  if (el.pdfModal) el.pdfModal.classList.add("hidden");
}

function openImage(url, name) {
  if (el.previewImage) el.previewImage.src = url;
  if (el.previewImage) el.previewImage.alt = name || "Preview";
  if (el.imageModal) el.imageModal.classList.remove("hidden");
}

function closeImage() {
  if (el.previewImage) el.previewImage.src = "";
  if (el.imageModal) el.imageModal.classList.add("hidden");
}

function handleLiveClick(event) {
  const actionEl = event.target.closest("[data-action]");
  const card = event.target.closest("[data-id]");
  const target = actionEl || card;
  if (!target) return;

  const id = target.dataset.id;
  const type = target.dataset.action || target.dataset.type;

  if (type === "watch-previous" || type === "previous") {
    window.location.href = `player?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(id)}`;
    return;
  }

  if (type === "watch-live" || type === "live") {
    window.location.href = `player?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(id)}&isLive=true`;
  }
}

function switchMainTab(tab) {
  state.activeMainTab = tab;
  const isContent = tab === "content";

  if (el.contentTab) el.contentTab.classList.toggle("active", isContent);
  if (el.liveTab) el.liveTab.classList.toggle("active", !isContent);
  if (el.contentSection) el.contentSection.classList.toggle("hidden", !isContent);
  if (el.liveSection) el.liveSection.classList.toggle("hidden", isContent);

  if (!isContent) {
    loadLiveData();
    loadPreviousLives();
  }
}

function switchLiveTab(tab) {
  state.activeLiveTab = tab;
  if (tab === "live") loadLiveData();
  if (tab === "previous") loadPreviousLives();
  renderLive();
}

function bindEvents() {
  if (el.contentTab) el.contentTab.addEventListener("click", () => switchMainTab("content"));
  if (el.liveTab) el.liveTab.addEventListener("click", () => switchMainTab("live"));
  if (el.liveUpcomingBtn) el.liveUpcomingBtn.addEventListener("click", () => switchLiveTab("live"));
  if (el.previousLiveBtn) el.previousLiveBtn.addEventListener("click", () => switchLiveTab("previous"));
  if (el.contentGrid) el.contentGrid.addEventListener("click", handleContentClick);
  if (el.liveGrid) el.liveGrid.addEventListener("click", handleLiveClick);
  if (el.previousGrid) el.previousGrid.addEventListener("click", handleLiveClick);
  if (el.closePdf) el.closePdf.addEventListener("click", closePdf);
  if (el.closeImage) el.closeImage.addEventListener("click", closeImage);

  if (el.pdfModal) {
    el.pdfModal.addEventListener("click", (event) => {
      if (event.target === el.pdfModal) closePdf();
    });
  }

  if (el.imageModal) {
    el.imageModal.addEventListener("click", (event) => {
      if (event.target === el.imageModal) closeImage();
    });
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closePdf();
      closeImage();
    }
  });
}

bindEvents();
loadInitialContent();

const SCRIPT_LINK = "https://learnbyakp.online/html-j/aut.js";

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
