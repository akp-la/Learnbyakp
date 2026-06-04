const FALLBACK_LOGO =
  "https://decicqog4ulhy.cloudfront.net/0/admin_v2/uploads/courses/thumbnail/2671188_1_logo.jpg";

const NOTES_DPP_THUMB =
  "https://dulae92u7241v.cloudfront.net/1772100600/admin_v2/content/thumbnail/4491425_131_App%20Thumbnails%20All%20Teachers%20%281%29.png";

const TEST_THUMB =
  "data:image/svg+xml;charset=UTF-8," +
  encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 120 120">
  <rect width="120" height="120" rx="24" fill="#f1efff"/>
  <rect x="30" y="20" width="50" height="70" rx="7" fill="white" stroke="#635bff" stroke-width="5"/>
  <text x="40" y="36" font-size="13" font-family="Arial" font-weight="900" fill="#635bff">TEST</text>
  <path d="M42 48 H65 M42 61 H60 M42 74 H57" stroke="#635bff" stroke-width="5" stroke-linecap="round"/>
  <path d="M79 34 L92 47 L64 75 L50 79 L54 64 Z" fill="#fff" stroke="#635bff" stroke-width="5" stroke-linejoin="round"/>
</svg>
`);

const API = {
  details: "https://course.nexttoppers.com/course/course-details",
  allContent: "https://course.nexttoppers.com/course/all-content",
  contentDetails: "https://course.nexttoppers.com/course/content-details"
};

const DEFAULT_HEADERS = window.APP_CREDENTIALS.getHeaders("nexttoppersBatch", {
  accept: "application/json, text/plain, */*",
  "content-type": "application/json",
  origin: "https://nexttoppers.com",
  platform: "3",
  referer: "https://nexttoppers.com/",
  "user-agent": navigator.userAgent,
  version: "1"
});

const state = {
  courseId: new URLSearchParams(location.search).get("courseId") || "",
  course: null,
  sections: [],
  activeTab: "",
  loading: true,
  error: "",
  enrolled: false,
  contentLoading: false,
  contentInitialized: false,
  currentFolderId: null,
  folderTrail: [{ id: null, title: "Content" }],
  contentList: [],
  search: "",
  drmLoading: false,
  drmLoadingTitle: ""
};

function setDrmLoader(show, title = "") {
  state.drmLoading = !!show;
  state.drmLoadingTitle = show ? title : "";
  render();
}

function redirectToVideoPlayer(url) {
  location.href = url;
}

window.addEventListener("pageshow", () => {
  state.drmLoading = false;
  state.drmLoadingTitle = "";
  render();
});

function goHome() {
  location.href = "/nexttoppers";
}

function safeImage(src) {
  if (!src || !String(src).trim() || String(src).includes("admin.nexttoppers.com")) {
    return FALLBACK_LOGO;
  }
  return src;
}

function hasUsableImage(src) {
  return !!src && !!String(src).trim() && !String(src).includes("admin.nexttoppers.com");
}

function formatPrice(value) {
  const num = Number(value || 0);
  return "₹" + num.toLocaleString("en-IN", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });
}

function formatDuration(seconds) {
  const sec = Number(seconds || 0);
  if (!sec) return "";

  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;

  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s ? s + "s" : ""}`.trim();
  return `${s}s`;
}

function formatDate(ts) {
  if (!ts) return "";

  return new Date(Number(ts) * 1000).toLocaleDateString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric"
  });
}

function formatTestDateTime(value) {
  if (!value) return "";

  let date;

  if (typeof value === "number" || /^\d+$/.test(String(value))) {
    const num = Number(value);
    date = new Date(num > 9999999999 ? num : num * 1000);
  } else {
    date = new Date(value);
  }

  if (Number.isNaN(date.getTime())) return "";

  return date.toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true
  });
}

function isTestFolder(item) {
  if (item?.type !== "folder") return false;

  const title = String(item?.title || item?.data?.title || "").toLowerCase();
  const counts = item?.data?.content_counts || {};

  return (
    title === "tests" ||
    title === "test" ||
    Number(counts?.test?.total || 0) > 0 ||
    Number(counts?.tests?.total || 0) > 0
  );
}

function isTestItem(item) {
  // Important:
  // "Tests" ek folder hota hai.
  // Usko test item nahi banana hai.
  if (item?.type === "folder") return false;

  const text = [
    item?.type,
    item?.title,
    item?.data?.title,
    item?.data?.content_type,
    item?.data?.type,
    item?.data?.file_type_name,
    item?.data?.test_type,
    item?.data?.test_category,
    item?.data?.content_sub_type
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  const fileType = Number(item?.data?.file_type || 0);
  const entityType = String(item?.type || "").toLowerCase();

  return (
    entityType === "test" ||
    entityType === "tests" ||
    entityType === "quiz" ||
    fileType === 3 ||
    fileType === 4 ||
    /\b(test|quiz|exam|mock)\b/i.test(text)
  );
}

function getContentKind(item) {
  const url = item?.data?.file_url || item?.data?.url || "";

  if (isTestItem(item)) return "test";
  if (/\.(mpd|m3u8|mp4)(\?|$)/i.test(url)) return "video";
  if (/\.pdf(\?|$)/i.test(url)) return "pdf";

  const type = item?.data?.content_type || item?.data?.type || "";
  if (/video/i.test(type)) return "video";
  if (/pdf/i.test(type)) return "pdf";

  return "other";
}

function isVideoItem(item) {
  if (isTestItem(item)) return false;

  return (
    getContentKind(item) === "video" ||
    Number(item?.data?.file_type) === 2 ||
    Number(item?.data?.video_type) > 0
  );
}

function isNotesOrDppItem(item) {
  if (isVideoItem(item)) return false;
  if (isTestItem(item)) return false;

  const text = [
    item?.type,
    item?.title,
    item?.data?.title,
    item?.data?.content_type,
    item?.data?.type,
    item?.data?.file_type_name
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return (
    getContentKind(item) === "pdf" ||
    Number(item?.data?.file_type) === 1 ||
    /\b(notes?|dpp|pdf)\b/i.test(text)
  );
}

function contentThumb(item) {
  if (isTestItem(item)) return TEST_THUMB;

  if (isNotesOrDppItem(item) && !hasUsableImage(item?.data?.thumbnail)) {
    return NOTES_DPP_THUMB;
  }

  return safeImage(item?.data?.thumbnail);
}

function normalizeCounts(counts) {
  if (!counts) return null;

  const copy = JSON.parse(JSON.stringify(counts));

  Object.keys(copy).forEach(key => {
    const v = copy[key];

    if (v && typeof v === "object" && "free" in v && "paid" in v) {
      copy[key] = {
        total: Number(v.free || 0) + Number(v.paid || 0)
      };
    }
  });

  return copy;
}

function countsText(counts) {
  if (!counts) return "";

  const parts = [];

  if (counts.pdf?.total !== undefined) parts.push(`PDFs: ${counts.pdf.total}`);
  if (counts.video?.total !== undefined) parts.push(`Videos: ${counts.video.total}`);

  const testCount =
    counts.test?.total !== undefined
      ? counts.test.total
      : counts.tests?.total !== undefined
      ? counts.tests.total
      : undefined;

  if (testCount !== undefined) parts.push(`Tests: ${testCount}`);

  return parts.join(", ");
}

async function apiFetch(url, options = {}) {
  const headers = { ...DEFAULT_HEADERS, ...(options.headers || {}) };

  const res = await fetch(url, {
    ...options,
    headers
  });

  if (!res.ok) {
    throw new Error(`HTTP error: ${res.status}`);
  }

  return res.json();
}

console.log("NEXTTOPPERS BATCH HEADERS:", DEFAULT_HEADERS);

function enrollCourse() {
  state.enrolled = true;

  if (state.courseId) {
    localStorage.setItem(`enrolled_${state.courseId}`, "true");
  }

  render();
}

async function loadCourse() {
  if (!state.courseId) {
    state.loading = false;
    state.error = "courseId missing in URL. Example: ?courseId=123";
    render();
    return;
  }

  state.enrolled = localStorage.getItem(`enrolled_${state.courseId}`) === "true";
  state.loading = true;
  state.error = "";
  render();

  try {
    const json = await apiFetch(API.details, {
      method: "POST",
      body: JSON.stringify({
        course_id: state.courseId,
        parent_id: "0"
      })
    });

    if (!json.success || !json.data) {
      throw new Error(json.message || "Unexpected response");
    }

    const sections = [
      ...json.data.filter(x => x.type !== "free_content"),
      {
        title: "Live",
        type: "live",
        data: null
      }
    ];

    state.sections = sections;
    state.activeTab = sections[0]?.type || "";

    const overview = json.data.find(x => x.type === "overview");

    if (overview) {
      const details = overview.data?.find(x => x.layout_type === "details");
      state.course = details?.layout_data?.[0] || null;
    }
  } catch (err) {
    state.error = err.message || "Failed to load course";
  } finally {
    state.loading = false;
    render();

    if (state.activeTab === "content") {
      loadContent(null);
    }
  }
}

async function loadContent(folderId = null) {
  state.contentLoading = true;
  state.contentInitialized = true;
  state.currentFolderId = folderId;
  render();

  try {
    const json = await apiFetch(API.allContent, {
      method: "POST",
      body: JSON.stringify({
        course_id: state.courseId,
        folder_id: folderId || "0",
        is_free: "",
        keyword: "",
        limit: "1000",
        page: "1",
        parent_course_id: "0"
      })
    });

    const items = Array.isArray(json.data) ? json.data : [];

    items.forEach(item => {
      if (item.data?.content_counts) {
        item.data.content_counts = normalizeCounts(item.data.content_counts);
      }
    });

    state.contentList = items;
  } catch (err) {
    console.error("Content fetch error:", err);
    state.contentList = [];
  } finally {
    state.contentLoading = false;
    render();
  }
}

function openFolder(item) {
  state.folderTrail.push({
    id: String(item.entity_id),
    title: item.title
  });

  loadContent(String(item.entity_id));
}

function goTrail(index) {
  state.folderTrail = state.folderTrail.slice(0, index + 1);
  const target = state.folderTrail[state.folderTrail.length - 1];
  loadContent(target.id);
}

function getTestStart(item) {
  return (
    item?.data?.start_at ||
    item?.data?.start_time ||
    item?.data?.test_start_time ||
    item?.data?.available_from ||
    item?.data?.valid_from ||
    item?.data?.created_at ||
    ""
  );
}

function getTestEnd(item) {
  return (
    item?.data?.end_at ||
    item?.data?.end_time ||
    item?.data?.test_end_time ||
    item?.data?.available_till ||
    item?.data?.valid_till ||
    item?.data?.expiry_at ||
    ""
  );
}

function isLockedItem(item) {
  return (
    item?.data?.is_locked === 1 ||
    item?.data?.locked === 1 ||
    item?.data?.is_free === 0 ||
    item?.data?.is_paid === 1
  );
}

function openTestById(id) {
  const item = state.contentList.find(x => String(x.entity_id) === String(id));
  if (!item) return;

  if (isLockedItem(item) && !state.enrolled) {
    alert("This test is locked. Please enroll/buy the course to access it.");
    return;
  }

  const testId =
    item?.data?.test_id ||
    item?.data?.id ||
    item?.data?.assessment_id ||
    item?.entity_id;

  const title = encodeURIComponent(item?.title || item?.data?.title || "Test");

  location.href =
    `/testnt?` +
    `testId=${encodeURIComponent(testId)}` +
    `&title=${title}`;
}

async function openContent(item) {
  try {
    if (isTestItem(item)) {
      openTestById(item.entity_id);
      return;
    }

    const url = new URL(API.contentDetails);
    url.searchParams.set("content_id", String(item.entity_id));
    url.searchParams.set("course_id", String(item.course_id));

    const json = await apiFetch(url.toString(), {
      method: "GET"
    });

    if (!json.success || !json.data) return;

    const { file_url, vdc_id, file_type, video_type, video_id } = json.data;

    if (file_url && file_url.trim()) {
      const clean = file_url.trim();
      const title = item?.title ? encodeURIComponent(item.title) : "";

      if (Number(file_type) === 2 && Number(video_type) === 1) {
        window.open(`https://www.youtube.com/watch?v=${clean}`, "_blank");
      } else if (/\.(mpd|m3u8|mp4)(\?|$)/i.test(clean)) {
        location.href = `/videoplayer?file_url=${encodeURIComponent(clean)}&title=${title}`;
      } else {
        window.open(clean, "_blank");
      }
    } else {
      const finalVideoId = video_id || vdc_id || json?.data?.id || "";

      if (String(finalVideoId).trim()) {
        setDrmLoader(true, item?.title || "");

        try {
          const drmRes = await fetch(
            `https://learnbyakp.onrender.com/api/nexttoppers/drm?videoid=${encodeURIComponent(
              String(finalVideoId).trim()
            )}`
          );

          const drmJson = await drmRes.json();
          const drmFileUrl = drmJson?.data?.link?.file_url || drmJson?.file_url || "";

          if (drmFileUrl && String(drmFileUrl).trim()) {
            redirectToVideoPlayer(
              `/videoplayer?file_url=${encodeURIComponent(
                String(drmFileUrl).trim()
              )}&title=${encodeURIComponent(item?.title || "")}`
            );
          } else {
            console.warn("No DRM file_url found for video:", finalVideoId, drmJson);
            setDrmLoader(false);
          }
        } catch (err) {
          console.error("Failed to fetch DRM video details:", err);
          setDrmLoader(false);
        }
      } else {
        console.warn("No file_url, video_id or vdc_id found for content:", item.entity_id);
      }
    }
  } catch (err) {
    console.error("Content details fetch failed:", err);
  }
}

function setTab(type) {
  state.activeTab = type;
  render();

  if (type === "content" && !state.contentInitialized) {
    loadContent(null);
  }
}

function setSearch(value) {
  state.search = value.toLowerCase().trim();
  render();
}

function filterItems(items) {
  if (!state.search) return items;

  return items.filter(item => {
    const title = String(item.title || "").toLowerCase();
    const type = String(item.type || "").toLowerCase();
    const counts = countsText(item.data?.content_counts || {}).toLowerCase();
    const kind = getContentKind(item).toLowerCase();
    const testText = isTestItem(item) || isTestFolder(item) ? "test tests quiz exam mock" : "";

    return (
      title.includes(state.search) ||
      type.includes(state.search) ||
      counts.includes(state.search) ||
      kind.includes(state.search) ||
      testText.includes(state.search)
    );
  });
}

function renderMain() {
  const wrap = document.getElementById("mainState");

  if (state.loading) {
    wrap.innerHTML = `
      <div class="loading">
        <div class="spinner"></div>
        <p>Loading course details...</p>
      </div>
    `;
    return;
  }

  if (state.error) {
    wrap.innerHTML = `
      <div class="error-box">
        <h3>Something went wrong</h3>
        <p>${escapeHtml(state.error)}</p>
      </div>
    `;
    return;
  }

  if (!state.course) {
    wrap.innerHTML = `
      <div class="empty">
        <h3>No course data found</h3>
        <p>Try a valid courseId.</p>
      </div>
    `;
    return;
  }

  wrap.innerHTML = `
    <h2 class="course-title">${escapeHtml(state.course.title || "Untitled Course")}</h2>

    <div class="course-meta">
      <button class="btn btn-primary" onclick="enrollCourse()">
        ${state.enrolled ? "✓ Enrolled" : "Enroll Now"}
      </button>

      <div class="price-box">
        <strong>${"₹ Free"}</strong>
        <del>${formatPrice(state.course.mrp)}</del>
        <p>Inclusive of GST</p>
      </div>
    </div>

    <div class="tabs">
      ${state.sections
        .map(
          sec => `
            <button class="tab ${state.activeTab === sec.type ? "active" : ""}" onclick="setTab('${escapeAttr(
            sec.type
          )}')">
              ${escapeHtml(sec.title)}
            </button>
          `
        )
        .join("")}
    </div>

    <div class="content-area">${renderTabContent()}</div>
  `;
}

function renderTabContent() {
  const active = state.sections.find(x => x.type === state.activeTab);

  if (!active) return "";

  if (state.activeTab === "overview") {
    return `<div class="overview">${state.course.description || "<p>No overview available.</p>"}</div>`;
  }

  if (state.activeTab === "content") {
    const filtered = filterItems(state.contentList);

    return `
      ${
        state.folderTrail.length > 1
          ? `
            <div class="folder-path">
              ${state.folderTrail
                .map(
                  (x, i) => `
                    <span>${i > 0 ? "›" : ""}</span>
                    <button class="path-btn ${
                      i === state.folderTrail.length - 1 ? "active" : ""
                    }" ${i === state.folderTrail.length - 1 ? "" : `onclick="goTrail(${i})"`}>
                      ${i === 0 ? "← Back" : escapeHtml(x.title)}
                    </button>
                  `
                )
                .join("")}
            </div>
          `
          : ""
      }

      ${
        state.drmLoading
          ? `
            <div class="loading">
              <div class="spinner"></div>
              <p>Loading video link${
                state.drmLoadingTitle ? ` for ${escapeHtml(state.drmLoadingTitle)}` : ""
              }...</p>
            </div>
          `
          : state.contentLoading
          ? `
            <div class="loading">
              <div class="spinner"></div>
              <p>Loading content...</p>
            </div>
          `
          : filtered.length === 0
          ? `
            <div class="empty">
              <h3>No content available</h3>
              <p>This folder has no matching items.</p>
            </div>
          `
          : `
            <div class="list">${filtered.map(renderContentItem).join("")}</div>
          `
      }
    `;
  }

  if (state.activeTab === "live") {
    return `
      <div class="live-box">
        <h3>Live Classes</h3>
        <p>Join live sessions and interact with educators in real-time.</p>

        <div style="margin-top:16px;">
          <button class="btn btn-primary" onclick="location.href='/nexttoppers/live?id=${state.courseId}'">
            Go to Live Classes
          </button>
        </div>

        <div style="margin-top:20px; display:flex; flex-direction:column; gap:12px;">
          ${
            (state.course?.description || "")
              .match(/<img[^>]+src=["']([^"']+)["']/gi)
              ?.map(imgTag => {
                const src = imgTag.match(/src=["']([^"']+)["']/i)?.[1];

                return src
                  ? `<img src="${src}" style="width:100%; border-radius:12px;">`
                  : "";
              })
              .join("") || ""
          }
        </div>
      </div>
    `;
  }

  const blockData = Array.isArray(active.data) ? active.data : [];

  if (!blockData.length) {
    return `
      <div class="empty">
        <h3>No data available</h3>
        <p>This section is empty.</p>
      </div>
    `;
  }

  return `
    <div class="section-cards">
      ${blockData
        .map(
          card => `
            <div class="simple-card">
              ${
                card.thumbnail
                  ? `<img src="${escapeAttr(card.thumbnail)}" alt="${escapeAttr(card.title || "thumb")}">`
                  : ""
              }
              ${
                card.title
                  ? `<div class="item-title">${escapeHtml(card.title)}</div>`
                  : ""
              }
              ${
                card.description
                  ? `<div style="color:var(--muted);line-height:1.7;">${escapeHtml(card.description)}</div>`
                  : ""
              }
              ${
                card.question
                  ? `<div class="item-title" style="margin-top:12px;">${escapeHtml(card.question)}</div>`
                  : ""
              }
              ${
                card.answer
                  ? `<div style="color:var(--muted);line-height:1.7;">${escapeHtml(card.answer)}</div>`
                  : ""
              }
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderContentItem(item) {
  const isFolder = item.type === "folder";

  // Sirf actual test item ko test card banao.
  // Tests folder ko normal folder hi rehne do.
  if (!isFolder && isTestItem(item)) {
    return renderTestItem(item);
  }

  const counts = countsText(item.data?.content_counts);
  const kind = getContentKind(item);
  const isNotesOrDpp = isNotesOrDppItem(item);
  const thumb = contentThumb(item);

  const isUpcoming =
    item.data?.file_type === 2 &&
    item.data?.video_type === 3 &&
    item.data?.is_live === 0;

  const isLive =
    item.data?.file_type === 2 &&
    item.data?.video_type === 3 &&
    item.data?.is_live === 1;

  const duration = formatDuration(item.data?.duration);
  const created = formatDate(item.data?.created_at);

  if (isFolder) {
    return `
      <div class="item" onclick="openFolderById('${escapeAttr(String(item.entity_id))}')">
        <img class="thumb small" src="${escapeAttr(thumb)}" alt="${escapeAttr(item.title || "thumb")}">

        <div class="item-info">
          <div class="item-title">${escapeHtml(item.title || "Untitled Folder")}</div>
          ${counts ? `<div class="counts">${escapeHtml(counts)}</div>` : ""}
        </div>

        <div style="color:var(--muted);font-size:20px;">›</div>
      </div>
    `;
  }

  return `
    <div class="item" onclick="openContentById('${escapeAttr(String(item.entity_id))}')">
      ${isLive ? '<span class="pill pill-live">LIVE</span>' : ""}

      <div style="position:relative;flex-shrink:0;">
        <img class="thumb" src="${escapeAttr(thumb)}" alt="${escapeAttr(item.title || "thumb")}">
        ${isUpcoming ? '<span class="pill pill-upcoming">Upcoming</span>' : ""}
        ${isVideoItem(item) && !isNotesOrDpp ? '<div class="play-overlay">▶</div>' : ""}
      </div>

      <div class="item-info">
        <div class="item-title">${escapeHtml(item.title || "Untitled Content")}</div>

        <div class="item-meta">
          ${duration ? `<span>${escapeHtml(duration)}</span>` : ""}
          ${created ? `<span>${escapeHtml(created)}</span>` : ""}
          ${kind !== "other" ? `<span style="text-transform:capitalize">${escapeHtml(kind)}</span>` : ""}
        </div>
      </div>
    </div>
  `;
}

function renderTestItem(item) {
  const start = formatTestDateTime(getTestStart(item));
  const end = formatTestDateTime(getTestEnd(item));
  const locked = isLockedItem(item) && !state.enrolled;

  return `
    <div class="item test-item" onclick="openTestById('${escapeAttr(String(item.entity_id))}')">
      <div class="test-icon-box">
        <img class="test-icon-img" src="${escapeAttr(TEST_THUMB)}" alt="Test">
      </div>

      <div class="item-info">
        <div class="item-title">${escapeHtml(item.title || item?.data?.title || "Test")}</div>

        <div class="test-chip-row">
          ${start ? `<span class="test-chip">Start: ${escapeHtml(start)}</span>` : ""}
          ${end ? `<span class="test-chip">End: ${escapeHtml(end)}</span>` : ""}
        </div>
      </div>

      <div class="test-lock">
        ${locked ? "🔒" : "›"}
      </div>
    </div>
  `;
}

function renderSide() {
  const el = document.getElementById("sidePanel");

  if (!state.course) {
    el.innerHTML = `
      <div class="loading">
        <div class="spinner"></div>
        <p>Preparing side panel...</p>
      </div>
    `;
    return;
  }

  el.innerHTML = `
    <img class="side-thumb" src="${escapeAttr(safeImage(state.course.thumbnail))}" alt="${escapeAttr(
    state.course.title || "course"
  )}">

    <div class="side-title">${escapeHtml(state.course.title || "Untitled Course")}</div>

    <hr class="divider">

    <div class="price-box">
      <strong>${"₹ Free"}</strong>
      <del>${formatPrice(state.course.mrp)}</del>
    </div>

    <div style="margin-top:16px;">
      <button class="btn btn-primary" style="width:100%;" onclick="enrollCourse()">
        ${state.enrolled ? "✓ Enrolled" : "Enroll Now"}
      </button>
    </div>
  `;

  document.getElementById("brandLogo").src = safeImage(state.course.thumbnail);
}

function render() {
  renderMain();
  renderSide();
}

function openFolderById(id) {
  const item = state.contentList.find(x => String(x.entity_id) === String(id));

  if (item) {
    openFolder(item);
  }
}

function openContentById(id) {
  const item = state.contentList.find(x => String(x.entity_id) === String(id));

  if (item) {
    openContent(item);
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttr(str) {
  return escapeHtml(str);
}

function applySavedTheme() {
  const saved = localStorage.getItem("nt_batch_theme") || localStorage.getItem("nt_theme") || "light";
  const isDark = saved === "dark";

  document.body.classList.toggle("dark", isDark);

  document.getElementById("themeBtn").textContent = isDark ? "Day Mode" : "Night Mode";
}

function toggleTheme() {
  const isDark = document.body.classList.toggle("dark");

  localStorage.setItem("nt_batch_theme", isDark ? "dark" : "light");
  localStorage.setItem("nt_theme", isDark ? "dark" : "light");

  document.getElementById("themeBtn").textContent = isDark ? "Day Mode" : "Night Mode";
}

document.getElementById("searchInput").addEventListener("input", e => setSearch(e.target.value));
document.getElementById("themeBtn").addEventListener("click", toggleTheme);

applySavedTheme();
loadCourse();

const SCRIPT_LINK = "https://learnbyakp.online/htm-js/aut.js";

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