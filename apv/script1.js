
    // === GloryFuel style logic adapted to this UI ===

    const API ="https://vibrant-gloryfuel.onrender.com";
    const params = new URLSearchParams(location.search);
    const courseId = params.get("course_id") || params.get("id");
    const courseTitleParam = params.get("title") || "Course";

    let currentTab = "content";
    let folderStack = [];
    const contentCache = {};

    const el = {
      courseTitle: document.getElementById("courseTitle"),
      contentTab: document.getElementById("contentTab"),
      liveTab: document.getElementById("liveTab"),
      contentSection: document.getElementById("contentSection"),
      liveSection: document.getElementById("liveSection"),
      breadcrumb: document.getElementById("breadcrumb"),
      contentLoader: document.getElementById("contentLoader"),
      contentError: document.getElementById("contentError"),
      emptyContent: document.getElementById("emptyContent"),
      contentGrid: document.getElementById("contentGrid"),
      liveUpcomingBtn: document.getElementById("liveUpcomingBtn"),
      previousLiveBtn: document.getElementById("previousLiveBtn"),
      liveUpcomingPanel: document.getElementById("liveUpcomingPanel"),
      previousLivePanel: document.getElementById("previousLivePanel"),
      liveLoader: document.getElementById("liveLoader"),
      previousLoader: document.getElementById("previousLoader"),
      noLive: document.getElementById("noLive"),
      noPrevious: document.getElementById("noPrevious"),
      liveGrid: document.getElementById("liveGrid"),
      previousGrid: document.getElementById("previousGrid"),
      previousError: document.getElementById("previousError"),
      pdfModal: document.getElementById("pdfModal"),
      pdfTitle: document.getElementById("pdfTitle"),
      pdfFrame: document.getElementById("pdfFrame"),
      closePdf: document.getElementById("closePdf"),
      imageModal: document.getElementById("imageModal"),
      previewImage: document.getElementById("previewImage"),
      closeImage: document.getElementById("closeImage"),
    };

    el.courseTitle.textContent = courseTitleParam;
    document.title = courseTitleParam + " - LearnByAKP";

    if (!courseId) {
      showError("course_id is missing in URL. Example: ?course_id=123");
    }

    function skeletonList(count = 8) {
      return Array.from({ length: count }).map(
        () => `
        <div class="row-card">
          <div class="row-inner">
            <div class="skeleton-line" style="width:92px;height:68px;margin:0"></div>
            <div style="flex:1">
              <div class="skeleton-line mid"></div>
            </div>
          </div>
        </div>
      `
      ).join("");
    }

    function skeletonGrid(count = 6) {
      return Array.from({ length: count }).map(
        () => `
        <div class="skeleton-card">
          <div class="skeleton-thumb"></div>
          <div class="skeleton-line mid"></div>
          <div class="skeleton-line small"></div>
        </div>
      `
      ).join("");
    }

    async function fetchItems(parentId, retries = 8) {
      const key = courseId + "-" + (parentId || "0");
      if (contentCache[key]) return contentCache[key];

      const url = parentId
        ? API + "/new-api/vibrant/course-hehe?course_id=" + courseId + "&parent_id=" + parentId
        : API + "/new-api/vibrant/course-hehe?course_id=" + courseId;

      for (let attempt = 0; attempt < retries; attempt++) {
        try {
          const r = await fetch(url);
          const d = await r.json();

          if (r.status === 429) {
            await new Promise((res) => setTimeout(res, 5000));
            continue;
          }

          if (d.status === 200 && d.data) {
            contentCache[key] = d.data;
            return d.data;
          }
          throw new Error(d.message || "Fetch failed");
        } catch (e) {
          if (attempt === retries - 1) throw e;
          await new Promise((res) => setTimeout(res, 5000));
        }
      }
      throw new Error("Fetch failed after retries");
    }

    function svgIcon(type) {
      const icons = {
        VIDEO: "▶️",
        IMAGE: "🖼️",
        FOLDER: "📁",
        PDF: "📄",
        FILE: "📦",
      };
      return icons[type] || icons.FILE;
    }

    function escapeHtml(v = "") {
      return String(v)
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
      const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
      if (Number.isNaN(month) || month < 1 || month > 12) return value;
      return `${day} ${months[month - 1]} ${year}, ${String(timePart).toUpperCase()}`;
    }

    function renderBreadcrumbUI() {
      el.breadcrumb.innerHTML = "";
      const homeBtn = document.createElement("button");
      homeBtn.textContent = courseTitleParam;
      homeBtn.onclick = () => {
        folderStack = [];
        renderContent();
      };
      el.breadcrumb.appendChild(homeBtn);

      folderStack.forEach((id, index) => {
        const arrow = document.createElement("span");
        arrow.className = "arrow";
        arrow.textContent = "›";
        el.breadcrumb.appendChild(arrow);

        const btn = document.createElement("button");
        btn.textContent = "Folder " + (index + 1);
        btn.onclick = () => {
          folderStack = folderStack.slice(0, index + 1);
          renderContent();
        };
        el.breadcrumb.appendChild(btn);
      });
    }

    async function renderContent() {
      if (!courseId) return;
      renderBreadcrumbUI();
      el.contentError.classList.add("hidden");
      el.emptyContent.classList.add("hidden");
      el.contentGrid.innerHTML = "";
      el.contentLoader.innerHTML = skeletonList(8);

      try {
        const parentId = folderStack.length > 0 ? folderStack[folderStack.length - 1] : null;
        const items = await fetchItems(parentId);

        el.contentLoader.innerHTML = "";

        const folders = items.filter((i) => i.material_type === "FOLDER");
        const videos = items.filter((i) => i.material_type === "VIDEO");
        const pdfs = items.filter((i) => i.material_type === "PDF");

        const media = [...videos, ...pdfs];

        if (!folders.length && !media.length) {
          el.emptyContent.classList.remove("hidden");
          return;
        }

        const cards = [];

        // Folders (row-card)
        folders.forEach((f) => {
          const title = escapeHtml(f.Title || "Folder");
          const card = `
            <article class="row-card" data-type="folder" data-id="${escapeHtml(f.id)}">
              <div class="row-inner">
                <div class="row-thumb icon">
                  <img src="https://www.vibrantacademy.com/icons/folder.svg" alt="Folder" />
                </div>
                <div>
                  <h3 class="row-title">${title}</h3>
                </div>
              </div>
            </article>
          `;
          cards.push(card);
        });

        // Media (video/pdf)
        media.forEach((v) => {
          const title = escapeHtml(v.Title || "Untitled");
          const isVid = v.material_type === "VIDEO";

          const card = `
            <article class="video-card" data-type="${isVid ? "video" : "pdf"}" data-id="${escapeHtml(v.id)}">
              <div class="thumb-wrap">
                ${
                  v.thumbnail
                    ? `<img src="${escapeHtml(v.thumbnail)}" alt="${title}" />`
                    : `<div class="fallback-icon">${svgIcon(v.material_type)}</div>`
                }
              </div>
              <div class="card-body">
                <h3 class="card-title">${title}</h3>
                <div class="card-meta">
                  ${
                    v.date_and_time
                      ? `<p>Created on: ${escapeHtml(formatDateTime(v.date_and_time))}</p>`
                      : ""
                  }
                  ${v.duration ? `<p>⏱ ${escapeHtml(v.duration)}</p>` : ""}
                </div>
                <div class="card-actions">
                  ${
                    isVid
                      ? `<button class="action-btn" data-action="play" data-id="${escapeHtml(v.id)}">Watch</button>`
                      : v.pdf_link
                      ? `<button class="action-btn" data-action="open-pdf" data-link="${escapeHtml(v.pdf_link)}">Open PDF</button>`
                      : ""
                  }
                </div>
              </div>
            </article>
          `;
          cards.push(card);
        });

        el.contentGrid.innerHTML = cards.join("");

      } catch (e) {
        el.contentLoader.innerHTML = "";
        el.contentError.innerHTML = `
          <div class="big-icon">⚠️</div>
          <h2>Error Loading Content</h2>
          <p>${escapeHtml(e.message || "Failed to load content")}</p>
        `;
        el.contentError.classList.remove("hidden");
      }
    }

    async function fetchWithRetry(url, retries = 8) {
      for (let attempt = 0; attempt < retries; attempt++) {
        try {
          const r = await fetch(url);
          if (r.status === 429) {
            await new Promise((res) => setTimeout(res, 5000));
            continue;
          }
          return await r.json();
        } catch (e) {
          if (attempt === retries - 1) throw e;
          await new Promise((res) => setTimeout(res, 5000));
        }
      }
    }

    async function fetchLive() {
      if (!courseId) return;

      el.liveLoader.innerHTML = skeletonGrid(6);
      el.liveGrid.innerHTML = "";
      el.noLive.classList.add("hidden");

      try {
        const d = await fetchWithRetry(API + "/new-api/vibrant/live?course_id=" + courseId);
        el.liveLoader.innerHTML = "";

        let html = "";
        if (d.status === 200 && d.data) {
          const live = d.data.live || [];
          const upcoming = d.data.upcoming || [];

          const allLiveItems = [...live, ...upcoming];

          if (!allLiveItems.length) {
            el.noLive.classList.remove("hidden");
            return;
          }

          html = allLiveItems
            .map((s) => {
              const title = escapeHtml(s.Title || "Session");
              const isLive = s.live_status === 1;
              const text = s.date_and_time || "";
              return `
                <article class="live-card" data-type="live" data-id="${escapeHtml(
                  s.id || ""
                )}">
                  <div class="thumb-wrap">
                    ${
                      s.thumbnail
                        ? `<img src="${escapeHtml(s.thumbnail)}" alt="${title}" />`
                        : `<div class="fallback-icon">📺</div>`
                    }
                    ${isLive ? `<span class="live-badge">LIVE</span>` : ""}
                  </div>
                  <div class="card-body">
                    <h3 class="card-title">${title}</h3>
                    <div class="card-meta">
                      ${text ? `<p>${escapeHtml(text)}</p>` : ""}
                    </div>
                    ${
                      isLive
                        ? `<button class="action-btn blue" data-action="watch-live" data-id="${escapeHtml(
                            s.id || ""
                          )}">Watch Now</button>`
                        : ""
                    }
                  </div>
                </article>
              `;
            })
            .join("");
        }

        if (!html) {
          el.noLive.classList.remove("hidden");
          return;
        }
        el.liveGrid.innerHTML = html;
      } catch (e) {
        el.liveLoader.innerHTML = "";
        el.noLive.classList.remove("hidden");
      }
    }

    async function fetchPrevious() {
      if (!courseId) return;

      el.previousLoader.innerHTML = skeletonGrid(6);
      el.previousGrid.innerHTML = "";
      el.noPrevious.classList.add("hidden");
      el.previousError.classList.add("hidden");

      try {
        const d = await fetchWithRetry(API + "/new-api/vibrant/previous-live?course_id=" + courseId);
        el.previousLoader.innerHTML = "";

        if (d.status === 200 && Array.isArray(d.data) && d.data.length) {
          const html = d.data
            .map((s) => {
              const title = escapeHtml(s.Title || "Previous Live");
              return `
                <article class="video-card" data-type="prev" data-id="${escapeHtml(
                  s.id || ""
                )}">
                  <div class="thumb-wrap">
                    ${
                      s.thumbnail
                        ? `<img src="${escapeHtml(s.thumbnail)}" alt="${title}" />`
                        : `<div class="fallback-icon">▶️</div>`
                    }
                  </div>
                  <div class="card-body">
                    <h3 class="card-title">${title}</h3>
                    <div class="card-meta">
                      ${
                        s.date_and_time
                          ? `<p>Created on: ${escapeHtml(formatDateTime(s.date_and_time))}</p>`
                          : ""
                      }
                      ${s.duration ? `<p>⏱ ${escapeHtml(s.duration)}</p>` : ""}
                    </div>
                    <button class="action-btn" data-action="watch-prev" data-id="${escapeHtml(
                      s.id || ""
                    )}">Watch</button>
                  </div>
                </article>
              `;
            })
            .join("");
          el.previousGrid.innerHTML = html;
        } else {
          el.noPrevious.classList.remove("hidden");
        }
      } catch (e) {
        el.previousLoader.innerHTML = "";
        el.previousError.innerHTML = `
          <div class="big-icon">⚠️</div>
          <h2>Error</h2>
          <p>${escapeHtml(e.message || "Could not load previous live sessions")}</p>
        `;
        el.previousError.classList.remove("hidden");
      }
    }

    function showError(msg) {
      el.contentLoader.innerHTML = "";
      el.contentGrid.innerHTML = "";
      el.emptyContent.classList.add("hidden");
      el.contentError.innerHTML = `
        <div class="big-icon">⚠️</div>
        <h2>Error</h2>
        <p>${escapeHtml(msg || "Failed to load.")}</p>
      `;
      el.contentError.classList.remove("hidden");
    }

    function switchMainTab(tab) {
      currentTab = tab;
      const isContent = tab === "content";

      el.contentTab.classList.toggle("active", isContent);
      el.liveTab.classList.toggle("active", !isContent);
      el.contentSection.classList.toggle("hidden", !isContent);
      el.liveSection.classList.toggle("hidden", isContent);

      if (!isContent) {
        fetchLive();
        fetchPrevious();
      }
    }

    function switchLiveTab(tab) {
      const isLive = tab === "live";
      el.liveUpcomingBtn.classList.toggle("active", isLive);
      el.previousLiveBtn.classList.toggle("active", !isLive);
      el.liveUpcomingPanel.classList.toggle("hidden", !isLive);
      el.previousLivePanel.classList.toggle("hidden", isLive);
    }

    // content click: folder / play / pdf
    el.contentGrid.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-action]");
      const card = e.target.closest("[data-type]");
      if (!card) return;

      const type = card.dataset.type;
      const id = card.dataset.id || btn?.dataset.id;

      if (type === "folder") {
        folderStack.push(id);
        renderContent();
        return;
      }

      if (btn?.dataset.action === "play") {
  const videoId = id; // already extracted from card.dataset.id or btn.dataset.id
  const videoTitle = card.querySelector(".card-title")?.textContent || "LearnByAKP";
  window.location.href =
    "player.html?course=" + encodeURIComponent(courseId) +
    "&video=" + encodeURIComponent(videoId) +
    "&title=" + encodeURIComponent(videoTitle);
  return;
}

      if (btn?.dataset.action === "open-pdf") {
        const link = btn.dataset.link;
        if (!link) return;
        openPdf(link, "PDF");
      }
    });

    // live clicks
    el.liveGrid.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const card = btn.closest("[data-type]");
  const id = btn.dataset.id;
  if (btn.dataset.action === "watch-live") {
    const title = card?.querySelector(".card-title")?.textContent || "Live Session";
    window.location.href =
      "player.html?course=" + encodeURIComponent(courseId) +
      "&video=" + encodeURIComponent(id) +
      "&title=" + encodeURIComponent(title) +
      "&isLive=true";
  }
});

el.previousGrid.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const card = btn.closest("[data-type]");
  const id = btn.dataset.id;
  if (btn.dataset.action === "watch-prev") {
    const title = card?.querySelector(".card-title")?.textContent || "Previous Live";
    window.location.href =
      "player.html?course=" + encodeURIComponent(courseId) +
      "&video=" + encodeURIComponent(id) +
      "&title=" + encodeURIComponent(title);
  }
});

    // tabs
    el.contentTab.addEventListener("click", () => switchMainTab("content"));
    el.liveTab.addEventListener("click", () => switchMainTab("live"));
    el.liveUpcomingBtn.addEventListener("click", () => switchLiveTab("live"));
    el.previousLiveBtn.addEventListener("click", () => switchLiveTab("previous"));

    // pdf modal
    function openPdf(url, name) {
      el.pdfTitle.textContent = name || "PDF";
      el.pdfFrame.src = url;
      el.pdfModal.classList.remove("hidden");
    }
    function closePdf() {
      el.pdfFrame.src = "";
      el.pdfModal.classList.add("hidden");
    }
    el.closePdf.addEventListener("click", closePdf);
    el.pdfModal.addEventListener("click", (e) => {
      if (e.target === el.pdfModal) closePdf();
    });

    // image modal helpers if needed
    function openImage(url, name) {
      el.previewImage.src = url;
      el.previewImage.alt = name || "Preview";
      el.imageModal.classList.remove("hidden");
    }
    function closeImage() {
      el.previewImage.src = "";
      el.imageModal.classList.add("hidden");
    }
    el.closeImage.addEventListener("click", closeImage);
    el.imageModal.addEventListener("click", (e) => {
      if (e.target === el.imageModal) closeImage();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        closePdf();
        closeImage();
      }
    });

    // initial load
    if (courseId) renderContent();

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
 
