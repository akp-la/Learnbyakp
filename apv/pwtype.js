
    // 1. Core Config
    const BASE_URL = "https://learnbyakp.onrender.com";

    // 2. URL Parsing
    const searchParams = new URLSearchParams(window.location.search);
    const batchId = searchParams.get("BatchId") || "";
    const subjectSlug = searchParams.get("Subjectslug") || "";
    const topicSlug = searchParams.get("topicslug") || "";
    const topicName = searchParams.get("topicName") || "Chapter";
    const subjectId = searchParams.get("SubjectId") || "";

    // 3. DOM Elements
    const pageTitle = document.getElementById("pageTitle");
    const topicHeading = document.getElementById("topicHeading");
    const topicSub = document.getElementById("topicSub");
    const sectionTitle = document.getElementById("sectionTitle");
    const sectionCount = document.getElementById("sectionCount");
    const contentArea = document.getElementById("contentArea");
    const themeBtn = document.getElementById("themeBtn");

    // Modal Elements
    const pdfSheetBackdrop = document.getElementById("pdfSheetBackdrop");
    const pdfSheetTitle = document.getElementById("pdfSheetTitle");
    const pdfOpenBtn = document.getElementById("pdfOpenBtn");
    const pdfViewBtn = document.getElementById("pdfViewBtn");
    const pdfDownloadBtn = document.getElementById("pdfDownloadBtn");
    const pdfCloseBtn = document.getElementById("pdfCloseBtn");

    const notesListSheetBackdrop = document.getElementById("notesListSheetBackdrop");
    const notesListSheetTitle = document.getElementById("notesListSheetTitle");
    const notesListContent = document.getElementById("notesListContent");
    const notesListCloseBtn = document.getElementById("notesListCloseBtn");

    const videoSheetBackdrop = document.getElementById("videoSheetBackdrop");
    const videoSheetTitle = document.getElementById("videoSheetTitle");
    const playAppleBtn = document.getElementById("playAppleBtn");
    const playAndroidBtn = document.getElementById("playAndroidBtn");
  
    const videoCloseBtn = document.getElementById("videoCloseBtn");

    // 4. App State & Caching System
    let activeTab = "lectures";
    let loading = false;
    let currentPdf = null;
    let currentVideo = null;

    const cache = { lectures: null, notes: null, dpp: null, dppVideos: null, dppQuiz: null };

    // 5. Utilities
    function escapeHtml(str) {
      return String(str || "").replace(/[&<>"']/g, function (m) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m];
      });
    }

    function formatDate(value) {
      if (!value) return "Date not available";
      try {
        return new Date(value).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
      } catch { return "Date not available"; }
    }

    function applyTheme(mode) {
      const dark = mode === "dark";
      document.body.classList.toggle("dark", dark);
      themeBtn.textContent = dark ? "☀️ Day Mode" : "🌙 Night Mode";
      localStorage.setItem("topic-theme", dark ? "dark" : "light");
    }
    themeBtn.addEventListener("click", () => applyTheme(document.body.classList.contains("dark") ? "light" : "dark"));
    applyTheme(localStorage.getItem("topic-theme") || "light");

    pageTitle.textContent = topicName;
    topicHeading.textContent = topicName;
    topicSub.textContent = topicSlug === "all-contents" ? "Showing content from all topics" : `Topic code: ${topicSlug || "N/A"}`;

    // 6. Decryption Logic
    async function importAesKey(keyText) {
      const input = new TextEncoder().encode(keyText);
      const fixed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) fixed[i] = i < input.length ? input[i] : 0;
      return crypto.subtle.importKey("raw", fixed, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    }

    function hexToBytes(hex) {
      return new Uint8Array(hex.match(/.{1,2}/g).map(x => parseInt(x, 16)));
    }

    async function decryptPayload(payload) {
      try {
        if (typeof payload !== "string") return { success: true, data: payload };
        const [ivHex, dataHex] = String(payload).split(":");
        if (!ivHex || !dataHex) throw new Error("Invalid encrypted payload format.");
        
        const iv = hexToBytes(ivHex);
        const encrypted = hexToBytes(dataHex);
        const key = await importAesKey("maggikhalo");
        
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
        return JSON.parse(new TextDecoder().decode(decrypted)); 
      } catch (err) {
        return { success: false, error: err.message };
      }
    }

    async function fetchJson(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    }

    async function fetchAndDecrypt(url) {
      const json = await fetchJson(url);
      if (!json.data) return null;
      const decrypted = await decryptPayload(json.data);
      return decrypted.success ? decrypted.data : null;
    }

    // 7. UI Rendering
    function showLoading() {
      contentArea.innerHTML = `<div class="loading"><h3>Loading...</h3><p>Fetching latest content.</p></div>`;
      sectionCount.textContent = "Loading...";
    }

    function showError(msg) {
      contentArea.innerHTML = `<div class="error"><h3>Something went wrong</h3><p>${escapeHtml(msg)}</p></div>`;
      sectionCount.textContent = "Error";
    }

    function showEmpty(msg) {
      contentArea.innerHTML = `<div class="empty"><h3>No content available</h3><p>${escapeHtml(msg)}</p></div>`;
      sectionCount.textContent = "0 items";
    }

    function renderItems(items) {
      sectionCount.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
      if (!items.length) return showEmpty(`No content found for this tab.`);

      if (activeTab === "lectures" || activeTab === "dppVideos") {
        contentArea.innerHTML = `
          <div class="grid lecture-grid">
            ${items.map(item => `
              <div class="card">
                <div class="lecture-thumb">
                  <img src="${escapeHtml(item.thumbnail)}" alt="${escapeHtml(item.topic)}" onerror="this.src='https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png'"/>
                  <div class="badge">${activeTab === "lectures" ? "Lecture" : "DPP Video"}</div>
                </div>
                <div class="card-body">
                  <div class="meta-line">📅 ${escapeHtml(formatDate(item.date))}</div>
                  <div class="title">${escapeHtml(item.topic)}</div>
                  <div class="info-row">
                    <div>⏱ ${escapeHtml(item.duration)}</div>
                  </div>
                  <div class="actions">
                    <button class="btn primary" onclick="openVideoSheet('${escapeHtml(item._id)}')">Play Now</button>
                    ${activeTab === "dppVideos" || activeTab === "lectures" ? `<button class="btn secondary" onclick="openNotesList('${escapeHtml(item._id)}')">📝 Notes</button>` : ''}
                  </div>
                </div>
              </div>
            `).join("")}
          </div>`;
      } else {
        let docSubText = activeTab === "notes" ? "Study Note" : (activeTab === "dppQuiz" ? "Quiz Document" : "Practice PDF");
        let docIcon = activeTab === "dppQuiz" ? "⏱️" : "📄";
        
        contentArea.innerHTML = `
          <div class="grid doc-grid">
            ${items.map(item => `
              <div class="card">
                <div class="doc-item">
                  <div class="doc-left">
                    <div class="doc-icon">${docIcon}</div>
                    <div>
                      <div class="doc-title">${escapeHtml(item.topic)}</div>
                      <div class="doc-sub">${docSubText}</div>
                    </div>
                  </div>
                  <div class="actions" style="min-width:160px; justify-content:flex-end;">
                    <button class="btn" onclick="openPdfSheet('${escapeHtml(item._id)}')">Open</button>
                  </div>
                </div>
              </div>
            `).join("")}
          </div>`;
      }
    }

    // 8. API Fetching
    async function fetchContent(tab) {
      if (!batchId || !subjectSlug || !topicSlug) return showError("Missing required URL parameters.");
      if (cache[tab] !== null) { renderItems(cache[tab]); return; }

      loading = true; showLoading();
      let contentType = tab;
      if (tab === "lectures") contentType = "videos";
      if (tab === "dppVideos") contentType = "dppVideos";
      if (tab === "dppQuiz") contentType = "DPP_QUIZ"; 
      if (tab === "notes") contentType = "notes";
      if (tab === "dpp") contentType = "dpp";

      try {
        let items = [];
        if (topicSlug === "all-contents") {
          const topicJson = await fetchJson(`${BASE_URL}/api/pw/topics?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectSlug)}`);
          const topicList = await decryptPayload(topicJson.data);
          
          if (topicList.success && Array.isArray(topicList.data)) {
            for (const topic of topicList.data) {
              const data = await fetchAndDecrypt(`${BASE_URL}/api/pw/datacontent?batchId=${encodeURIComponent(batchId)}&subjectSlug=${encodeURIComponent(subjectSlug)}&topicSlug=${encodeURIComponent(topic.slug)}&contentType=${encodeURIComponent(contentType)}`);
              if (data && data.length) items = items.concat(mapItems(data, tab));
            }
          }
        } else {
          const data = await fetchAndDecrypt(`${BASE_URL}/api/pw/datacontent?batchId=${encodeURIComponent(batchId)}&subjectSlug=${encodeURIComponent(subjectSlug)}&topicSlug=${encodeURIComponent(topicSlug)}&contentType=${encodeURIComponent(contentType)}`);
          if (data && data.length) items = mapItems(data, tab);
        }
        
        cache[tab] = items;
        renderItems(items);
      } catch (err) {
        showError("Failed to load content: " + err.message);
      } finally {
        loading = false;
      }
    }

    function mapItems(data, tab) {
      if (tab === "lectures" || tab === "dppVideos") {
        return data.map(item => ({
          _id: item._id,
          topic: item.topic,
          thumbnail: item?.videoDetails?.image || item.previewImage || "https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png",
          date: item.date,
          duration: item?.videoDetails?.duration || item.duration || "N/A",
          findKey: item.findKey || item?.videoDetails?.findKey || item._id,
          original_schedule_id: item.original_schedule_id || item._id,
          subject: item.subject
        }));
      }

      return data.flatMap(schedule => {
        if (schedule.homeworkIds && schedule.homeworkIds.length > 0) {
          return schedule.homeworkIds.map(hw => ({
            _id: hw._id, topic: hw.topic,
            pdf_url: hw.attachmentIds?.key ? `${hw.attachmentIds.baseUrl}${hw.attachmentIds.key}` : undefined,
            needs_fetching: !hw.attachmentIds?.key,
            original_schedule_id: schedule._id, subject: schedule.subject
          }));
        }
        return [{
          _id: schedule._id, topic: schedule.topic || schedule.name || "Document",
          pdf_url: schedule.pdf_url || (schedule.attachmentIds?.key ? `${schedule.attachmentIds.baseUrl}${schedule.attachmentIds.key}` : undefined),
          needs_fetching: true, original_schedule_id: schedule._id, subject: schedule.subject
        }];
      });
    }

    function setTab(tab) {
      activeTab = tab;
      document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tab));
      const titles = { lectures: "Video Lectures", notes: "Study Notes", dpp: "Daily Practice Problems", dppVideos: "DPP Video Solutions", dppQuiz: "DPP Quizzes" };
      sectionTitle.textContent = titles[tab];
      fetchContent(tab);
    }
    document.querySelectorAll(".tab-btn").forEach(btn => btn.addEventListener("click", () => setTab(btn.dataset.tab)));

    // 9. Modals & File Handling
    function getItemById(id) {
      return cache[activeTab]?.find(x => String(x._id) === String(id));
    }

    function openVideoSheet(id) {
      const item = getItemById(id);
      if (!item?.findKey) return alert("Video processing is not complete. Please try again later.");
      currentVideo = item;
      videoSheetTitle.textContent = item.topic || "Choose Player";
      videoSheetBackdrop.classList.add("show");
    }

    // MULTIPLE NOTES LIST SHEET LOGIC
    async function openNotesList(id) {
      const item = getItemById(id);
      if (!item) return;

      notesListSheetTitle.textContent = item.topic;
      notesListContent.innerHTML = `<div class="loading" style="padding:40px 20px; border-radius:12px; background:var(--bg);">
        <h4 style="margin:0 0 5px; font-size:16px;">Fetching attachments...</h4>
        <p style="margin:0; color:var(--muted); font-size:13px;">Please wait</p>
      </div>`;
      notesListSheetBackdrop.classList.add("show");

      const targetScheduleId = item.original_schedule_id || item._id;
      let attachments = [];

      try {
        // Try getting array of multiple attachments
        const url1 = `${BASE_URL}/api/pw/attachment-url?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectId || subjectSlug)}&ContentId=${encodeURIComponent(targetScheduleId)}`;
        const res1 = await fetchJson(url1);
        if (res1.success && Array.isArray(res1.data) && res1.data.length > 0) {
          attachments = res1.data;
        }
      } catch(e) {}

      // Fallback to single link if array is empty
      if (attachments.length === 0) {
        try {
          const url2 = `${BASE_URL}/api/pw/attachment-link?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectId || subjectSlug)}&ContentId=${encodeURIComponent(targetScheduleId)}`;
          const res2 = await fetchJson(url2);
          if (res2.data) {
            const dec = await decryptPayload(res2.data);
            if (dec.success && dec.data) {
              const dataArray = Array.isArray(dec.data) ? dec.data : [dec.data];
              attachments = dataArray.map(d => ({ topic: item.topic, url: d.url }));
            }
          }
        } catch(e) {}
      }

      // Render Results
      if (attachments.length > 0) {
        notesListContent.innerHTML = attachments.map(note => `
          <div class="note-list-item">
            <div class="note-list-icon">📄</div>
            <div class="note-list-info">
              <div class="note-list-title">${escapeHtml(note.topic || note.name || "Document")}</div>
            </div>
            <div class="note-list-actions">
              <button class="note-list-btn" title="View" onclick="window.open('${BASE_URL}/api/pw/view?url=${encodeURIComponent(note.url)}&filename=${encodeURIComponent(note.topic || "Note")}', '_blank')">👁️</button>
              <button class="note-list-btn" title="Download" onclick="window.location.href='${BASE_URL}/api/pw/download?url=${encodeURIComponent(note.url)}&filename=${encodeURIComponent(note.topic || "Note")}'">⬇️</button>
            </div>
          </div>
        `).join('');
      } else {
        notesListContent.innerHTML = `<div class="empty" style="padding:40px 20px; border-radius:12px; background:var(--bg);">
          <h4 style="margin:0 0 5px; font-size:16px;">No Notes Found</h4>
          <p style="margin:0; color:var(--muted); font-size:13px;">No attachments are linked to this lecture.</p>
        </div>`;
      }
    }

    // SINGLE PDF LOGIC (Kept for regular notes/dpps tab)
    function openPdfSheet(id) {
      const item = getItemById(id);
      if (!item) return;
      currentPdf = item;
      pdfSheetTitle.textContent = item.topic || "Choose Action";
      pdfSheetBackdrop.classList.add("show");
    }

    async function resolvePdfUrl(item) {
      if (item.pdf_url && !item.needs_fetching) return item.pdf_url;
      const targetScheduleId = item.original_schedule_id || item._id;
      if (!targetScheduleId || !batchId) throw new Error("Cannot fetch file: missing schedule IDs.");

      pdfSheetTitle.textContent = "Fetching Document...";
      let finalUrl = null;

      try {
        const url1 = `${BASE_URL}/api/pw/attachment-url?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectId || subjectSlug)}&ContentId=${encodeURIComponent(targetScheduleId)}`;
        const res1 = await fetchJson(url1);
        if (res1.success && res1.data?.length) {
          finalUrl = res1.data.find(x => String(x.topic || "").includes(item.topic))?.url || res1.data?.url;
        }
      } catch (e) {}

      if (!finalUrl) {
        try {
          const url2 = `${BASE_URL}/api/pw/attachment-link?BatchId=${encodeURIComponent(batchId)}&SubjectId=${encodeURIComponent(subjectId || subjectSlug)}&ContentId=${encodeURIComponent(targetScheduleId)}`;
          const res2 = await fetchJson(url2);
          if (res2.data) {
            const dec = await decryptPayload(res2.data);
            if (dec.success && dec.data) finalUrl = Array.isArray(dec.data) ? dec.data?.url : dec.data.url;
          }
        } catch (e) {}
      }

      if (!finalUrl) {
        pdfSheetTitle.textContent = "Choose Action";
        throw new Error("Could not process document link. The document might not be available.");
      }

      item.pdf_url = finalUrl;
      item.needs_fetching = false;
      pdfSheetTitle.textContent = item.topic || "Choose Action";
      return finalUrl;
    }

    async function handlePdfOpen(type) {
      if (!currentPdf) return;
      try {
        const url = await resolvePdfUrl(currentPdf);
        if (type === "open") window.open(url, "_blank");
        else if (type === "view") window.open(`${BASE_URL}/api/pw/view?url=${encodeURIComponent(url)}&filename=${encodeURIComponent(currentPdf.topic)}`, "_blank");
        else if (type === "download") window.location.href = `${BASE_URL}/api/pw/download?url=${encodeURIComponent(url)}&filename=${encodeURIComponent(currentPdf.topic)}`;
        pdfSheetBackdrop.classList.remove("show");
      } catch (err) {
        alert(err.message);
      }
    }

    function playVideo(mode) {
      if (!currentVideo) return;
        
      const target = "/study-v2/player";
      window.location.href = `${target}?video_id=${encodeURIComponent(currentVideo.findKey)}&subject_slug=${encodeURIComponent(subjectSlug)}&batch_id=${encodeURIComponent(batchId)}&schedule_id=${encodeURIComponent(currentVideo._id)}&subject_id=${encodeURIComponent(subjectId || subjectSlug)}&topicSlug=${encodeURIComponent(topicSlug)}`;
    }

    ///study-v2/player

    // Hook listeners
    pdfOpenBtn.addEventListener("click", () => handlePdfOpen("open"));
    pdfViewBtn.addEventListener("click", () => handlePdfOpen("view"));
    pdfDownloadBtn.addEventListener("click", () => handlePdfOpen("download"));
    pdfCloseBtn.addEventListener("click", () => pdfSheetBackdrop.classList.remove("show"));

    notesListCloseBtn.addEventListener("click", () => notesListSheetBackdrop.classList.remove("show"));

    playAppleBtn.addEventListener("click", () => playVideo("apple"));
    playAndroidBtn.addEventListener("click", () => playVideo("android"));
    
    videoCloseBtn.addEventListener("click", () => videoSheetBackdrop.classList.remove("show"));

    window.addEventListener("click", (e) => {
      if (e.target === pdfSheetBackdrop) pdfSheetBackdrop.classList.remove("show");
      if (e.target === videoSheetBackdrop) videoSheetBackdrop.classList.remove("show");
      if (e.target === notesListSheetBackdrop) notesListSheetBackdrop.classList.remove("show");
    });

    window.openVideoSheet = openVideoSheet;
    window.openPdfSheet = openPdfSheet;
    window.openNotesList = openNotesList;

    // Boot
    setTab("lectures");
  
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
  
