
      document.addEventListener("keydown", function (e) {
  if (
    e.key === "F12" ||
    (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(e.key)) ||
    (e.ctrlKey && e.key === "U")
  ) {
    e.preventDefault();
    debugger; // pause
  }
});  
    
    const API_BASE = "https://learnbyakp.onrender.com";
    const DEFAULT_THUMB = "https://i.ibb.co/9Hm0NqsH/f69ed82b-7169-45fc-a82b-915e453c6340.png";
    const DEFAULT_SUBJECT_ICON = "https://static.pw.live/react-batches/assets/svg/subjects/defaultSubject.svg";

    const params = new URLSearchParams(window.location.search);
    const batchNameFromUrl = params.get("name") || "Batch";
    const batchId = params.get("batchid") || params.get("BatchId") || params.get("batchId");

    let batchDetails = null;
    let liveClasses = [];

    const pageTitle = document.getElementById("pageTitle");
    const heroTitle = document.getElementById("heroTitle");
    const liveArea = document.getElementById("liveArea");
    const subjectArea = document.getElementById("subjectArea");
    const aboutContent = document.getElementById("aboutContent");
    const liveSearch = document.getElementById("liveSearch");
    const subjectSearch = document.getElementById("subjectSearch");
    const toast = document.getElementById("toast");

    pageTitle.textContent = batchNameFromUrl;
    heroTitle.textContent = batchNameFromUrl;

    function showToast(message) {
      toast.textContent = message;
      toast.classList.add("show");
      setTimeout(() => toast.classList.remove("show"), 2300);
    }

    function startLoading() {
      document.body.style.cursor = "progress";
    }

    function stopLoading() {
      document.body.style.cursor = "";
    }

    async function makeKey(secret) {
      const encodedSecret = new TextEncoder().encode(secret);
      const keyBytes = new Uint8Array(32);

      for (let i = 0; i < 32; i++) {
        keyBytes[i] = i < encodedSecret.length ? encodedSecret[i] : 0;
      }

      return crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
    }

    function hexToBytes(hex) {
      if (!hex || hex.length % 2 !== 0) {
        throw new Error("Invalid hex string.");
      }

      const matches = hex.match(/.{1,2}/g);
      if (!matches) {
        throw new Error("Invalid hex payload.");
      }

      return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
    }

    async function decryptPayload(payload) {
      try {
        const [ivHex, dataHex] = String(payload).split(":");

        if (!ivHex || !dataHex) {
          throw new Error("Invalid encrypted payload format.");
        }

        const iv = hexToBytes(ivHex);
        const encryptedData = hexToBytes(dataHex);
        const secretKey = "maggikhalo";
        const key = await makeKey(secretKey);

        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          encryptedData
        );

        const text = new TextDecoder().decode(decrypted);
        return JSON.parse(text);
      } catch (error) {
        console.error("Client-side decryption failed:", error);
        return {
          success: false,
          error: "Decryption failed: " + error.message
        };
      }
    }

    async function fetchJson(url, options) {
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error("HTTP error! status: " + response.status);
      }

      return response.json();
    }

    async function loadLiveClasses() {
      liveArea.innerHTML = `
        <div class="skeleton sk-live"></div>
        <div class="skeleton sk-live"></div>
      `;

      try {
        const result = await fetchJson(`${API_BASE}/api/pw/live`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ batchId })
        });

        if (result.data && Array.isArray(result.data)) {
          liveClasses = result.data;
        } else {
          liveClasses = [];
          console.warn("API call for live classes failed or data is not an array:", result.message);
        }

        renderLiveClasses();
      } catch (error) {
        console.error("Failed to fetch schedule:", error);
        liveClasses = [];
        liveArea.innerHTML = `<div class="empty-card" style="width:100%;">Failed to load live classes.</div>`;
      }
    }

    async function loadBatchDetails() {
      subjectArea.innerHTML = `
        <div class="skeleton sk-subject"></div>
        <div class="skeleton sk-subject"></div>
        <div class="skeleton sk-subject"></div>
        <div class="skeleton sk-subject"></div>
      `;

      aboutContent.innerHTML = `<div class="skeleton" style="height: 170px;"></div>`;

      try {
        const encryptedResult = await fetchJson(`${API_BASE}/api/pw/batchdetails`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            searchParams: {
              BatchId: batchId
            }
          })
        });

        if (!encryptedResult.data) {
          throw new Error("No encrypted data in response.");
        }

        const decryptedResult = await decryptPayload(encryptedResult.data);

        if (!decryptedResult.success) {
          throw new Error(decryptedResult.error || "Failed to decrypt batch details");
        }

        batchDetails = decryptedResult.data;

        const finalTitle = batchDetails.name || batchNameFromUrl;
        pageTitle.textContent = finalTitle;
        heroTitle.textContent = finalTitle;
        document.title = `${finalTitle} - LearnByAKP`;

        renderSubjects();
        renderAbout();
      } catch (error) {
        console.error("Error fetching batch details:", error);
        subjectArea.innerHTML = `<div class="empty-card">Failed to load subjects.</div>`;
        aboutContent.innerHTML = `<p style="color:#dc2626;font-weight:800;">${escapeHtml(error.message)}</p>`;
      }
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function safeText(value, fallback = "N/A") {
      const text = value === null || value === undefined ? "" : String(value);
      return text.trim() || fallback;
    }

    function getTime(dateString) {
      if (!dateString) return "N/A";

      const date = new Date(dateString);
      if (Number.isNaN(date.getTime())) return "N/A";

      return date.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true
      });
    }

    function getClassBadge(item) {
      const topic = (item.topic || "").toLowerCase();
      const tag = (item.tag || "").toLowerCase();

      if (topic.includes("cancelled") || topic.includes("canceled")) {
        return `<span class="badge cancelled">Cancelled</span>`;
      }

      if (tag === "ended" || topic.includes("recorded")) {
        return `<span class="badge recorded">Recorded</span>`;
      }

      if (tag === "live") {
        return `<span class="badge live">LIVE</span>`;
      }

      return `<span class="badge upcoming">${escapeHtml(item.tag || "Upcoming")}</span>`;
    }

    function isDisabledClass(item) {
      const topic = (item.topic || "").toLowerCase();
      const tag = (item.tag || "").toLowerCase();

      return tag === "upcoming" ||
        topic.includes("cancelled") ||
        topic.includes("canceled");
    }

    function openClass(item) {
  const topic = (item.topic || "").toLowerCase();

  // Cancelled class check
  if (topic.includes("cancelled") || topic.includes("canceled")) {
    showToast("This class is cancelled.");
    return;
  }

  startLoading();

  const videoId = item.videoDetails?.findKey || item._id;
  const subjectSlug = item.subjectId?.slug || "";
  const subjectId = item.subjectId?._id || "";
  const scheduleId = item._id || "";
  const targetBatchId = item.batchId || batchId || "";
  
  // Fix: batchNameFromUrl को सुरक्षित तरीके से हैंडल करें
  const title = typeof batchNameFromUrl !== 'undefined' ? batchNameFromUrl : (item.batchName || "Class");
    const time = item.startTime 
  ? Math.floor(new Date(item.startTime).getTime() / 1000) 
  : "";

           const query2 =
    `&batchId=${encodeURIComponent(targetBatchId)}` +
    `&scheduleId=${encodeURIComponent(scheduleId)}` +
    `&subjectId=${encodeURIComponent(subjectId)}` +
  // Fix: escapeHtml को साबिस्टेंड में इकॉनसिस्टेंसी ठीक करें
  const query =
    `video_id=${encodeURIComponent(videoId)}` +
    `&subject_slug=${encodeURIComponent(subjectSlug)}` +
    `&batch_id=${encodeURIComponent(targetBatchId)}` +
    `&schedule_id=${encodeURIComponent(scheduleId)}` +
    `&subject_id=${encodeURIComponent(subjectId)}` +
    `&title=${encodeURIComponent(title)}` +
    `&time=${encodeURIComponent(time)}`;

  // Fix: recorded और live के लिए अलग URL होना चाहिए (अगर वाक़ई अलग हैं)
  if (topic.includes("recorded")) {
    window.location.href = `https://stream.testuk.org/schedule-details?${query2}`;
  } else {
    // Live class - same URL अगर तुमके कोड में एक ही है, तो condition हटा सकते हो
    window.location.href = `https://stream.testuk.org/schedule-details??${query2}`;
  }
}

function renderLiveClasses() {
  const query = liveSearch.value.trim().toLowerCase();

  const filtered = liveClasses.filter(item => {
    const searchable = [
      item.topic,
      item.tag,
      item.subjectId?.name,
      item.teachers?.[0]?.name,
      item.batchId,
      item._id
    ].join(" ").toLowerCase();

    return searchable.includes(query);
  });

  if (!filtered.length) {
    liveArea.innerHTML = `<div class="empty-card" style="width:100%;">No live classes scheduled for today.</div>`;
    return;
  }

  liveArea.innerHTML = filtered.map((item, index) => {
    const topic = safeText(item.topic, "Untitled Class");
    const subject = safeText(item.subjectId?.name, "Subject");
    const teacher = safeText(item.teachers?.[0]?.name, "N/A");
    const image = item.videoDetails?.image || DEFAULT_THUMB;
    const disabled = isDisabledClass(item);
    const formattedTime = getTime(item.startTime);

    return `
      <article class="live-card">
        <div class="thumb">
          <img src="${escapeHtml(image)}" alt="${escapeHtml(topic)}" loading="lazy" onerror="this.src='${DEFAULT_THUMB}'" />
          ${getClassBadge(item)}
        </div>

        <div class="live-body">
          <p class="subject-name">${escapeHtml(subject)}</p>
          <h3 class="live-title">${escapeHtml(topic)}</h3>

          <div class="meta-row">
            <span title="${escapeHtml(teacher)}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-8 0v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
              </svg>
              ${escapeHtml(teacher)}
            </span>
            <span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <path d="M12 6v6l4 2"></path>
              </svg>
              ${escapeHtml(formattedTime)}
            </span>
          </div>

          <button class="btn btn-primary play-btn" data-live-index="${index}" ${disabled ? "disabled" : ""}>
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <path d="m10 8 6 4-6 4V8z"></path>
            </svg>
            Play
          </button>
        </div>
      </article>
    `;
  }).join("");

  // Fix: Button event listeners सही से attach करें
  [...liveArea.querySelectorAll("[data-live-index]")].forEach(button => {
    button.addEventListener("click", () => {
      const selectedItem = filtered[Number(button.dataset.liveIndex)];
      if (selectedItem) {
        openClass(selectedItem);
      }
    });
  });
}

    function openSubject(subject) {
      if (!batchId) {
        showToast("Batch ID missing in URL.");
        return;
      }

      startLoading();

      const subjectSlug = subject.slug || "";
      const subjectName = subject.subject || "";
      const subjectId = subject.subjectId || subject._id || "";

      window.location.href =
        `/study-v2/batches/content?BatchId=${encodeURIComponent(batchId)}` +
        `&Subjectslug=${encodeURIComponent(subjectSlug)}` +
        `&subjectName=${encodeURIComponent(subjectName)}` +
        `&SubjectId=${encodeURIComponent(subjectId)}`;
    }

    function renderSubjects() {
      const subjects = Array.isArray(batchDetails?.subjects) ? batchDetails.subjects : [];
      const query = subjectSearch.value.trim().toLowerCase();

      const filtered = subjects.filter(subject => {
        const searchable = [
          subject.subject,
          subject.slug,
          subject.subjectId,
          subject._id
        ].join(" ").toLowerCase();

        return searchable.includes(query);
      });

      if (!filtered.length) {
        subjectArea.innerHTML = `<div class="empty-card">No subjects found.</div>`;
        return;
      }

      subjectArea.innerHTML = filtered.map((subject, index) => {
        const name = safeText(subject.subject, "Subject");
        const icon = subject.icon || DEFAULT_SUBJECT_ICON;

        return `
          <button class="subject-card" data-subject-index="${index}">
            <img src="${escapeHtml(icon)}" alt="${escapeHtml(name)}" loading="lazy" onerror="this.src='${DEFAULT_SUBJECT_ICON}'" />
            <h3>${escapeHtml(name)}</h3>
          </button>
        `;
      }).join("");

      [...subjectArea.querySelectorAll("[data-subject-index]")].forEach(button => {
        button.addEventListener("click", () => {
          const selectedSubject = filtered[Number(button.dataset.subjectIndex)];
          if (selectedSubject) openSubject(selectedSubject);
        });
      });
    }

    function renderAbout() {
      const description = batchDetails?.description;

      if (!description) {
        aboutContent.innerHTML = `<p>No batch description available.</p>`;
        return;
      }

      aboutContent.innerHTML = description;
    }

    async function initPage() {
      if (!batchId) {
        liveArea.innerHTML = `<div class="empty-card" style="width:100%;">Batch ID missing. Add <b>?batchid=YOUR_BATCH_ID</b> in URL.</div>`;
        subjectArea.innerHTML = `<div class="empty-card">Batch ID missing.</div>`;
        aboutContent.innerHTML = `<p style="color:#dc2626;font-weight:800;">Batch ID missing in URL.</p>`;
        return;
      }

      startLoading();

      try {
        await Promise.all([
          loadLiveClasses(),
          loadBatchDetails()
        ]);
      } finally {
        stopLoading();
      }
    }

    document.getElementById("backBtn").addEventListener("click", () => {
      if (history.length > 1) history.back();
      else window.location.href = "/";
    });

    document.getElementById("refreshBtn").addEventListener("click", () => {
      initPage();
      showToast("Refreshing data...");
    });

    document.getElementById("shareBtn").addEventListener("click", () => {
      const message = `Check out this course from 𝘓𝙚𝙖𝙧𝙣𝙗𝙮𝙖𝙠𝙥-𝙥𝙬-${window.location.href}`;
      const shareUrl = `https://api.whatsapp.com/send?text=${encodeURIComponent(message)}`;
      window.open(shareUrl, "_blank");
    });

    document.getElementById("announcementBtn").addEventListener("click", () => {
      if (!batchId) {
        showToast("Batch ID missing in URL.");
        return;
      }

      startLoading();
      window.location.href = `/study-v2/batches/${encodeURIComponent(batchId)}/announcements`;
    });

    liveSearch.addEventListener("input", renderLiveClasses);
    subjectSearch.addEventListener("input", renderSubjects);

    const drawer = document.getElementById("drawer");
    const drawerBackdrop = document.getElementById("drawerBackdrop");

    function openMenu() {
      drawer.classList.add("open");
      drawerBackdrop.classList.add("open");
    }

    function closeMenu() {
      drawer.classList.remove("open");
      drawerBackdrop.classList.remove("open");
    }

    document.getElementById("menuBtn").addEventListener("click", openMenu);
    document.getElementById("closeMenuBtn").addEventListener("click", closeMenu);
    drawerBackdrop.addEventListener("click", closeMenu);

    document.getElementById("subjectsLink").addEventListener("click", event => {
      event.preventDefault();
      closeMenu();
      document.querySelector("#subjectArea").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    document.getElementById("liveLink").addEventListener("click", event => {
      event.preventDefault();
      closeMenu();
      document.querySelector("#liveArea").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    document.getElementById("aboutLink").addEventListener("click", event => {
      event.preventDefault();
      closeMenu();
      document.querySelector("#aboutSection").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    initPage();

    
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
  
