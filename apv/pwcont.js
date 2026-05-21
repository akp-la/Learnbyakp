
    const API_BASE = "https://learnbyakp.onrender.com";
    const ENCRYPTION_KEY = "maggikhalo";

    let topics = [];
    let filteredTopics = [];
    let isLoading = true;
    let currentError = null;

    const $ = (id) => document.getElementById(id);
    const topicList = $("topicList");
    const statusArea = $("statusArea");
    const searchInput = $("searchInput");
    const clearSearch = $("clearSearch");

    const params = new URLSearchParams(window.location.search);
    const BatchId = params.get("BatchId") || params.get("batchid") || "";
    const Subjectslug = params.get("Subjectslug") || params.get("subjectslug") || "";
    const subjectName = params.get("subjectName") || params.get("name") || "Subject";
    const SubjectId = params.get("SubjectId") || params.get("subjectid") || "";

    document.addEventListener("DOMContentLoaded", init);

    function init(){
      setupHeader();
      setupEvents();
      loadTheme();
      fetchTopics();
    }

    function setupHeader(){
      $("pageTitle").textContent = subjectName;
      $("heroTitle").textContent = subjectName;
      $("pageSubTitle").textContent = "Topics & Contents";
      $("batchPill").textContent = `BatchId: ${BatchId || "missing"}`;
      $("subjectPill").textContent = `SubjectId: ${SubjectId || "missing"}`;
    }

    function setupEvents(){
      $("backBtn").addEventListener("click", () => {
        if(history.length > 1) history.back();
        else window.location.href = "/study-v2/batches";
      });

      $("searchToggle").addEventListener("click", () => {
        $("searchWrap").classList.toggle("hidden");
        if(!$("searchWrap").classList.contains("hidden")) searchInput.focus();
      });

      searchInput.addEventListener("input", () => {
        clearSearch.classList.toggle("hidden", !searchInput.value.trim());
        applySearchAndRender();
      });

      clearSearch.addEventListener("click", clearSearchValue);
      $("clearSearchToolbar").addEventListener("click", clearSearchValue);

      $("menuToggle").addEventListener("click", () => $("sideMenu").classList.add("open"));
      document.querySelectorAll("[data-close-menu]").forEach(el => el.addEventListener("click", () => $("sideMenu").classList.remove("open")));

      $("themeToggle").addEventListener("click", toggleTheme);
      $("reloadBtn").addEventListener("click", () => {
        $("sideMenu").classList.remove("open");
        fetchTopics();
      });
    }

    function clearSearchValue(){
      searchInput.value = "";
      clearSearch.classList.add("hidden");
      applySearchAndRender();
    }

    function loadTheme(){
      const saved = localStorage.getItem("akpTheme");
      if(saved === "dark") document.body.classList.add("dark");
      $("themeToggle").textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
    }

    function toggleTheme(){
      document.body.classList.toggle("dark");
      localStorage.setItem("akpTheme", document.body.classList.contains("dark") ? "dark" : "light");
      $("themeToggle").textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
    }

    async function fetchTopics(){
      if(!BatchId || !Subjectslug || !SubjectId){
        isLoading = false;
        currentError = "Required URL params missing. Need BatchId, Subjectslug, SubjectId and optional subjectName.";
        topics = [];
        render();
        return;
      }

      isLoading = true;
      currentError = null;
      render();

      try{
        const url = new URL(`${API_BASE}/api/pw/topics`);
        url.searchParams.append("BatchId", BatchId);
        // Original code sends Subjectslug value as SubjectId param.
        url.searchParams.append("SubjectId", Subjectslug);

        const response = await fetch(url.toString());
        if(!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const json = await response.json();
        if(!json.data) throw new Error("No data in response for topics");

        let decoded;
        if(Array.isArray(json.data)){
          decoded = {success:true,data:json.data};
        }else if(json.success && Array.isArray(json.data)){
          decoded = {success:true,data:json.data};
        }else if(typeof json.data === "string"){
          decoded = await decryptPayload(json.data);
        }else{
          throw new Error("Invalid topics response format.");
        }

        if(!decoded || !decoded.success || !Array.isArray(decoded.data)){
          throw new Error(decoded?.error || "error came fixing quickly");
        }

        const allContents = buildAllContents(decoded.data);
        topics = [allContents, ...decoded.data];
        isLoading = false;
        currentError = null;
        applySearchAndRender();
      }catch(error){
        console.error("Failed to fetch topics:", error);
        isLoading = false;
        currentError = error.message;
        topics = [];
        render();
      }
    }

    function buildAllContents(list){
      return {
        _id: "all-contents",
        name: "All Contents",
        videos: list.reduce((sum, item) => sum + Number(item.videos || 0), 0),
        lectureVideos: list.reduce((sum, item) => sum + Number(item.lectureVideos || 0), 0),
        exercises: list.reduce((sum, item) => sum + Number(item.exercises || 0), 0),
        notes: list.reduce((sum, item) => sum + Number(item.notes || 0), 0),
        slug: "all-contents"
      };
    }

    function applySearchAndRender(){
      const query = searchInput.value.trim().toLowerCase();
      filteredTopics = topics.filter(topic => {
        const text = `${topic.name || ""} ${topic.slug || ""}`.toLowerCase();
        return text.includes(query);
      });
      render();
    }

    function render(){
      if(isLoading){
        statusArea.innerHTML = "";
        $("countText").textContent = "Loading...";
        topicList.innerHTML = Array.from({length:5}).map(() => `
          <div class="skeleton-card">
            <div class="skeleton sk-title"></div>
            <div class="skeleton sk-row"></div>
          </div>
        `).join("");
        return;
      }

      if(currentError){
        topicList.innerHTML = "";
        $("countText").textContent = "Error";
        statusArea.innerHTML = `<div class="error"><h3>Error</h3><p>${escapeHtml(currentError)}</p></div>`;
        return;
      }

      if(!filteredTopics.length){
        topicList.innerHTML = "";
        $("countText").textContent = "0 topics found";
        statusArea.innerHTML = `<div class="empty"><h3>No topics found</h3><p>Try another search keyword.</p></div>`;
        return;
      }

      statusArea.innerHTML = "";
      $("countText").textContent = `${filteredTopics.length} topic${filteredTopics.length > 1 ? "s" : ""} found`;
      topicList.innerHTML = filteredTopics.map(topicTemplate).join("");
      bindTopicClicks();
    }

    function topicTemplate(topic){
      const isAll = topic._id === "all-contents";
      return `
        <button class="topic-card ${isAll ? "all-card" : ""}" data-topic='${escapeAttr(JSON.stringify(topic))}'>
          <span class="topic-strip"></span>
          <span class="topic-main">
            <span class="topic-title">${escapeHtml(topic.name || "Untitled Topic")}</span>
            <span class="stats">${topicStats(topic)}</span>
          </span>
          <span class="arrow">›</span>
        </button>
      `;
    }

    function topicStats(topic){
      if(topic._id === "all-contents"){
        return `<span>All Videos</span><span class="sep">|</span><span>All Exercises</span><span class="sep">|</span><span>All Notes</span>`;
      }

      const parts = [];
      const videoCount = Number(topic.videos || topic.lectureVideos || 0);
      const exerciseCount = Number(topic.exercises || 0);
      const notesCount = Number(topic.notes || 0);
      if(videoCount > 0) parts.push(`${videoCount} Videos`);
      if(exerciseCount > 0) parts.push(`${exerciseCount} Exercises`);
      if(notesCount > 0) parts.push(`${notesCount} Notes`);
      if(!parts.length) parts.push("Open contents");
      return parts.map((part, index) => `${index ? '<span class="sep">|</span>' : ''}<span>${escapeHtml(part)}</span>`).join("");
    }

    function bindTopicClicks(){
      document.querySelectorAll("[data-topic]").forEach(card => {
        card.addEventListener("click", () => openTopic(JSON.parse(card.dataset.topic)));
      });
    }

    function openTopic(topic){
      const url = `/study-v2/batches/type?BatchId=${encodeURIComponent(BatchId)}&Subjectslug=${encodeURIComponent(Subjectslug)}&topicslug=${encodeURIComponent(topic.slug || "")}&topicName=${encodeURIComponent(topic.name || "")}&topicId=${encodeURIComponent(topic._id || "")}&SubjectId=${encodeURIComponent(SubjectId)}`;
      window.location.href = url;
    }

    async function decryptPayload(payload){
      try{
        const [ivHex, encryptedHex] = payload.split(":");
        if(!ivHex || !encryptedHex) throw new Error("Invalid encrypted payload format.");
        const iv = hexToBytes(ivHex);
        const encrypted = hexToBytes(encryptedHex);
        const key = await importAesKey(ENCRYPTION_KEY);
        const decrypted = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, encrypted);
        const text = new TextDecoder().decode(decrypted);
        return JSON.parse(text);
      }catch(error){
        console.error("Client-side decryption failed:", error);
        return {success:false,error:"Decryption failed: " + error.message};
      }
    }

    async function importAesKey(keyText){
      const encoded = new TextEncoder().encode(keyText);
      const keyBytes = new Uint8Array(32);
      for(let i=0;i<32;i++) keyBytes[i] = i < encoded.length ? encoded[i] : 0;
      return crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM", length:256}, false, ["decrypt"]);
    }

    function hexToBytes(hex){
      const matches = hex.match(/.{1,2}/g);
      if(!matches) return new Uint8Array();
      return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
    }

    function toast(title, description, type="normal"){
      const box = $("toastBox");
      const item = document.createElement("div");
      item.className = `toast ${type === "danger" ? "danger" : ""}`;
      item.innerHTML = `<h4>${escapeHtml(title)}</h4><p>${escapeHtml(description)}</p>`;
      box.appendChild(item);
      setTimeout(() => item.remove(), 3200);
    }

    function escapeHtml(value){
      return String(value || "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[char]));
    }

    function escapeAttr(value){
      return escapeHtml(value).replace(/`/g, "&#96;");
    }
  

    
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