(function () {
  var API_BASE = "https://learnbyakp.onrender.com";
  var state = {
    masterUrl: "",
    urlPrefix: "",
    key: "",
    qualities: [],
    selectedQuality: null,
    segments: [],
    estimatedBytes: 0,
    downloadedBytes: 0,
    running: false,
    paused: false,
    stopped: false
  };

  var els = {
    masterUrl: document.getElementById("masterUrl"),
    urlPrefix: document.getElementById("urlPrefix"),
    keyInput: document.getElementById("keyInput"),
    fetchPlaylist: document.getElementById("fetchPlaylist"),
    loadSegments: document.getElementById("loadSegments"),
    downloadMp4: document.getElementById("downloadMp4"),
    runningActions: document.getElementById("runningActions"),
    pauseDownload: document.getElementById("pauseDownload"),
    stopDownload: document.getElementById("stopDownload"),
    progressBar: document.getElementById("progressBar"),
    statusText: document.getElementById("statusText"),
    qualityCount: document.getElementById("qualityCount"),
    segmentCount: document.getElementById("segmentCount"),
    estimatedSize: document.getElementById("estimatedSize"),
    downloadedSize: document.getElementById("downloadedSize"),
    qualitySection: document.getElementById("qualitySection"),
    qualityList: document.getElementById("qualityList"),
    logList: document.getElementById("logList")
  };

  function log(message, type) {
    var line = document.createElement("div");
    var time = new Date().toLocaleTimeString();
    line.className = "log-line " + (type || "info");
    line.innerHTML = "<span></span><span></span>";
    line.children[0].textContent = "[" + time + "]";
    line.children[1].textContent = message;
    els.logList.appendChild(line);
    els.logList.parentElement.scrollTop = els.logList.parentElement.scrollHeight;
  }

  function mb(bytes) {
    return (bytes / 1048576).toFixed(2) + " MB";
  }

  function setProgress(value, text) {
    var percent = Math.max(0, Math.min(100, value || 0));
    els.progressBar.style.width = percent + "%";
    els.statusText.textContent = text || "Ready";
  }

  function updateStats() {
    els.qualityCount.textContent = state.qualities.length;
    els.segmentCount.textContent = state.segments.length;
    els.estimatedSize.textContent = state.estimatedBytes ? mb(state.estimatedBytes) : "N/A";
    els.downloadedSize.textContent = mb(state.downloadedBytes);
  }

  function showAction(action) {
    els.fetchPlaylist.hidden = action !== "fetch";
    els.loadSegments.hidden = action !== "segments";
    els.downloadMp4.hidden = action !== "download";
    els.runningActions.hidden = action !== "running";
  }

  function buildUrl(path, base) {
    try {
      var url = new URL(path, base);
      url.search = state.urlPrefix;
      return url.href;
    } catch (error) {
      log('Error building URL for path "' + path + '": ' + error.message, "error");
      return "";
    }
  }

  function hexToBuffer(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes.buffer;
  }

  async function decryptSegment(buffer, keyHex) {
    var key = await crypto.subtle.importKey("raw", hexToBuffer(keyHex), { name: "AES-CBC" }, false, ["decrypt"]);
    var iv = new Uint8Array(16);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: iv }, key, buffer));
  }

  function validateInputs() {
    state.masterUrl = els.masterUrl.value.trim();
    state.urlPrefix = els.urlPrefix.value.trim();
    state.key = els.keyInput.value.trim();
    if (!state.masterUrl) {
      log("Please enter a master URL", "error");
      return false;
    }
    if (!/^[a-fA-F0-9]{32}$/.test(state.key)) {
      log("Please enter a valid 32-character hex key", "error");
      return false;
    }
    return true;
  }

  function renderQualities() {
    els.qualityList.innerHTML = "";
    state.qualities.forEach(function (quality, index) {
      var item = document.createElement("button");
      item.type = "button";
      item.className = "quality-item" + (quality.selected ? " active" : "");
      item.innerHTML = "<span></span><strong></strong>";
      item.children[0].textContent = quality.name;
      item.children[1].textContent = quality.selected ? "Selected" : "";
      item.addEventListener("click", function () {
        selectQuality(index);
      });
      els.qualityList.appendChild(item);
    });
    els.qualitySection.hidden = state.qualities.length === 0;
  }

  function selectQuality(index) {
    state.qualities = state.qualities.map(function (quality, qualityIndex) {
      quality.selected = qualityIndex === index;
      return quality;
    });
    state.selectedQuality = state.qualities[index];
    state.segments = [];
    state.estimatedBytes = 0;
    state.downloadedBytes = 0;
    renderQualities();
    updateStats();
    log("Selected quality: " + state.selectedQuality.name, "info");
    showAction("segments");
  }

  async function autoFillFromQuery() {
    var params = new URLSearchParams(window.location.search);
    var encodedUrl = params.get("url");
    if (!encodedUrl) return;
    var decoded = decodeURIComponent(encodedUrl);
    var parts = decoded.split("?");
    els.masterUrl.value = parts[0];
    els.urlPrefix.value = parts[1] ? "?" + parts.slice(1).join("?") : "";
    var mpdUrl = parts[0].replace(/\.m3u8/i, ".mpd") + els.urlPrefix.value;
    try {
      var kidResponse = await fetch(API_BASE + "/api/pw/kid?mpdUrl=" + encodeURIComponent(mpdUrl));
      var kidData = await kidResponse.json();
      if (!kidResponse.ok || !kidData.success || !kidData.kid) return;
      var otpResponse = await fetch(API_BASE + "/api/pw/otp?kid=" + encodeURIComponent(kidData.kid));
      var otpData = await otpResponse.json();
      if (otpResponse.ok && otpData.success && otpData.key) {
        els.keyInput.value = otpData.key;
        log("Key fetched automatically from URL", "success");
      }
    } catch (error) {
      log("Could not automatically fetch key: " + error.message, "warning");
    }
  }

  async function fetchPlaylist() {
    if (!validateInputs()) return;
    log("Starting HLS download process...", "info");
    setProgress(10, "Validating inputs...");
    try {
      var url = state.masterUrl + state.urlPrefix;
      log("Fetching master playlist...", "info");
      setProgress(20, "Fetching playlist...");
      var response = await fetch(url);
      if (!response.ok) throw new Error("HTTP " + response.status);
      var text = await response.text();
      log("Master playlist fetched", "success");
      setProgress(40, "Parsing qualities...");
      var lines = text.split("\n");
      var qualities = [];
      for (var i = 0; i < lines.length; i += 1) {
        if (lines[i].startsWith("#EXT-X-STREAM-INF:")) {
          var resolution = (lines[i].match(/RESOLUTION=(\d+x\d+)/) || [])[1] || "";
          var name = resolution ? resolution.split("x")[1] + "p" : "Unknown";
          var path = (lines[i + 1] || "").trim();
          if (path) {
            qualities.push({ name: name, resolution: resolution, path: path, url: buildUrl(path, url), selected: false });
          }
        }
      }
      if (!qualities.length) throw new Error("No qualities found");
      state.qualities = qualities;
      log("Found " + qualities.length + " quality levels", "success");
      selectQuality(0);
      setProgress(80, "Ready to select quality");
    } catch (error) {
      log("Error fetching master playlist: " + error.message, "error");
      setProgress(0, "Failed");
    }
  }

  async function loadSegments() {
    if (!state.selectedQuality) {
      log("No quality selected", "error");
      return;
    }
    log("Loading segments from " + state.selectedQuality.name + "...", "info");
    setProgress(10, "Fetching quality playlist...");
    try {
      var response = await fetch(state.selectedQuality.url);
      if (!response.ok) throw new Error("HTTP " + response.status);
      var text = await response.text();
      log("Quality playlist loaded", "success");
      setProgress(30, "Parsing segments...");
      var count = 0;
      state.segments = text.split("\n").filter(function (line) {
        line = line.trim();
        return line && !line.startsWith("#") && line.endsWith(".ts");
      }).map(function (line) {
        count += 1;
        return {
          index: count,
          name: "segment_" + String(count).padStart(3, "0") + ".ts",
          url: buildUrl(line.trim(), state.selectedQuality.url)
        };
      });
      if (!state.segments.length) throw new Error("No segments found");
      var first = await fetch(state.segments[0].url);
      var firstSize = (await first.arrayBuffer()).byteLength;
      state.estimatedBytes = firstSize * state.segments.length;
      updateStats();
      log("Found " + state.segments.length + " segments", "success");
      log("Estimated total size: " + mb(state.estimatedBytes), "info");
      setProgress(100, "Ready to download " + state.segments.length + " segments");
      showAction("download");
    } catch (error) {
      log("Error loading segments: " + error.message, "error");
      setProgress(0, "Failed");
    }
  }

  async function downloadMp4() {
    if (!state.segments.length || !state.key) {
      log("No segments or key available", "error");
      return;
    }
    state.running = true;
    state.paused = false;
    state.stopped = false;
    state.downloadedBytes = 0;
    showAction("running");
    updateStats();

    var parts = new Array(state.segments.length);
    var downloaded = 0;
    try {
      for (var i = 0; i < state.segments.length; i += 1) {
        while (state.paused && !state.stopped) {
          await new Promise(function (resolve) { setTimeout(resolve, 350); });
        }
        if (state.stopped) return;
        var segment = state.segments[i];
        var response = await fetch(segment.url);
        if (!response.ok) throw new Error("HTTP " + response.status);
        var encrypted = await response.arrayBuffer();
        var decrypted = await decryptSegment(encrypted, state.key);
        parts[i] = decrypted;
        state.downloadedBytes += decrypted.length;
        downloaded += 1;
        updateStats();
        setProgress(downloaded / state.segments.length * 100, "Downloaded " + downloaded + "/" + state.segments.length);
      }
      var total = parts.reduce(function (sum, part) { return sum + part.length; }, 0);
      var merged = new Uint8Array(total);
      var offset = 0;
      parts.forEach(function (part) {
        merged.set(part, offset);
        offset += part.length;
      });
      log("Combined all segments. Total size: " + mb(total), "success");
      var blob = new Blob([merged], { type: "video/mp4" });
      var link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "pw.theeduverse.xyz.mp4";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      setProgress(100, "Download Complete!");
    } catch (error) {
      log("Failed to process download: " + error.message, "error");
      setProgress(0, "Failed");
    } finally {
      state.running = false;
      state.paused = false;
      showAction("download");
      els.pauseDownload.textContent = "Pause";
    }
  }

  els.fetchPlaylist.addEventListener("click", fetchPlaylist);
  els.loadSegments.addEventListener("click", loadSegments);
  els.downloadMp4.addEventListener("click", downloadMp4);
  els.pauseDownload.addEventListener("click", function () {
    state.paused = !state.paused;
    els.pauseDownload.textContent = state.paused ? "Resume" : "Pause";
    log(state.paused ? "Download paused." : "Download resumed.", "warning");
  });
  els.stopDownload.addEventListener("click", function () {
    state.stopped = true;
    state.running = false;
    state.paused = false;
    log("Download stopped by user.", "warning");
    setProgress(0, "Download stopped");
    showAction("download");
  });

  log("Ready", "info");
  autoFillFromQuery();
})();


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
