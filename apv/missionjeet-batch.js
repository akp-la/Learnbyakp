    const FALLBACK_LOGO = 'https://decicqog4ulhy.cloudfront.net/0/admin_v2/uploads/courses/thumbnail/7524245_1_WhatsApp%20Image%202026-03-02%20at%204.19.45%20PM.jpeg';
    const NOTES_DPP_THUMB = 'https://dulae92u7241v.cloudfront.net/1772100600/admin_v2/content/thumbnail/4491425_131_App%20Thumbnails%20All%20Teachers%20%281%29.png';

    const API = {
      details: 'https://course.nexttoppers.com/course/course-details',
      allContent: 'https://course.nexttoppers.com/course/all-content',
      contentDetails: 'https://course.nexttoppers.com/course/content-details'
    };

    const DEFAULT_HEADERS = window.APP_CREDENTIALS.getHeaders('missionjeetBatch', {
      accept: 'application/json, text/plain, */*',
      'content-type': 'application/json',
      origin: 'https://missionjeet.in',
      platform: '3',
      referer: 'https://missionjeet.in/',
      'user-agent': navigator.userAgent,
      version: '1'
    });

    const state = {
      courseId: new URLSearchParams(location.search).get('courseId') || '',
      course: null,
      sections: [],
      activeTab: '',
      loading: true,
      error: '',
      enrolled: false,
      contentLoading: false,
      contentInitialized: false,
      currentFolderId: null,
      folderTrail: [{ id: null, title: 'Content' }],
      contentList: [],
      search: ''
    };

    function goHome() {
      location.href = '/missionjeet';
    }

    function safeImage(src) {
      if (!src || !String(src).trim() || String(src).includes('admin.nexttoppers.com')) return FALLBACK_LOGO;
      return src;
    }

    function hasUsableImage(src) {
      return !!src && !!String(src).trim() && !String(src).includes('admin.nexttoppers.com');
    }

    function escapeHtml(str = '') {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function escapeAttr(str = '') {
      return escapeHtml(str);
    }

    function formatPrice(value) {
      const num = Number(value || 0);
      return '₹' + num.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    function formatDuration(seconds) {
      const sec = Number(seconds || 0);
      if (!sec) return '';
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = sec % 60;
      if (h > 0) return `${h}h ${m}m`;
      if (m > 0) return `${m}m ${s ? s + 's' : ''}`.trim();
      return `${s}s`;
    }

    function formatDate(ts) {
      if (!ts) return '';
      return new Date(Number(ts) * 1000).toLocaleDateString('en-IN', {
        day: 'numeric', month: 'short', year: 'numeric'
      });
    }

    function formatDateTime(ts) {
      if (!ts) return 'Not scheduled';
      const date = new Date(Number(ts) * 1000);
      if (Number.isNaN(date.getTime())) return 'Not scheduled';
      const day = date.toLocaleDateString('en-IN', {
        day: 'numeric', month: 'short', year: 'numeric'
      });
      const time = date.toLocaleTimeString('en-IN', {
        hour: 'numeric', minute: '2-digit', hour12: true
      });
      return `${day}, ${time}`;
    }

    function getContentKind(item) {
      const url = item?.data?.file_url || item?.data?.url || '';
      if (/\.(mpd|m3u8|mp4)(\?|$)/i.test(url)) return 'video';
      if (/\.pdf(\?|$)/i.test(url)) return 'pdf';
      const type = item?.data?.content_type || item?.data?.type || '';
      if (/video/i.test(type)) return 'video';
      if (/pdf/i.test(type)) return 'pdf';
      return 'other';
    }

    function isNotesOrDppItem(item) {
      if (isVideoItem(item)) return false;
      const text = [
        item?.type,
        item?.title,
        item?.data?.title,
        item?.data?.content_type,
        item?.data?.type,
        item?.data?.file_type_name
      ].filter(Boolean).join(' ').toLowerCase();
      return getContentKind(item) === 'pdf' || Number(item?.data?.file_type) === 1 || /\b(notes?|dpp|pdf)\b/i.test(text);
    }

    function isVideoItem(item) {
      return getContentKind(item) === 'video' || Number(item?.data?.file_type) === 2 || Number(item?.data?.video_type) > 0;
    }

    function contentThumb(item) {
      if (isNotesOrDppItem(item) && !hasUsableImage(item?.data?.thumbnail)) return NOTES_DPP_THUMB;
      return safeImage(item?.data?.thumbnail);
    }

    function normalizeCounts(counts) {
      if (!counts) return null;
      const copy = JSON.parse(JSON.stringify(counts));
      Object.keys(copy).forEach(key => {
        const v = copy[key];
        if (v && typeof v === 'object' && 'free' in v && 'paid' in v) {
          copy[key] = { total: Number(v.free || 0) + Number(v.paid || 0) };
        }
      });
      return copy;
    }

    function countsText(counts) {
      if (!counts) return '';
      const parts = [];
      if (counts.pdf?.total) parts.push(`PDFs: ${counts.pdf.total}`);
      if (counts.video?.total) parts.push(`Videos: ${counts.video.total}`);
      if (counts.test?.total !== undefined) parts.push(`Tests: ${counts.test.total}`);
      return parts.join(', ');
    }

    async function apiFetch(url, options = {}) {
      const headers = { ...DEFAULT_HEADERS, ...(options.headers || {}) };
      const res = await fetch(url, { ...options, headers });
      if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
      return res.json();
    }

    function enrollCourse() {
      state.enrolled = true;
      if (state.courseId) localStorage.setItem(`enrolled_${state.courseId}`, 'true');
      render();
    }

    async function loadCourse() {
      if (!state.courseId) {
        state.loading = false;
        state.error = 'courseId missing in URL. Example: ?courseId=151';
        render();
        return;
      }

      state.enrolled = localStorage.getItem(`enrolled_${state.courseId}`) === 'true';
      state.loading = true;
      state.error = '';
      render();

      try {
        const json = await apiFetch(API.details, {
          method: 'POST',
          body: JSON.stringify({ course_id: state.courseId, parent_id: '0' })
        });

        if (!json.success || !json.data) throw new Error(json.message || 'Unexpected response');

        const sections = [...json.data.filter(x => x.type !== 'free_content'), { title: 'Live', type: 'live', data: null }];
        state.sections = sections;
        state.activeTab = sections[0]?.type || '';

        const overview = json.data.find(x => x.type === 'overview');
        if (overview) {
          const details = overview.data?.find(x => x.layout_type === 'details');
          state.course = details?.layout_data?.[0] || null;
        }
      } catch (err) {
        state.error = err.message || 'Failed to load course';
      } finally {
        state.loading = false;
        render();
        if (state.activeTab === 'content') loadContent(null);
      }
    }

    async function loadContent(folderId = null) {
      state.contentLoading = true;
      state.contentInitialized = true;
      state.currentFolderId = folderId;
      render();

      try {
        const json = await apiFetch(API.allContent, {
          method: 'POST',
          body: JSON.stringify({
            course_id: state.courseId,
            folder_id: folderId || '0',
            is_free: '',
            keyword: '',
            limit: '1000',
            page: '1',
            parent_course_id: '0'
          })
        });

        const items = Array.isArray(json.data) ? json.data : [];
        items.forEach(item => {
          if (item.data?.content_counts) item.data.content_counts = normalizeCounts(item.data.content_counts);
        });
        state.contentList = items;
      } catch (err) {
        console.error('Content fetch error:', err);
        state.contentList = [];
      } finally {
        state.contentLoading = false;
        render();
      }
    }

    function openFolder(item) {
      state.folderTrail.push({ id: String(item.entity_id), title: item.title });
      loadContent(String(item.entity_id));
    }

    function goTrail(index) {
      state.folderTrail = state.folderTrail.slice(0, index + 1);
      const target = state.folderTrail[state.folderTrail.length - 1];
      loadContent(target.id);
    }

    async function openContent(item) {
      try {
        const url = new URL(API.contentDetails);
        url.searchParams.set('content_id', String(item.entity_id));
        url.searchParams.set('course_id', String(item.course_id));

        const json = await apiFetch(url.toString(), { method: 'GET' });
        if (!json.success || !json.data) return;

        const { file_url, vdc_id, file_type, video_type, video_id } = json.data;

        if (file_url && file_url.trim()) {
          const clean = file_url.trim();
          const title = item?.title ? encodeURIComponent(item.title) : '';

          if (Number(file_type) === 2 && Number(video_type) === 1) {
            window.open(`https://www.youtube.com/watch?v=${clean}`, '_blank');
          } else if (/\.(mpd|m3u8|mp4)(\?|$)/i.test(clean)) {
            location.href = `/videoplayer?file_url=${encodeURIComponent(clean)}&title=${title}`;
          } else {
            window.open(clean, '_blank');
          }
        } else {
          const finalVideoId = video_id || vdc_id || json?.data?.id || '';

          if (String(finalVideoId).trim()) {
            try {
              const drmRes = await fetch(
                `https://learnbyakp.onrender.com/api/nexttoppers/drm?videoid=${encodeURIComponent(String(finalVideoId).trim())}`
              );
              const drmJson = await drmRes.json();

              const drmFileUrl = drmJson?.data?.link?.file_url || drmJson?.file_url || '';

              if (drmFileUrl && String(drmFileUrl).trim()) {
                location.href =
                  `/videoplayer?file_url=${encodeURIComponent(String(drmFileUrl).trim())}` +
                  `&title=${encodeURIComponent(item?.title || '')}`;
              } else {
                console.warn('No DRM file_url found for video:', finalVideoId, drmJson);
              }
            } catch (err) {
              console.error('Failed to fetch DRM video details:', err);
            }
          } else {
            console.warn('No file_url, video_id or vdc_id found for content:', item.entity_id);
          }
        }
      } catch (err) {
        console.error('Content details fetch failed:', err);
      }
    }

    function setTab(type) {
      state.activeTab = type;
      render();
      if (type === 'content' && !state.contentInitialized) loadContent(null);
    }

    function setSearch(value) {
      state.search = value.toLowerCase().trim();
      render();
    }

    function filterItems(items) {
      if (!state.search) return items;
      return items.filter(item => {
        const title = String(item.title || '').toLowerCase();
        const type = String(item.type || '').toLowerCase();
        const counts = countsText(item.data?.content_counts || {}).toLowerCase();
        const kind = getContentKind(item).toLowerCase();
        return title.includes(state.search) || type.includes(state.search) || counts.includes(state.search) || kind.includes(state.search);
      });
    }

    function renderMain() {
      const wrap = document.getElementById('mainState');

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
        <h2 class="course-title">${escapeHtml(state.course.title || 'Untitled Course')}</h2>

        <div class="course-meta">
          <button class="btn btn-primary" onclick="enrollCourse()">${state.enrolled ? '✓ Enrolled' : 'Enroll Now'}</button>
          <div class="price-box">
            <strong>Free</strong>
            <del>${formatPrice(state.course.mrp)}</del>
            <p>Inclusive of GST</p>
          </div>
        </div>

        <div class="tabs">
          ${state.sections.map(sec => `
            <button class="tab ${state.activeTab === sec.type ? 'active' : ''}" onclick="setTab('${escapeAttr(sec.type)}')">
              ${escapeHtml(sec.title)}
            </button>
          `).join('')}
        </div>

        <div class="content-area">${renderTabContent()}</div>
      `;
    }

    function renderTabContent() {
      const active = state.sections.find(x => x.type === state.activeTab);
      if (!active) return '';

      if (state.activeTab === 'overview') {
        return `<div class="overview">${state.course.description || '<p>No overview available.</p>'}</div>`;
      }

      if (state.activeTab === 'content') {
        const filtered = filterItems(state.contentList);
        return `
          ${state.folderTrail.length > 1 ? `
            <div class="folder-path">
              ${state.folderTrail.map((x, i) => `
                <span>${i > 0 ? '›' : ''}</span>
                <button class="path-btn ${i === state.folderTrail.length - 1 ? 'active' : ''}" ${i === state.folderTrail.length - 1 ? '' : `onclick="goTrail(${i})"`}>
                  ${i === 0 ? '← Back' : escapeHtml(x.title)}
                </button>
              `).join('')}
            </div>
          ` : ''}

          ${state.contentLoading ? `
            <div class="loading"><div class="spinner"></div><p>Loading content...</p></div>
          ` : filtered.length === 0 ? `
            <div class="empty"><h3>No content available</h3><p>This folder has no matching items.</p></div>
          ` : `
            <div class="list">${filtered.map(renderContentItem).join('')}</div>
          `}
        `;
      }

      if (state.activeTab === 'live') {
        return `
          <div class="live-box">
            <h3>Live Classes</h3>
            <p>Join live sessions and interact with educators in real-time.</p>

            <div style="margin-top:16px;">
              <button class="btn btn-primary" onclick="location.href='/missionjeet/live?id=${state.courseId}'">
                Go to Live Classes
              </button>
            </div>

            <div style="margin-top:20px; display:flex; flex-direction:column; gap:12px;">
              ${
                (state.course?.description || "")
                  .match(/<img[^>]+src=["']([^"']+)["']/gi)
                  ?.map(imgTag => {
                    const src = imgTag.match(/src=["']([^"']+)["']/i)?.[1];
                    return src ? `<img src="${src}" style="width:100%; border-radius:12px;">` : "";
                  })
                  .join("") || ""
              }
            </div> 
          </div>
        `;
      }

      const blockData = Array.isArray(active.data) ? active.data : [];
      if (!blockData.length) {
        return `<div class="empty"><h3>No data available</h3><p>This section is empty.</p></div>`;
      }

      return `
        <div class="section-cards">
          ${blockData.map(card => `
            <div class="simple-card">
              ${card.thumbnail ? `<img src="${escapeAttr(card.thumbnail)}" alt="${escapeAttr(card.title || 'thumb')}">` : ''}
              ${card.title ? `<div class="item-title">${escapeHtml(card.title)}</div>` : ''}
              ${card.description ? `<div class="overview">${card.description}</div>` : ''}
              ${card.question ? `<div class="item-title">${escapeHtml(card.question)}</div>` : ''}
              ${card.answer ? `<div class="overview">${card.answer}</div>` : ''}
            </div>
          `).join('')}
        </div>
      `;
    }

    function renderContentItem(item) {
      if (item.type === 'folder') {
        const counts = countsText(item.data?.content_counts);
        return `
          <div class="item" onclick='openFolder(${JSON.stringify(item).replace(/'/g, "&apos;")})'>
            <img class="thumb small" src="https://cdn-icons-png.flaticon.com/512/716/716784.png" alt="Folder">
            <div class="item-info">
              <div class="item-title">${escapeHtml(item.title)}</div>
              ${counts ? `<div class="counts">${escapeHtml(counts)}</div>` : ''}
            </div>
          </div>
        `;
      }

      if (item.type === 'test') {
        const test = item.data || {};
        return `
          <div class="test-card">
            <div class="test-head">
              <div class="test-icon">T</div>
              <div class="item-info">
                <div class="test-title">${escapeHtml(item.title || 'Untitled Test')}</div>
                <div class="test-times">
                  <span class="test-chip"><strong>Starts:</strong> ${escapeHtml(formatDateTime(test.schedule_start_time))}</span>
                  <span class="test-chip ends"><strong>Ends:</strong> ${escapeHtml(formatDateTime(test.schedule_end_time))}</span>
                </div>
              </div>
            </div>
            <hr class="test-divider">
            <div class="test-action">
              <button class="test-btn" type="button" onclick="location.href='../nexttext?testid=${encodeURIComponent(item.entity_id)}'">Start Test</button>
            </div>
          </div>
        `;
      }

      const kind = getContentKind(item);
      const isNotesOrDpp = isNotesOrDppItem(item);
      const thumb = contentThumb(item);
      const duration = formatDuration(item.data?.duration);
      const created = formatDate(item.data?.created_at);
      const isLive = Number(item?.data?.file_type) === 2 && Number(item?.data?.video_type) === 3 && Number(item?.data?.is_live) === 1;
      const isUpcoming = Number(item?.data?.file_type) === 2 && Number(item?.data?.video_type) === 3 && Number(item?.data?.is_live) === 0;

      return `
        <div class="item" onclick='openContent(${JSON.stringify(item).replace(/'/g, "&apos;")})'>
          ${isLive ? `<span class="pill pill-live">LIVE</span>` : ''}
          ${isUpcoming ? `<span class="pill pill-upcoming">Upcoming</span>` : ''}

          <img class="thumb" src="${escapeAttr(thumb)}" alt="${escapeAttr(item.title || 'thumb')}">
          ${isVideoItem(item) && !isNotesOrDpp ? '<div class="play-overlay">▶</div>' : ''}

          <div class="item-info">
            <div class="item-title">${escapeHtml(item.title)}</div>
            <div class="item-meta">
              ${duration ? `<span>${escapeHtml(duration)}</span>` : ''}
              ${created ? `<span>${escapeHtml(created)}</span>` : ''}
              <span>${escapeHtml(kind)}</span>
            </div>
          </div>
        </div>
      `;
    }

    function renderSidePanel() {
      const side = document.getElementById('sidePanel');

      if (!state.course) {
        side.innerHTML = '';
        return;
      }

      side.innerHTML = `
        <img class="side-thumb" src="${escapeAttr(safeImage(state.course.thumbnail))}" alt="${escapeAttr(state.course.title || 'course')}">
        <div class="side-title">${escapeHtml(state.course.title || '')}</div>
        <hr class="divider">
        <div class="price-box">
          <strong>Free</strong>
          <del>${formatPrice(state.course.mrp)}</del>
          <p>Inclusive of GST</p>
        </div>
        <button class="btn btn-primary" style="width:100%; margin-top:14px;" onclick="enrollCourse()">
          ${state.enrolled ? '✓ Enrolled' : 'Enroll Now'}
        </button>
      `;
    }

    function render() {
      renderMain();
      renderSidePanel();
    }

    document.getElementById('searchInput').addEventListener('input', (e) => {
      setSearch(e.target.value || '');
    });

    loadCourse();


    
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