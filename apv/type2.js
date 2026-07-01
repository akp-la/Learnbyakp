const QS = new URLSearchParams(location.search);
const BATCH_ID = QS.get('batchId') || '';
const SUBJECT_ID = QS.get('subjectId') || '';
const CHAPTER_ID = QS.get('chapterId') || '';
const BATCH_NAME = QS.get('batchName') || '';
const SUBJECT_NAME = QS.get('subjectName') || '';
const CHAPTER_NAME = QS.get('chapterName') || '';
const INIT_SEC = QS.get('section') || 'videos';


if(!BATCH_ID || !SUBJECT_ID || !CHAPTER_ID) location.href = '/study-v2/batches';
document.getElementById('back-label').textContent = CHAPTER_NAME || 'Chapters';
const SITE_NAME = 'LearnByAKP';
document.title = (CHAPTER_NAME || 'Content') + ' — ' + SITE_NAME;


// ========== LOADER FEATURE ==========
const LOADER_HTML = `
  <div id="page-loader" class="loader-overlay">
    <div class="loader-content">
      <div class="loader-spinner"></div>
      <div class="loader-text">Loading...</div>
    </div>
  </div>
`;

function showLoader() {
  if (!document.getElementById('page-loader')) {
    document.body.insertAdjacentHTML('beforeend', LOADER_HTML);
  }
  document.getElementById('page-loader').classList.add('show');
}

function hideLoader() {
  const loader = document.getElementById('page-loader');
  if (loader) {
    loader.classList.remove('show');
    setTimeout(() => loader.remove(), 300);
  }
}

const LOADER_CSS = `
  <style id="loader-css">
    .loader-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.85);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 9999;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.3s, visibility 0.3s;
    }
    
    .loader-overlay.show {
      opacity: 1;
      visibility: visible;
    }
    
    .loader-content {
      text-align: center;
      color: white;
    }
    
    .loader-spinner {
      width: 50px;
      height: 50px;
      border: 4px solid rgba(255, 255, 255, 0.3);
      border-top: 4px solid #4CAF50;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 20px;
    }
    
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .loader-text {
      font-size: 16px;
      font-weight: 500;
    }
  </style>
`;

// Insert CSS on page load
document.head.insertAdjacentHTML('beforeend', LOADER_CSS);
// ========== END LOADER FEATURE ==========


const PW_HDR={"Accept-Encoding": "gzip", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A707F Build/RP1A.200720.012)", "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODM1MjY1MzcuMjEzLCJkYXRhIjp7Il9pZCI6IjY0YjM1MmZiMjNhNmM3MDAxODVkZjEyNCIsInVzZXJuYW1lIjoiODU0MzA0NDk2MiIsImZpcnN0TmFtZSI6Ik5hbmN5IiwibGFzdE5hbWUiOiJKYWlzd2FsIiwib3JnYW5pemF0aW9uIjp7Il9pZCI6IjVlYjM5M2VlOTVmYWI3NDY4YTc5ZDE4OSIsIndlYnNpdGUiOiJwaHlzaWNzd2FsbGFoLmNvbSIsIm5hbWUiOiJQaHlzaWNzd2FsbGFoIn0sImVtYWlsIjoiamFpc3dhbGdhdXJpNjA0QGdtYWlsLmNvbSIsInJvbGVzIjpbIjViMjdiZDk2NTg0MmY5NTBhNzc4YzZlZiJdLCJjb3VudHJ5R3JvdXAiOiJJTiIsIm9uZVJvbGVzIjpbXSwidHlwZSI6IlVTRVIifSwianRpIjoiTEhLY3dMSWNUZWVBb09uakl0VmpVZ182NGIzNTJmYjIzYTZjNzAwMTg1ZGYxMjQiLCJpYXQiOjE3ODI5MjE3Mzd9.-JaFpfzHyahSLboZgrYccFTS-BE2NigDGqoetpi901Q", "client-id": "ADMIN", "client-type": "MOBILE", "client-version": "538", "content-type": "application/json", "device-meta": "{\"APP_VERSION\":\"538\",\"APP_VERSION_NAME\":\"15.32.0\",\"DEVICE_MAKE\":\"Samsung\",\"DEVICE_MODEL\":\"SM-A707F\",\"OS_VERSION\":\"11\",\"PACKAGE_NAME\":\"xyz.penpencil.physicswala\",\"network\":\"wifi_data\",\"carrier\":\"UNDEFINED\"}", "randomid": "b8441281-cf24-4f70-8f70-164ed703d534", "referer": "https://android.pw.live"};



async function pw(url) {
    return fetch(url, {headers: PW_HDR}).then(r => r.json());
}


function esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}


function ep(v) {
    return encodeURIComponent(v || '');
}


function fmtDate(iso) {
    if(!iso) return '';
    try {
        const d = new Date(iso), M = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        return `${d.getUTCDate()} ${M[d.getUTCMonth()]}, ${d.getUTCMonth()}`;
    } catch { return ''; }
}


function showMsg(t) {
    const p = document.getElementById('popup');
    p.textContent = t;
    p.classList.add('show');
    setTimeout(() => p.classList.remove('show'), 3000);
}


const CK = 'LearnByAKP_completed';
function getC() {
    try { return JSON.parse(localStorage.getItem(CK) || '{}'); }
    catch { return {}; }
}
function saveC(d) {
    localStorage.setItem(CK, JSON.stringify(d));
}
function toggleC(ev, id, name) {
    ev.preventDefault();
    ev.stopPropagation();
    if(!id) return;
    const c = getC(), btn = ev.currentTarget;
    if(c[id]) {
        delete c[id];
        btn.classList.remove('done');
    } else {
        c[id] = true;
        btn.classList.add('done');
        showMsg('🎉 Congratulations!\n' + name);
    }
    saveC(c);
}
function initComplete(panel) {
    const c = getC();
    panel.querySelectorAll('.complete-btn').forEach(btn => {
        if(c[btn.dataset.id]) btn.classList.add('done');
    });
}


const TABS = ['videos','notes','dpp','DppNotes','DppVideos'];
const tabState = {};
TABS.forEach(t => tabState[t] = {page:1, loading:false, done:false, loaded:false});


let activeTab = INIT_SEC;


function skelCount(h) {
    return Math.max(3, Math.floor((window.innerHeight - 152) / (h + 12)));
}
function skels(panel, h) {
    panel.innerHTML = Array(skelCount(h)).fill(`<div class="skel" style="height:${h}px;border-radius:14px;margin-bottom:12px"></div>`).join('');
}
function bottomSkels(panel, h) {
    const d = document.createElement('div');
    d.className = 'bskels';
    d.innerHTML = Array(Math.max(2, Math.floor(skelCount(h)/2))).fill(`<div class="skel" style="height:${h}px;border-radius:14px;margin-bottom:12px"></div>`).join('');
    panel.appendChild(d);
}
function removeBottomSkels(panel) {
    panel.querySelectorAll('.bskels').forEach(e => e.remove());
}


function showComingSoon(panel) {
    panel.innerHTML = `<div class="coming-soon"><div class="cs-icon">🚀</div><div class="cs-text">Coming Soon</div><div class="cs-sub">Content will be available soon!</div></div>`;
}


function buildVideoItem(item) {
    const vd = item.videoDetails || {};
    const thumb = vd.image || '';
    const dur = vd.duration || '';
    const date = fmtDate(item.date || item.startTime || '');
    const id_ = item._id || '';
    const name = item.topic || vd.name || '';
    const done = getC()[id_] ? 'done' : '';
    const href = `/study-v2/player.html?batch_id=${ep(BATCH_ID)}&subject_id=${ep(SUBJECT_ID)}&video_id=${ep(id_)}&schedule_id=${ep(id_)}&title=${ep(name)}`;
    const li = document.createElement('li');
    li.className = 'content-item';
    li.innerHTML = `<a class="content-link" href="${esc(href)}" onclick="showLoader();">
        <div class="thumb-box">
            <img data-src="${esc(thumb) || '/static/site_thumbnail.png'}" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1 1'%3E%3C/svg%3E" alt="" class="lazy-img" onerror="this.src='/static/site_thumbnail.png'">
            ${dur ? `<div class="duration-badge">${esc(dur)}</div>` : ''}
        </div>
        <div class="content-details">
            <div class="content-name">${esc(name)}</div>
            <div class="content-meta">${date ? `<span>${esc(date)}</span>` : ''}</div>
            <button class="complete-btn ${done}" onclick="toggleC(event,'${esc(id_)}','${esc(name)}')" data-id="${esc(id_)}"><svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg></button>
        </div>
    </a>`;
    return li;
}


function buildNoteItems(item, isDpp) {
  const frags = [];
  const date = fmtDate(item.date || item.startTime || '');

  (item.homeworkIds || []).forEach((hw, hwIdx) => {
    (hw.attachmentIds || []).forEach((att, attIdx) => {
      const name = hw.topic || att.name || 'Note';

      // global note index (same logic as tumhara gIdx)
      let gIdx = 0;
      for (let i = 0; i < hwIdx; i++) {
        gIdx += (item.homeworkIds[i].attachmentIds || []).length;
      }
      gIdx += attIdx;

      const li = document.createElement('li');
      li.className = 'content-item';
      li.style.display = 'flex';

      const a = document.createElement('a');
      a.className = 'content-link';
      a.href = 'javascript:void(0)';   // direct slides URL mat do
      a.target = '_self';

      a.addEventListener('click', async (e) => {
        e.preventDefault();
        // same flow as openNotePage: API call + redirect
        await openNotePage({
          batchId: BATCH_ID,
          sid: SUBJECT_ID,
          schId: item._id,
          index: gIdx,
          isDpp
        });
      });

      a.innerHTML = `
        <div class="pdf-box">📄</div>
        <div class="content-details">
          <div class="content-name">${esc(name)}</div>
          <div class="content-meta">${date ? `<span>${esc(date)}</span>` : ''}</div>
        </div>
      `;

      li.appendChild(a);
      frags.push(li);
    });
  });

  return frags;
}
async function openNotePage({ batchId, sid, schId, index, isDpp }) {
  const apiUrl =
    `https://learnbyakp.onrender.com/slides?batch_id=${ep(batchId)}&subject_id=${ep(sid)}&schedule_id=${ep(schId)}&type=schedule-details&tap=note&noteIndex=${index}&isDpp=${isDpp ? 'true' : 'false'}`;

  // same as initScheduleData: no credentials
  const res = await fetch(apiUrl);

  const json = await res.json();
  if (!json?.success || !json?.data) return;

  const data = json.data;
  const hw = (data.homeworkIds || [])[index] || (data.homeworkIds || [])[0];
  const url = getAttachmentUrl(hw);

  window.location.href = url;
}

function getAttachmentUrl(hw) {
  if (!hw) {
    throw new Error('No homework data found for note');
  }

  const att = (hw.attachmentIds || [])[0];

  if (!att) {
    throw new Error('No attachment found for this note');
  }

  if (!att.baseUrl || !att.key) {
    throw new Error('Attachment URL is incomplete');
  }

  return att.baseUrl + att.key;
}
function buildDppItem(item) {
    const test = item.test || {};
    const isFree = item.isFree === true;
    const href = `/get-dpp-quiz?batchId=${ep(BATCH_ID)}&scheduleId=${ep(item.scheduleId || '')}&testId=${ep(test._id || '')}&tag=${ep(item.tag || 'Start')}&isFreeTest=${isFree}`;
    const li = document.createElement('li');
    li.className = 'dpp-item';
    li.innerHTML = `<a class="dpp-link" href="${esc(href)}">
        <div class="dpp-content">
            <div class="dpp-name">${esc(test.name || 'DPP Quiz')}</div>
            <div class="dpp-meta"><span>📋 ${test.totalQuestions || 0} questions</span><span style="margin:0 2px">•</span><span>${test.totalMarks || 0} Marks</span>${test.maxDuration ? `<span style="margin:0 2px">•</span><span>${test.maxDuration} Mins</span>` : ''}</div>
        </div>
        <div class="dpp-play"><div class="play-btn"><div class="play-icon"></div></div><span class="dpp-tag">${esc(item.tag || 'Start')}</span></div>
    </a>`;
    return li;
}


async function loadContent(tab, page) {
    const st = tabState[tab];
    if(st.loading || st.done) return;
    st.loading = true;
    const panel = document.getElementById('panel-' + tab);
    const isVid = (tab === 'videos' || tab === 'DppVideos');
    const isDppNotes = (tab === 'DppNotes');
    const isDpp = (tab === 'dpp');
    const cardH = isDpp ? 82 : 88;


    if(page === 1) {
        if(isVid) {
            panel.innerHTML = '<div class="lecture-grid"></div>';
        } else if(tab === 'notes' || tab === 'DppNotes') {
            panel.innerHTML = '<div class="notes-grid"></div>';
        } else {
            skels(panel, cardH);
        }
    } else {
        if(!isVid && tab !== 'notes' && tab !== 'DppNotes') bottomSkels(panel, cardH);
    }


    try {
        let data;
        if(isDpp) {
            data = await pw(`https://api.penpencil.co/v3/test-service/tests/dpp?batchId=${BATCH_ID}&batchSubjectId=${SUBJECT_ID}&chapterId=${CHAPTER_ID}&isSubjective=false&page=${page}`);
        } else {
            data = await pw(`https://api.penpencil.co/v2/batches/${BATCH_ID}/subject/${SUBJECT_ID}/contents?page=${page}&contentType=${tab}&tag=${CHAPTER_ID}`);
        }


        removeBottomSkels(panel);
        
        if(page === 1 && !isVid && tab !== 'notes' && tab !== 'DppNotes') panel.innerHTML = '';


        if(!data.success || !data.data?.length) {
            st.done = true;
            if(page === 1) showComingSoon(panel);
            return;
        }


        let container;
        if(isVid) {
            container = panel.querySelector('.lecture-grid');
        } else if(tab === 'notes' || tab === 'DppNotes') {
            container = panel.querySelector('.notes-grid');
        } else {
            container = panel.querySelector('.content-list');
            if(!container) {
                container = document.createElement('ul');
                container.className = 'content-list';
                panel.appendChild(container);
            }
        }


        if(isDpp) {
            data.data.forEach(item => container.appendChild(buildDppItem(item)));
            const total = data.paginate?.totalCount || 0;
            const limit = data.paginate?.limit || 50;
            if(data.data.length < limit || (total > 0 && page * limit >= total)) st.done = true;
            else st.page = page + 1;
        } else if(isVid) {
            data.data.forEach(item => container.appendChild(buildVideoItem(item)));
            if(data.data.length < 20) st.done = true;
            else st.page = page + 1;
        } else {
            data.data.forEach(item => buildNoteItems(item, isDppNotes).forEach(f => container.appendChild(f)));
            if(data.data.length < 20) st.done = true;
            else st.page = page + 1;
        }


        initComplete(panel);
        initLazyImages(panel);
    } catch {
        removeBottomSkels(panel);
        if(page === 1) showComingSoon(panel);
    } finally {
        st.loading = false;
    }
}


function switchTab(tab, btn) {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.getElementById('panel-' + tab).classList.add('active');
    activeTab = tab;
    window.scrollTo({top: 0, behavior: 'smooth'});
    const st = tabState[tab];
    if(!st.loaded) {
        st.loaded = true;
        loadContent(tab, 1);
    }
}


window.addEventListener('scroll', () => {
    if(window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 180) {
        const st = tabState[activeTab];
        if(st.loaded && !st.loading && !st.done) loadContent(activeTab, st.page);
    }
});


(function() {
    const btn = document.querySelector(`.nav-tab[data-sec="${INIT_SEC}"]`) || document.querySelector('.nav-tab');
    if(btn) {
        btn.classList.add('active');
        activeTab = btn.dataset.sec || INIT_SEC;
    }
    document.getElementById('panel-' + activeTab).classList.add('active');
    tabState[activeTab].loaded = true;
    loadContent(activeTab, 1);
    ['contextmenu','selectstart','dragstart','copy'].forEach(e => document.addEventListener(e, ev => ev.preventDefault()));
    document.addEventListener('keydown', e => {
        if(e.key === 'F12' || (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key)) || (e.ctrlKey && ['U','S'].includes(e.key))) {
            e.preventDefault();
            return false;
        }
    });
})();


function initLazyImages(root) {
    if(!('IntersectionObserver' in window)) {
        root.querySelectorAll('img.lazy-img[data-src]').forEach(img => {
            img.src = img.dataset.src;
            img.classList.remove('lazy-img');
        });
        return;
    }
    const io = new IntersectionObserver((entries, obs) => {
        entries.forEach(e => {
            if(e.isIntersecting) {
                const img = e.target;
                img.src = img.dataset.src;
                img.removeAttribute('data-src');
                img.classList.remove('lazy-img');
                obs.unobserve(img);
            }
        });
    }, {rootMargin: '200px 0px'});
    root.querySelectorAll('img.lazy-img[data-src]').forEach(img => io.observe(img));
}
