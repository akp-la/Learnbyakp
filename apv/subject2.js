const QS = new URLSearchParams(location.search);
const BATCH_ID = QS.get('batchid') || '';
const BATCH_NAME = QS.get('name') || '';

if (!BATCH_ID) location.href = '/study-v2/batches';

document.getElementById('back-label').textContent = BATCH_NAME || 'Batches';

const TEACHER_BG = 'https://study-mf.pw.live/static/image/teacherbg.807b2b2f.png';

const PW_HDR = {
  "Accept-Encoding": "gzip",
  "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A707F Build/RP1A.200720.012)",
  "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODM1MjY1MzcuMjEzLCJkYXRhIjp7Il9pZCI6IjY0YjM1MmZiMjNhNmM3MDAxODVkZjEyNCIsInVzZXJuYW1lIjoiODU0MzA0NDk2MiIsImZpcnN0TmFtZSI6Ik5hbmN5IiwibGFzdE5hbWUiOiJKYWlzd2FsIiwib3JnYW5pemF0aW9uIjp7Il9pZCI6IjVlYjM5M2VlOTVmYWI3NDY4YTc5ZDE4OSIsIndlYnNpdGUiOiJwaHlzaWNzd2FsbGFoLmNvbSIsIm5hbWUiOiJQaHlzaWNzd2FsbGFoIn0sImVtYWlsIjoiamFpc3dhbGdhdXJpNjA0QGdtYWlsLmNvbSIsInJvbGVzIjpbIjViMjdiZDk2NTg0MmY5NTBhNzc4YzZlZiJdLCJjb3VudHJ5R3JvdXAiOiJJTiIsIm9uZVJvbGVzIjpbXSwidHlwZSI6IlVTRVIifSwianRpIjoiTEhLY3dMSWNUZWVBb09uakl0VmpVZ182NGIzNTJmYjIzYTZjNzAwMTg1ZGYxMjQiLCJpYXQiOjE3ODI5MjE3Mzd9.-JaFpfzHyahSLboZgrYccFTS-BE2NigDGqoetpi901Q",
  "client-id": "ADMIN",
  "client-type": "MOBILE",
  "client-version": "538",
  "content-type": "application/json",
  "device-meta": "{\"APP_VERSION\":\"538\",\"APP_VERSION_NAME\":\"15.32.0\",\"DEVICE_MAKE\":\"Samsung\",\"DEVICE_MODEL\":\"SM-A707F\",\"OS_VERSION\":\"11\",\"PACKAGE_NAME\":\"xyz.penpencil.physicswala\",\"network\":\"wifi_data\",\"carrier\":\"UNDEFINED\"}",
  "randomid": "b8441281-cf24-4f70-8f70-164ed703d534",
  "referer": "https://android.pw.live"
};

async function pw(url) {
  return fetch(url, { headers: PW_HDR }).then(r => r.json());
}

function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function ep(v) {
  return encodeURIComponent(v || '');
}

function fmtIST(iso) {
  if (!iso) return '';
  try {
    const d = new Date(new Date(iso).getTime() + (5 * 60 + 30) * 60000);
    let h = d.getUTCHours(), m = d.getUTCMinutes(), ap = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    return `${h}:${String(m).padStart(2, '0')}${ap}`;
  } catch {
    return '';
  }
}

function fmtHeld(iso) {
  if (!iso) return '';
  try {
    const d = new Date(new Date(iso).getTime() + (5 * 60 + 30) * 60000);
    const M = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    let h = d.getUTCHours(), m = d.getUTCMinutes(), ap = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    return `${d.getUTCDate()} ${M[d.getUTCMonth()]} ${d.getUTCFullYear()} • ${h}:${String(m).padStart(2, '0')} ${ap}`;
  } catch {
    return '';
  }
}

function relTime(ts) {
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s >= 31536000) return Math.floor(s / 31536000) + 'y ago';
  if (s >= 86400) return Math.floor(s / 86400) + 'd ago';
  if (s >= 3600) return Math.floor(s / 3600) + 'h ago';
  if (s >= 60) return Math.floor(s / 60) + 'm ago';
  return 'just now';
}

function linkify(t) {
  return t.replace(/(\b(https?|ftp):\/\/[-A-Z0-9+&@#/%?=~_|!:,.;]*[-A-Z0-9+&@#/%=~_|])/ig, '<a href="$1" target="_blank">$1</a>');
}

function showMsg(t) {
  const p = document.getElementById('popup');
  p.textContent = t;
  p.classList.add('show');
  setTimeout(() => p.classList.remove('show'), 3000);
}

function showInfo(em, ti, ms) {
  document.getElementById('info-emoji').textContent = em;
  document.getElementById('info-title').textContent = ti;
  document.getElementById('info-msg').innerHTML = ms.replace(/\n/g, '<br>');
  document.getElementById('info-overlay').classList.add('open');
}

function closeInfo(ev) {
  if (ev && ev.target !== document.getElementById('info-overlay')) return;
  document.getElementById('info-overlay').classList.remove('open');
}

async function fetchTeacherMap(ids) {
  if (!ids || !ids.length) return {};
  try {
    const unique = [...new Set(ids)].join(',');
    const data = await pw(`https://api.penpencil.co/v1/users/get-user-details-list?userIds=${unique}`);
    const map = {};
    (data.data || []).forEach(u => {
      map[u._id] = {
        name: u.name || `${u.firstName || ''} ${u.lastName || ''}`.trim(),
        img: u.imageId ? (u.imageId.baseUrl + u.imageId.key) : ''
      };
    });
    return map;
  } catch {
    return {};
  }
}

function mkTeacherCard(teachers, map) {
  const first = teachers && teachers[0] ? map[teachers[0]] : null;
  const name = first ? first.name : '';
  const img = first ? first.img : '';
  const div = document.createElement('div');
  div.className = 'sc-teacher-thumb';

  const bg = document.createElement('img');
  bg.className = 'sc-teacher-bg';
  bg.src = TEACHER_BG;
  bg.alt = '';
  div.appendChild(bg);

  if (img) {
    const ti = document.createElement('img');
    ti.className = 'sc-teacher-img';
    ti.src = img;
    ti.alt = name;
    ti.onerror = function () { this.style.display = 'none'; };
    div.appendChild(ti);
  }

  if (name) {
    const tn = document.createElement('div');
    tn.className = 'sc-teacher-name';
    tn.textContent = name;
    div.appendChild(tn);
  }

  return div;
}

function isVideoClass(item) {
  const tag = (item.tag || '').toLowerCase();
  if (['live', 'upcoming'].includes(tag)) return true;
  if (tag === 'ended') return !!item.isVideoLecture;
  return false;
}

/**
 * Determine item type label for top‑right of thumbnail.
 * Priority:
 *  - If hasAttachment only: Notes
 *  - If video only: Lecture
 *  - If both: Mixed
 *  - Fallback: Lecture
 */
function getItemType(item) {
  const hasVideo = isVideoClass(item);
  const hasNotes = !!item.hasAttachment;
  if (hasVideo && hasNotes) return 'Mixed';
  if (hasNotes && !hasVideo) return 'Notes';
  if (hasVideo && !hasNotes) return 'Lecture';
  return 'Lecture';
}

async function loadSchedule() {
  const row = document.getElementById('sched-row');
  if (!row) return;

  try {
    const data = await pw(`https://api.penpencil.co/v1/batches/${BATCH_ID}/todays-schedule`);
    row.innerHTML = '';

    if (!data.success || !data.data?.length) {
      row.innerHTML = '<p style="font-style:italic;color:#94a3b8;padding:12px 0;font-size:13px">No classes scheduled for today.</p>';
      return;
    }

    const allTeacherIds = [];
    data.data.forEach(item => {
      if (isVideoClass(item)) (item.teachers || []).forEach(tid => { if (tid) allTeacherIds.push(tid); });
    });

    const teacherMap = await fetchTeacherMap(allTeacherIds);
    let any = false;

    data.data.forEach((item, index) => {
      const sid = item.batchSubjectId || '';
      const schId = item._id || '';
      const videoId = item.videoDetails?.id || schId;
      const title = item.topic || item.videoDetails?.name || item.subjectId?.name || '';
      const subjectId = item.subjectId?._id || sid;

      const tag = item.tag || '';
      const tagL = tag.toLowerCase();
      const st = fmtIST(item.startTime);
      const time = Math.floor(new Date(item.startTime).getTime() / 1000);
      const subN = item.subjectId?.name || '';
      const topic = item.topic || '';
      const teachers = item.teachers || [];
      const thumb = item.videoDetails?.image || '';

      const itemType = getItemType(item);

      // VIDEO CLASS BLOCK
      if (isVideoClass(item)) {
        any = true;
        const a = document.createElement('a');
        a.className = 'sc';
        a.href = `/study-v2/player.html?batch_id=${ep(BATCH_ID)}&subject_id=${ep(subjectId)}&video_id=${ep(videoId)}&schedule_id=${ep(schId)}&title=${ep(title)}&time=${ep(time)}`;

        if (tagL === 'upcoming') {
          a.onclick = ev => {
            ev.preventDefault();
            showMsg(`Class not started yet. Begins at ${st}.`);
          };
        }

        // Thumb / teacher card
        if (thumb) {
          const ti = document.createElement('img');
          ti.className = 'sc-thumb';
          ti.src = thumb;
          ti.alt = '';
          ti.onerror = function () {
            const tc = mkTeacherCard(teachers, teacherMap);
            a.insertBefore(tc, this);
            this.remove();
          };
          a.appendChild(ti);
        } else {
          a.appendChild(mkTeacherCard(teachers, teacherMap));
        }

        // TYPE BADGE (top‑right)
        const typeBadge = document.createElement('div');
        typeBadge.className = 'sc-type-badge';
        typeBadge.textContent = itemType;
        a.appendChild(typeBadge);

        // Body
        const body = document.createElement('div');
        body.className = 'sc-body';

        const top = document.createElement('div');
        top.className = 'sc-top';

        if (tag) {
          const sp = document.createElement('span');
          sp.className = 'tag ' + tagL;
          sp.textContent = tag;
          top.appendChild(sp);
        }

        if (st) {
          const tm = document.createElement('div');
          tm.className = 'sc-time';
          tm.innerHTML = `<span class="clk"></span><span>${esc(st)}</span>`;
          top.appendChild(tm);
        }

        const sn = document.createElement('div');
        sn.className = 'sc-sub';
        sn.textContent = subN;

        const tp = document.createElement('div');
        tp.className = 'sc-topic';
        tp.textContent = topic;

        body.appendChild(top);
        body.appendChild(sn);
        body.appendChild(tp);
        a.appendChild(body);
        row.appendChild(a);
      }

      // ATTACHMENT / NOTES BLOCK
      if (item.hasAttachment) {
        any = true;

        (item.homeworkIds || []).forEach(hw => {
          (hw.attachmentIds || []).forEach(() => {
            const isDpp = hw.note === 'DPP';

            const a = document.createElement('a');
            a.className = 'sc';
            a.href = 'javascript:void(0)';
            a.target = '_self';

            a.addEventListener('click', async (e) => {
              e.preventDefault();
              await openNotePage({
                batchId: BATCH_ID,
                sid,
                schId,
                index,
                isDpp
              });
            });

            const body = document.createElement('div');
            body.className = 'sc-body';
            body.style.cssText = 'justify-content:flex-start;padding-top:14px';

            const imgWrap = document.createElement('div');
            imgWrap.className = 'note-thumb';

            const img = document.createElement('img');
            img.src = getAttachmentUrl(hw);
            img.alt = hw.topic || 'Note';
            img.onerror = function () {
              this.onerror = null;
              this.src = NOTES_FALLBACK;
            };

            imgWrap.appendChild(img);

            const nt = document.createElement('div');
            nt.className = 'note-t';
            nt.textContent = hw.topic || 'Note';

            const ns = document.createElement('div');
            ns.className = 'note-s';
            ns.textContent = subN;

            body.appendChild(imgWrap);
            body.appendChild(nt);
            body.appendChild(ns);

            // Type badge for notes-only card
            const typeBadge = document.createElement('div');
            typeBadge.className = 'sc-type-badge';
            typeBadge.textContent = 'Notes';
            a.appendChild(typeBadge);

            a.appendChild(body);
            row.appendChild(a);
          });
        });
      }
    });

    if (!any) {
      row.innerHTML = '<p style="font-style:italic;color:#94a3b8;padding:12px 0;font-size:13px">No classes scheduled for today.</p>';
    }
  } catch (e) {
    console.error('loadSchedule error:', e);
    row.innerHTML = `<p style="font-style:italic;color:#94a3b8;padding:12px 0;font-size:13px">Failed to load: ${esc(e.message || e)}</p>`;
  }
}

let khazanaId = null, subjectsLoaded = false;
const NOTES_FALLBACK = 'https://static.vecteezy.com/system/resources/thumbnails/023/492/712/small/3d-notes-icon-png.png';

function getAttachmentUrl(hw) {
  const att = (hw?.attachmentIds || [])[0];
  if (!att) return NOTES_FALLBACK;
  if (att.baseUrl && att.key) return att.baseUrl + att.key;
  return NOTES_FALLBACK;
}

async function openNotePage({ batchId, sid, schId, index, isDpp }) {
  const apiUrl =
    `https://learnbyakp.onrender.com/slides?batch_id=${ep(batchId)}&subject_id=${ep(sid)}&schedule_id=${ep(schId)}&type=schedule-details&tap=note&noteIndex=${index}&isDpp=${isDpp ? 'true' : 'false'}`;

  // SAME as initScheduleData: no credentials
  const res = await fetch(apiUrl); // <-- credentials: 'include' hata do

  const json = await res.json();
  if (!json?.success || !json?.data) return;

  const data = json.data;
  const hw = (data.homeworkIds || [])[0];
  const url = getAttachmentUrl(hw);

  window.location.href = url;
}

function subjSkelCount() {
  return Math.max(3, Math.floor((window.innerHeight - 200) / clamp(76, 110)));
}

function clamp(min, max) {
  return Math.min(max, Math.max(min, Math.floor(window.innerHeight * 0.15)));
}

function showSubjSkels() {
  const n = Math.max(3, Math.floor((window.innerHeight - 200) / 100));
  document.getElementById('subj-list').innerHTML =
    Array(n).fill('<div class="skel" style="height:clamp(76px,20vw,110px);border-radius:14px;margin-bottom:12px"></div>').join('');
}

async function loadSubjects() {
  if (subjectsLoaded) return;
  subjectsLoaded = true;
  showSubjSkels();
  const list = document.getElementById('subj-list');
  try {
    const data = await pw(`https://api.penpencil.co/v3/batches/${BATCH_ID}/details`);
    list.innerHTML = '';
    if (!data.success) {
      list.innerHTML = '<li style="text-align:center;padding:40px;color:#64748b">Failed to load subjects</li>';
      return;
    }
    const subs = data.data?.subjects || [];
    khazanaId = data.data?.khazanaProgramId || null;
    if (!subs.length) {
      list.innerHTML = '<li style="text-align:center;padding:40px;color:#64748b">No subjects found</li>';
      return;
    }
    subs.forEach(sub => {
      const img = sub.imageId ? sub.imageId.baseUrl + sub.imageId.key : 'https://cdn-icons-png.flaticon.com/512/5780/5780875.png';
      const li = document.createElement('li');
      li.className = 'subj-item';
      li.innerHTML =
        `<a class="subj-link" href="content?batchId=${ep(BATCH_ID)}&subjectId=${ep(sub._id)}&batchName=${ep(BATCH_NAME)}&subjectName=${ep(sub.subject)}">
           <img class="subj-img" src="${esc(img)}" alt="${esc(sub.subject)}" onerror="this.src='https://cdn-icons-png.flaticon.com/512/5780/5780875.png'">
           <div class="subj-cnt">
             <div class="subj-info">
               <div class="subj-name">${esc(sub.subject)}</div>
               <div class="subj-count">${sub.tagCount || 0} Chapters</div>
             </div>
             <span class="subj-arr">
               <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
             </span>
           </div>
         </a>`;
      list.appendChild(li);
    });
  } catch {
    document.getElementById('subj-list').innerHTML = '<li style="text-align:center;padding:40px;color:#64748b">Failed to load</li>';
  }
}

let khazanaRendered = false;

async function renderKhazana() {
  if (khazanaRendered) return;
  khazanaRendered = true;
  const list = document.getElementById('khazana-list');
  list.innerHTML = '<div class="skel" style="height:clamp(76px,20vw,110px);border-radius:14px"></div>';
  if (!khazanaId) {
    list.innerHTML =
      `<li>
         <div style="text-align:center;padding:60px 20px;color:#64748b">
           <div style="font-size:48px;margin-bottom:14px;opacity:0.5">🏆</div>
           <div style="font-size:16px;font-weight:700;color:#94a3b8;margin-bottom:8px">No Khazana Available</div>
           <div style="font-size:13px">Not available for <strong style="color:#94a3b8">${esc(BATCH_NAME)}</strong></div>
         </div>
       </li>`;
    return;
  }
  list.innerHTML = '<div class="skel" style="height:clamp(76px,20vw,110px);border-radius:14px"></div>';
  try {
    const data = await pw(`https://api.penpencil.co/v2/programs/${khazanaId}/filters?page=1&limit=20`);
    const khName = data.data?.name || 'Khazana';
    list.innerHTML = '';
    const li = document.createElement('li');
    li.className = 'subj-item';
    li.innerHTML =
      `<a class="subj-link" href="/khazana?khazanaProgramId=${ep(khazanaId)}&batchName=${ep(BATCH_NAME)}&batchId=${ep(BATCH_ID)}">
         <img class="subj-img" src="https://cdn-icons-png.flaticon.com/512/5780/5780875.png" alt="${esc(khName)}">
         <div class="subj-cnt">
           <div class="subj-info">
             <div class="subj-name">${esc(khName)}</div>
           </div>
           <span class="subj-arr">
             <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
           </span>
         </div>
       </a>`;
    list.appendChild(li);
  } catch {
    list.innerHTML = '';
    const li = document.createElement('li');
    li.className = 'subj-item';
    li.innerHTML =
      `<a class="subj-link" href="/khazana?khazanaProgramId=${ep(khazanaId)}&batchName=${ep(BATCH_NAME)}&batchId=${ep(BATCH_ID)}">
         <img class="subj-img" src="https://cdn-icons-png.flaticon.com/512/5780/5780875.png" alt="Khazana">
         <div class="subj-cnt">
           <div class="subj-info">
             <div class="subj-name">Khazana</div>
           </div>
           <span class="subj-arr">
             <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
           </span>
         </div>
       </a>`;
    list.appendChild(li);
  }
}

let testsLoaded = false, testsLoading = false, allSections = [], activeType = 'objective', activePill = 0;
let loadedObjSections = {}, loadedSubSections = {};
const ICO_Q =
  `<svg viewBox="0 0 24 24"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`;
const ICO_S =
  `<svg viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`;
const ICO_C =
  `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
const ICO_D =
  `<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`;

async function loadTests() {
  if (testsLoaded || testsLoading) return;
  testsLoading = true;
  const root = document.getElementById('tests-root');
  {
    const n = Math.max(3, Math.floor((window.innerHeight - 200) / 130));
    root.innerHTML = Array(n).fill('<div class="skel" style="height:120px;border-radius:14px;margin-bottom:12px"></div>').join('');
  }
  try {
    const filters = await pw(`https://api.penpencil.co/v3/test-service/tests/filters?batchId=${BATCH_ID}`);
    if (!filters.success) {
      root.innerHTML = ndH('Failed to load tests');
      return;
    }
    const catSecs = (filters.data?.categorySections || []).flatMap(c => c.sections || []);
    if (!catSecs.length) {
      root.innerHTML = ndH('No Tests Available');
      return;
    }
    allSections = catSecs.map(sec => ({ id: sec.id, title: sec.title }));
    testsLoaded = true;
    buildTestUI(root);
    await loadSectionTests(allSections[0].id, 'objective');
    rebuildTests();
  } catch {
    document.getElementById('tests-root').innerHTML = ndH('Failed to load tests');
  } finally {
    testsLoading = false;
  }
}

async function loadSectionTests(secId, type) {
  if (type === 'objective') {
    if (loadedObjSections[secId] !== undefined) return;
    loadedObjSections[secId] = null;
    try {
      const r = await pw(`https://api.penpencil.co/v3/test-service/tests?categorySectionId=${secId}&batchId=${BATCH_ID}&isSubjective=false`);
      loadedObjSections[secId] = (r.data || []).map(t => mkT(t, false));
    } catch {
      loadedObjSections[secId] = [];
    }
  } else {
    if (loadedSubSections[secId] !== undefined) return;
    loadedSubSections[secId] = null;
    try {
      const r = await pw(`https://api.penpencil.co/v3/test-service/tests?categorySectionId=${secId}&batchId=${BATCH_ID}&isSubjective=true`);
      loadedSubSections[secId] = (r.data || []).map(t => mkT(t, true));
    } catch {
      loadedSubSections[secId] = [];
    }
  }
}

function mkT(t, isSub) {
  return {
    _id: t._id,
    name: t.name,
    totalQuestions: t.totalQuestions || 0,
    totalMarks: t.totalMarks || 0,
    maxDuration: t.maxDuration || 180,
    heldOn: fmtHeld(t.startTime),
    startTimeIso: t.startTime || '',
    isResultAwaiting: !!t.isResultAwaiting,
    enableSyllabus: !!t.enableSyllabus,
    isSubjective: isSub
  };
}

function buildTestUI(root) {
  root.innerHTML = '';
  const tops = document.createElement('div');
  tops.className = 'test-top-tabs';
  ['Objective', 'Subjective'].forEach((l, i) => {
    const b = document.createElement('button');
    b.className = 'test-top-tab' + (i === 0 ? ' active' : '');
    b.textContent = l;
    b.onclick = async () => {
      if (b.disabled) return;
      activeType = i === 0 ? 'objective' : 'subjective';
      activePill = 0;
      const sec = allSections[activePill];
      if (sec) {
        b.disabled = true;
        renderTestsLoading();
        await loadSectionTests(sec.id, activeType);
        b.disabled = false;
      }
      rebuildTests();
    };
    tops.appendChild(b);
  });
  root.appendChild(tops);
  const pw2 = document.createElement('div');
  pw2.id = 't-pills';
  root.appendChild(pw2);
  const ar = document.createElement('div');
  ar.id = 't-area';
  root.appendChild(ar);
}

function renderTestsLoading() {
  const ar = document.getElementById('t-area');
  if (ar) {
    ar.innerHTML =
      '<div class="skel" style="height:120px;border-radius:14px;margin-bottom:12px"></div>' +
      '<div class="skel" style="height:120px;border-radius:14px;margin-bottom:12px"></div>';
  }
}

function rebuildTests() {
  document.querySelectorAll('.test-top-tab').forEach((b, i) =>
    b.classList.toggle('active', (i === 0 && activeType === 'objective') || (i === 1 && activeType === 'subjective'))
  );
  const pw2 = document.getElementById('t-pills');
  pw2.innerHTML = '';
  const ar = document.getElementById('t-area');
  ar.innerHTML = '';
  if (!allSections.length) {
    ar.innerHTML = ndH('No Tests Available');
    return;
  }
  if (activePill >= allSections.length) activePill = 0;
  if (allSections.length > 1) {
    const row = document.createElement('div');
    row.className = 'test-pills';
    allSections.forEach((sec, i) => {
      const pill = document.createElement('button');
      pill.className = 'test-pill' + (i === activePill ? ' active' : '');
      pill.textContent = sec.title || `Section ${i + 1}`;
      pill.onclick = async () => {
        activePill = i;
        row.querySelectorAll('.test-pill').forEach((p, j) => p.classList.toggle('active', j === i));
        const store = activeType === 'objective' ? loadedObjSections : loadedSubSections;
        if (store[sec.id] === undefined) {
          renderTestsLoading();
          await loadSectionTests(sec.id, activeType);
        }
        renderTests(getTests(sec.id));
      };
      row.appendChild(pill);
    });
    pw2.appendChild(row);
  }
  renderTests(getTests(allSections[activePill].id));
}

function getTests(secId) {
  const store = activeType === 'objective' ? loadedObjSections : loadedSubSections;
  return store[secId] || [];
}

function renderTests(tests) {
  const ar = document.getElementById('t-area');
  ar.innerHTML = '';
  if (!tests || !tests.length) {
    ar.innerHTML = ndH(`No ${activeType === 'subjective' ? 'Subjective' : 'Objective'} Tests`);
    return;
  }
  const list = document.createElement('div');
  list.className = 'test-list';
  tests.forEach(t => {
    const now = Date.now(), sMs = t.startTimeIso ? new Date(t.startTimeIso).getTime() : null;
    const ns = sMs && sMs > now, ra = !!t.isResultAwaiting;
    let badge = '';
    if (ns) badge = '<span class="test-badge b-ns">⏳ Not Started</span>';
    else if (ra) badge = '<span class="test-badge b-ra">📊 Result Awaiting</span>';
    else if (sMs) badge = '<span class="test-badge b-av">✅ Available</span>';
    const card = document.createElement('div');
    card.className = 'test-card';
    card.dataset.siso = t.startTimeIso || '';
    card.dataset.ra = ra ? 'true' : 'false';
    card.dataset.held = t.heldOn || '';
    card.dataset.tid = t._id;
    card.dataset.tname = t.name || '';
    card.dataset.hasSyl = t.enableSyllabus ? 'true' : 'false';
    card.innerHTML =
      `<div class="test-card-body">
         <div class="test-card-name">${esc(t.name || 'Untitled')}</div>
         <div class="test-meta">
           <span class="test-chip">${ICO_Q}${t.totalQuestions} Qs</span>
           <span class="test-chip">${ICO_S}${t.totalMarks} Marks</span>
           <span class="test-chip">${ICO_C}${t.maxDuration} Mins</span>
         </div>
         ${badge ? `<div class="test-status-row">${badge}</div>` : ''}
         ${t.heldOn ? `<div class="test-date-row">${ICO_D}<span class="test-date-text">Starts: ${esc(t.heldOn)}</span></div>` : ''}
       </div>
       ${t.enableSyllabus ? `<div class="test-syl-wrap"><button class="test-syl-btn" onclick="event.stopPropagation();openSyl(this)">📋 View Syllabus</button></div>` : ''}`;
    card.querySelector('.test-card-body').addEventListener('click', () => {
      const si = card.dataset.siso, isRa = card.dataset.ra === 'true', held = card.dataset.held;
      if (si) {
        const ms = new Date(si).getTime();
        if (!isNaN(ms) && ms > Date.now()) {
          showInfo('⏳', 'Test Not Started Yet', `Scheduled:\n\n📅 ${held}\n\nCome back at scheduled time 💪`);
          return;
        }
      }
      if (isRa) {
        showInfo('📊', 'Result Not Published', 'Result not published yet. Once out, you can start. 🔔');
        return;
      }
      location.href = `/get-batch-test?testId=${ep(card.dataset.tid)}&testName=${ep(card.dataset.tname)}&batchId=${ep(BATCH_ID)}`;
    });
    list.appendChild(card);
  });
  ar.appendChild(list);
}

function ndH(t) {
  return `<div class="no-data"><div class="no-data-icon">📝</div><div class="no-data-title">${t}</div></div>`;
}

let sylLangs = [], sylLang = '', sylData = {};

async function openSyl(btn) {
  const card = btn.closest('.test-card');
  const tid = card.dataset.tid, tname = card.dataset.tname;
  document.getElementById('syl-title').textContent = (tname || '') + ' — Syllabus';
  document.getElementById('syl-langs').style.display = 'none';
  document.getElementById('syl-content').innerHTML = '<div class="syl-loading">Loading syllabus...</div>';
  document.getElementById('syl-modal').classList.add('open');
  try {
    const data = await pw(`https://api.penpencil.co/v3/test-service/tests/${tid}/instructions`);
    const d = data.data || {};
    sylData = parseSyl(d.syllabus || {});
    sylLangs = (d.languageCodes || [])
      .map(l => ({ code: l.code.toLowerCase(), label: l.code.toUpperCase() }))
      .filter(l => sylData[l.code]);
    if (!sylLangs.length) sylLangs = Object.keys(sylData).map(k => ({ code: k, label: k.toUpperCase() }));
    sylLang = sylLangs.length ? sylLangs[0].code : '';
    renderSyl();
  } catch {
    document.getElementById('syl-content').innerHTML =
      '<p style="color:#64748b;font-size:13px">Failed to load syllabus.</p>';
  }
}

function parseSyl(syl) {
  const r = {};
  if (!syl || typeof syl !== 'object') return r;
  Object.entries(syl).forEach(([k, v]) => {
    if (typeof v === 'string') {
      r[k.toLowerCase()] = cleanSyl(v);
    } else if (typeof v === 'object' && v) {
      Object.entries(v).forEach(([sk, sv]) => {
        r[(k + '_' + sk).toLowerCase()] =
          typeof sv === 'string' ? cleanSyl(sv) : JSON.stringify(sv);
      });
    }
  });
  return r;
}

function cleanSyl(s) {
  if (!s) return '';
  s = s.replace(/<!--[\s\S]*?-->/g, m => /\[if\s/i.test(m) ? m : '');
  s = s.replace(/<\/?[owm]:[^>]*>/gi, '');
  s = s.replace(/\s*style="[^"]*mso-[^"]*"/gi, '');
  s = s.replace(/\s*class="[^"]*"/gi, '');
  s = s.replace(/<xml[\s\S]*?<\/xml>/gi, '');
  return s.trim();
}

function renderSyl() {
  const lr = document.getElementById('syl-langs');
  lr.innerHTML = '';
  if (sylLangs.length > 1) {
    lr.style.display = 'flex';
    sylLangs.forEach(l => {
      const b = document.createElement('button');
      b.className = 'modal-lang-btn' + (l.code === sylLang ? ' active' : '');
      b.textContent = l.label;
      b.onclick = () => { sylLang = l.code; renderSyl(); };
      lr.appendChild(b);
    });
  } else {
    lr.style.display = 'none';
  }
  const clean = sylData[sylLang] || '';
  document.getElementById('syl-content').innerHTML =
    clean ? `<div class="syl-body">${clean}</div>` :
      '<p style="color:#64748b;font-size:13px">No syllabus available.</p>';
}

function closeSyl(ev) {
  if (ev && ev.target !== document.getElementById('syl-modal')) return;
  document.getElementById('syl-modal').classList.remove('open');
}

let annPage = 1, annLoading = false, annDone = false, annLoaded = false;

async function loadAnn(page) {
  if (annLoading || annDone) return;
  annLoading = true;
  const list = document.getElementById('ann-list');
  if (page === 1) {
    const n = Math.max(3, Math.floor((window.innerHeight - 200) / 100));
    list.innerHTML = Array(n).fill('<div class="skel" style="height:90px;border-radius:12px;margin-bottom:12px"></div>').join('');
  }
  try {
    const data = await pw(`https://api.penpencil.co/v1/batches/${BATCH_ID}/announcement?page=${page}`);
    if (page === 1) list.innerHTML = '';
    if (data.success && data.data?.length) {
      data.data.forEach(item => {
        const card = document.createElement('div');
        card.className = 'ann-card';
        const iu = item.attachment ? item.attachment.baseUrl + item.attachment.key : '';
        card.innerHTML =
          `<div class="ann-head">
             <img class="ann-logo" src="https://static.pw.live/react-batches/assets/images/logo.png" alt="PW">
             <div class="ann-meta">
               <div class="ann-name">PW Team</div>
               <div class="ann-time">${relTime(item.updatedAt)}</div>
             </div>
           </div>
           <div class="ann-text">${linkify(item.announcement || '')}</div>
           ${iu ? `<img class="ann-img" src="${esc(iu)}" alt="">` : ''}`;
        list.appendChild(card);
      });
      annPage = page + 1;
    } else {
      annDone = true;
      if (page === 1) {
        list.innerHTML = '<p style="text-align:center;padding:40px;color:#64748b">No announcements yet.</p>';
      }
    }
  } catch {
    if (page === 1) {
      list.innerHTML = '<p style="text-align:center;padding:40px;color:#64748b">Failed to load.</p>';
    }
  } finally {
    annLoading = false;
  }
}

function switchTab(name, btn) {
  ['classes', 'khazana', 'tests', 'announcements'].forEach(n =>
    document.getElementById('panel-' + n).classList.remove('active')
  );
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
  if (name === 'khazana') renderKhazana();
  if (name === 'tests') loadTests();
  if (name === 'announcements' && !annLoaded) {
    annLoaded = true;
    loadAnn(1);
  }
}

window.addEventListener('scroll', () => {
  if (!document.getElementById('panel-announcements').classList.contains('active')) return;
  if (window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 100) {
    loadAnn(annPage);
  }
});

// Disable context menu / shortcuts
(function () {
  ['contextmenu', 'selectstart', 'dragstart', 'copy'].forEach(e =>
    document.addEventListener(e, ev => ev.preventDefault())
  );
  document.addEventListener('keydown', e => {
    if (
      e.key === 'F12' ||
      (e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key)) ||
      (e.ctrlKey && ['U', 'S'].includes(e.key))
    ) {
      e.preventDefault();
      return false;
    }
  });
})();

loadSchedule();
loadSubjects();
