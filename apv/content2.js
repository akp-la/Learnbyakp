
const QS=new URLSearchParams(location.search);
const BATCH_ID=QS.get('batchId')||'';
const SUBJECT_ID=QS.get('subjectId')||'';
const BATCH_NAME=QS.get('batchName')||'';
const SUBJECT_NAME=QS.get('subjectName')||'';

if(!BATCH_ID||!SUBJECT_ID)location.href='/study-v2/batches';

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function ep(v){return encodeURIComponent(v||'')}

document.getElementById('back-label').textContent=SUBJECT_NAME||'Subjects';
document.getElementById('sub-label').textContent=BATCH_NAME?`Batch: ${BATCH_NAME}`:'Chapters list';
document.getElementById('hero-title').textContent=SUBJECT_NAME
  ? `${SUBJECT_NAME} — Chapters`
  : 'Subject Chapters';

/* Theme toggle with localStorage */

const root=document.documentElement;
const themeToggle=document.getElementById('theme-toggle');
const themeEmoji=document.getElementById('theme-emoji');

function applyTheme(t){
  root.setAttribute('data-theme',t);
  themeEmoji.textContent=t==='dark'?'🌙':'🌞';
  localStorage.setItem('rs-theme',t);
}

(function initTheme(){
  const saved=localStorage.getItem('rs-theme');
  if(saved==='dark'||saved==='light'){
    applyTheme(saved);
  }else{
    const preferDark=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(preferDark?'dark':'light');
  }
})();

themeToggle.addEventListener('click',()=>{
  const current=root.getAttribute('data-theme')==='dark'?'dark':'light';
  applyTheme(current==='dark'?'light':'dark');
});

/* API config */

const PW_HDR={"Accept-Encoding": "gzip", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A707F Build/RP1A.200720.012)", "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODMxNTIxNDguOTg0LCJkYXRhIjp7Il9pZCI6IjY0YWQ4ODM5ZmU5ZTZhMDAxODRjMGI1ZSIsInVzZXJuYW1lIjoiOTU1OTk3NTM3MCIsImZpcnN0TmFtZSI6IkFrdWwiLCJsYXN0TmFtZSI6IlByYWphcGF0aSIsIm9yZ2FuaXphdGlvbiI6eyJfaWQiOiI1ZWIzOTNlZTk1ZmFiNzQ2OGE3OWQxODkiLCJ3ZWJzaXRlIjoicGh5c2ljc3dhbGxhaC5jb20iLCJuYW1lIjoiUGh5c2ljc3dhbGxhaCJ9LCJlbWFpbCI6ImFrdWxwcmFqYXBhdGkwMEBnbWFpbC5jb20iLCJyb2xlcyI6WyI1YjI3YmQ5NjU4NDJmOTUwYTc3OGM2ZWYiXSwiY291bnRyeUdyb3VwIjoiSU4iLCJvbmVSb2xlcyI6W10sInR5cGUiOiJVU0VSIn0sImp0aSI6IjNKeWtZOWFjVFQtZlQ3QlFOVXBJWWdfNjRhZDg4MzlmZTllNmEwMDE4NGMwYjVlIiwiaWF0IjoxNzgyNTQ3MzQ4fQ.ZljN2PqFVB9HNt-2fknXVDo0VO6rXp4WkrRaf8DF65g", "client-id": "ADMIN", "client-type": "MOBILE", "client-version": "538", "content-type": "application/json", "device-meta": "{\"APP_VERSION\":\"538\",\"APP_VERSION_NAME\":\"15.32.0\",\"DEVICE_MAKE\":\"Samsung\",\"DEVICE_MODEL\":\"SM-A707F\",\"OS_VERSION\":\"11\",\"PACKAGE_NAME\":\"xyz.penpencil.physicswala\",\"network\":\"wifi_data\",\"carrier\":\"UNDEFINED\"}", "randomid": "b8441281-cf24-4f70-8f70-164ed703d534", "referer": "https://android.pw.live"};


async function pw(url){
  return fetch(url,{headers:PW_HDR}).then(r=>r.json());
}

/* Pagination + load */

let page=1,loading=false,done=false;
const list=document.getElementById('ch-list');
const lsk=document.getElementById('load-skels');

function skelCount(){
  return Math.max(3,Math.floor((window.innerHeight-160)/80));
}

function showSkels(container){
  const n=skelCount();
  container.innerHTML=Array(n).fill('<div class="skel skel-ch"></div>').join('');
}

async function loadPage(){
  if(loading||done)return;
  loading=true;

  if(page===1){
    showSkels(list);
  }else{
    showSkels(lsk);
    lsk.style.display='block';
  }

  try{
    const data=await pw(`https://api.penpencil.co/v2/batches/${BATCH_ID}/subject/${SUBJECT_ID}/topics?page=${page}`);
    lsk.style.display='none';
    lsk.innerHTML='';
    if(page===1)list.innerHTML='';

    if(!data.success||!data.data?.length){
      done=true;
      if(page===1){
        list.innerHTML='<li class="empty-text">No chapters found</li>';
      }
      return;
    }

    data.data.forEach(ch=>{
      const li=document.createElement('li');
      li.className='chapter-item';
      li.innerHTML=
        `<a class="chapter-link" href="type?batchId=${ep(BATCH_ID)}&subjectId=${ep(SUBJECT_ID)}&chapterId=${ep(ch._id)}&batchName=${ep(BATCH_NAME)}&subjectName=${ep(SUBJECT_NAME)}&chapterName=${ep(ch.name)}&section=videos">
          <div class="chapter-content">
            <div class="chapter-name">${esc(ch.name)}</div>
            <div class="chapter-counts">
              ${(ch.videos||0)} Videos · ${(ch.exercises||0)} Exercises · ${(ch.notes||0)} Notes
            </div>
          </div>
          <span class="chapter-arrow">
            <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
          </span>
        </a>`;
      list.appendChild(li);
    });

    if(data.data.length<10)done=true;
    else page++;
  }catch(e){
    lsk.style.display='none';
    lsk.innerHTML='';
    if(page===1){
      list.innerHTML='<li class="empty-text">Failed to load chapters. Please try again.</li>';
    }
  }finally{
    loading=false;
  }
}

/* Infinite scroll */

window.addEventListener('scroll',()=>{
  if(window.scrollY+window.innerHeight>=document.documentElement.scrollHeight-150){
    loadPage();
  }
});

/* Block inspect / copy (same as original) */

(function(){
  ['contextmenu','selectstart','dragstart','copy'].forEach(e=>document.addEventListener(e,ev=>ev.preventDefault()));
  document.addEventListener('keydown',e=>{
    if(
      e.key==='F12'||
      (e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))||
      (e.ctrlKey&&['U','S'].includes(e.key))
    ){
      e.preventDefault();
      return false;
    }
  });
})();

loadPage();
