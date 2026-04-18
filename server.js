// ================== IMPORTS ==================
const functions = require("firebase-functions/v1"); // v1 import
const admin = require("firebase-admin");
const cors = require("cors");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const crypto = require("crypto");
const fetch = require("node-fetch");
const corsFn = cors();

const BASE = "https://apiserver-m8ea.onrender.com";
const rateLimit = require("express-rate-limit");
const app = express();
app.use(rateLimit({ windowMs: 60 * 1000, max: 30 }));
//  Use node-fetch via dynamic import (for proxy routes)
const fetchfn = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

// ================== FIREBASE INIT ================== 
if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
const COL = db.collection("studyData");
const ADMIN_PWD = process.env.ADMIN_PWD || "992jaa";

// ================== CORS HELPER FOR /data ==================
const MAIL_TM_BASE = "https://api.mail.tm";

app.use(cors());
app.use(express.json());

async function proxy(req, res) {
  try {
    const targetPath = req.originalUrl.replace(/^\/api\/tempmail/, "");
    const url = `${MAIL_TM_BASE}${targetPath}`;

    const response = await fetch(url, {
      method: req.method,
      headers: {
        Accept: "application/json",
        ...(req.headers.authorization
          ? { Authorization: req.headers.authorization }
          : {}),
        ...(req.method !== "GET" && req.method !== "HEAD"
          ? { "Content-Type": "application/json" }
          : {})
      },
      body:
        req.method !== "GET" && req.method !== "HEAD"
          ? JSON.stringify(req.body || {})
          : undefined
    });

    const text = await response.text();
    const contentType =
      response.headers.get("content-type") || "application/json";

    res.status(response.status);
    res.setHeader("Content-Type", contentType);
    res.send(text);
  } catch (error) {
    res.status(500).json({
      error: true,
      message: error.message
    });
  }
}

app.all("/api/tempmail", proxy);
app.all("/api/tempmail/*", proxy);

app.get("/", (req, res) => {
  res.json({
    ok: true,
    api: "/api/tempmail"
  });
});


//=====================etertert=================
const allowedOrigins = [
  "https://learnbyakp.onrender.com",
  "https://learnbyakp.online",
  "https://studyakp-d8cfa.web.app"
];

const corsOptions = {
  origin(origin, callback) {
    if (!origin || origin === "null") return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(null, false);
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // preflight handle

app.use(express.json());
app.use(corsFn);
// ================== DATA HELPER (DELETE COLLECTION) ==================
async function deleteCollection(db, collectionPath, batchSize = 300) {
  const collectionRef = db.collection(collectionPath);
  const query = collectionRef.orderBy("__name__").limit(batchSize);

  return new Promise((resolve, reject) => {
    deleteQueryBatch(db, query, resolve).catch(reject);
  });
}

async function deleteQueryBatch(db, query, resolve) {
  const snapshot = await query.get();
  const batchSize = snapshot.size;
  if (batchSize === 0) {
    resolve();
    return;
  }

  const batch = db.batch();
  snapshot.docs.forEach((doc) => batch.delete(doc.ref));
  await batch.commit();

  process.nextTick(() => {
    deleteQueryBatch(db, query, resolve);
  });
}


// ================== AUTH / EXPRESS APP ==================
const JWT_SECRET = process.env.JWT_SECRET || "SUPER_SECRET_CHANGE_ME";
const TWOFACTOR_API_KEY =
  process.env.TWOFACTOR_API_KEY || "40cc9d6e-cc55-11f0-a6b2-0200cd936042";
const EMAIL_SERVICE_API_KEY =
  process.env.EMAIL_SERVICE_API_KEY ||
  "re_4GdgW5h3_5u8fTxA1oeQv4PxGZprdcLTJ";

const users = new Map();
const emailOtpStore = new Map();
const OTP_EXPIRY_MS = 5 * 60 * 1000;

// Helpers
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Auth middlewares
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid/expired token" });
    }
    req.user = user;
    next();
  });
}

function authenticateAdmin(req, res, next) {
  authenticateToken(req, res, () => {
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Admin access required" });
    }
    next();
  });
}

// ================== EMAIL HTML HELPERS ==================
function emailOtpHtml(otp) {
  return `
  <div style="
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background:#0f172a;
    padding:24px;
  ">
    <div style="
      max-width:480px;
      margin:0 auto;
      background:#020617;
      border-radius:18px;
      padding:24px 24px 28px;
      border:1px solid rgba(148,163,184,0.2);
      box-shadow:0 18px 40px rgba(15,23,42,0.8);
      color:#e5e7eb;
    ">
      <div style="text-align:center;margin-bottom:20px;">
        <div style="
          display:inline-flex;
          align-items:center;
          justify-content:center;
          width:52px;
          height:52px;
          border-radius:999px;
          background:radial-gradient(circle at 30% 30%, #22c55e, #0f172a);
          box-shadow:0 0 20px rgba(34,197,94,0.7);
          font-size:26px;
        ">✉️</div>
      </div>
      <h1 style="
        font-size:22px;
        margin:0 0 8px;
        text-align:center;
        letter-spacing:-0.02em;
        background:linear-gradient(135deg,#22c55e,#4ade80);
        -webkit-background-clip:text;
        -webkit-text-fill-color:transparent;
      ">
        Email verification
      </h1>
      <p style="
        font-size:14px;
        line-height:1.6;
        color:#9ca3af;
        text-align:center;
        margin:0 0 18px;
      ">
        Use this one‑time code to verify your email on
        <strong style="color:#e5e7eb;">LearnByAKP.online</strong>.
      </p>
      <div style="
        margin:18px 0 20px;
        padding:14px 16px;
        border-radius:14px;
        background:rgba(15,23,42,0.9);
        border:1px solid rgba(34,197,94,0.5);
        text-align:center;
      ">
        <div style="font-size:12px;color:#9ca3af;margin-bottom:6px;">
          Your verification code
        </div>
        <div style="
          font-size:28px;
          letter-spacing:0.35em;
          font-weight:700;
          color:#e5e7eb;
        ">
          ${otp}
        </div>
      </div>
      <p style="
        font-size:13px;
        color:#9ca3af;
        margin:0 0 4px;
      ">
        This code is valid for <strong style="color:#e5e7eb;">5 minutes</strong>.
      </p>
      <p style="
        font-size:12px;
        color:#6b7280;
        margin:0 0 18px;
      ">
        If you did not request this, you can safely ignore this email.
      </p>
      <hr style="border:none;border-top:1px solid rgba(31,41,55,0.9);margin:18px 0 12px;">
      <p style="
        font-size:11px;
        color:#4b5563;
        text-align:center;
      ">
        Learn by AKP · Account Verification
      </p>
    </div>
  </div>
  `;
}

// Registration email template
function registerOtpHtml(otp) {
  return `
  <div style="
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background:#020617;
    padding:24px;
  ">
    <div style="
      max-width:480px;
      margin:0 auto;
      background:radial-gradient(circle at top, rgba(55,65,81,0.9), #020617);
      border-radius:18px;
      padding:24px 24px 28px;
      border:1px solid rgba(148,163,184,0.3);
      box-shadow:0 20px 45px rgba(15,23,42,0.9);
      color:#e5e7eb;
    ">
      <div style="text-align:center;margin-bottom:18px;">
        <div style="
          display:inline-flex;
          align-items:center;
          justify-content:center;
          width:52px;
          height:52px;
          border-radius:999px;
          background:radial-gradient(circle at 30% 30%, #22c55e, #15803d);
          box-shadow:0 0 22px rgba(34,197,94,0.8);
          font-size:26px;
        ">✅</div>
      </div>
      <h1 style="
        font-size:22px;
        margin:0 0 6px;
        text-align:center;
        letter-spacing:-0.02em;
        background:linear-gradient(135deg,#22c55e,#4ade80,#a3e635);
        -webkit-background-clip:text;
        -webkit-text-fill-color:transparent;
      ">
        Verify your email
      </h1>
      <p style="
        font-size:14px;
        line-height:1.7;
        color:#cbd5f5;
        text-align:center;
        margin:0 0 18px;
      ">
        Complete your registration on
        <strong style="color:#e5e7eb;">LearnByAKP.online</strong> using the
        one‑time code below.
      </p>
      <div style="
        margin:18px 0 20px;
        padding:16px 18px;
        border-radius:16px;
        background:rgba(15,23,42,0.95);
        border:1px solid rgba(34,197,94,0.6);
        text-align:center;
      ">
        <div style="font-size:12px;color:#9ca3af;margin-bottom:6px;">
          Your verification code
        </div>
        <div style="
          font-size:30px;
          letter-spacing:0.35em;
          font-weight:700;
          color:#f9fafb;
        ">
          ${otp}
        </div>
      </div>
      <p style="
        font-size:13px;
        color:#9ca3af;
        margin:0 0 4px;
      ">
        Code is valid for <strong style="color:#e5e7eb;">5 minutes</strong>.
      </p>
      <p style="
        font-size:12px;
        color:#6b7280;
        margin:0 0 18px;
      ">
        If you did not try to sign up, you can ignore this email and your address will not be used.
      </p>
      <hr style="border:none;border-top:1px solid rgba(31,41,55,0.9);margin:18px 0 12px;">
      <p style="
        font-size:11px;
        color:#4b5563;
        text-align:center;
      ">
        Learn by AKP · Account Registration
      </p>
    </div>
  </div>
  `;
}

// Reset password email template
function resetOtpHtml(otp) {
  return `
  <div style="
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background:#0f172a;
    padding:24px;
  ">
    <div style="
      max-width:480px;
      margin:0 auto;
      background:#020617;
      border-radius:18px;
      padding:24px 24px 28px;
      border:1px solid rgba(148,163,184,0.2);
      box-shadow:0 18px 40px rgba(15,23,42,0.8);
      color:#e5e7eb;
    ">
      <div style="text-align:center;margin-bottom:20px;">
        <div style="
          display:inline-flex;
          align-items:center;
          justify-content:center;
          width:52px;
          height:52px;
          border-radius:999px;
          background:radial-gradient(circle at 30% 30%, #4f46e5, #0f172a);
          box-shadow:0 0 20px rgba(79,70,229,0.7);
          font-size:26px;
        ">🔐</div>
      </div>
      <h1 style="
        font-size:22px;
        margin:0 0 8px;
        text-align:center;
        letter-spacing:-0.02em;
        background:linear-gradient(135deg,#a855f7,#6366f1);
        -webkit-background-clip:text;
        -webkit-text-fill-color:transparent;
      ">
        Reset your password
      </h1>
      <p style="
        font-size:14px;
        line-height:1.6;
        color:#9ca3af;
        text-align:center;
        margin:0 0 18px;
      ">
        Use the one‑time verification code below to complete your password reset.
      </p>
      <div style="
        margin:18px 0 20px;
        padding:14px 16px;
        border-radius:14px;
        background:rgba(15,23,42,0.9);
        border:1px solid rgba(129,140,248,0.4);
        text-align:center;
      ">
        <div style="font-size:12px;color:#9ca3af;margin-bottom:6px;">
          Your 6‑digit reset code
        </div>
        <div style="
          font-size:28px;
          letter-spacing:0.35em;
          font-weight:700;
          color:#e5e7eb;
        ">
          ${otp}
        </div>
      </div>
      <p style="
        font-size:13px;
        color:#9ca3af;
        margin:0 0 4px;
      ">
        This code is valid for <strong style="color:#e5e7eb;">5 minutes</strong>.
      </p>
      <p style="
        font-size:12px;
        color:#6b7280;
        margin:0 0 18px;
      ">
        If you did not request this, you can safely ignore this email.
      </p>
      <hr style="border:none;border-top:1px solid rgba(31,41,55,0.9);margin:18px 0 12px;">
      <p style="
        font-size:11px;
        color:#4b5563;
        text-align:center;
      ">
        Learn by AKP · Secure Access System
      </p>
    </div>
  </div>
  `;
}

// ================== CREATE EXPRESS APP ==================
function createApp() {
  const app = express();
  const corsMiddleware = cors({ origin: true });
   app.use(cors());
  app.use(corsMiddleware);
  app.use(express.json());

  // HEALTH CHECK
  app.get("/api/health", (req, res) => {
    res.json({ ok: true, env: process.env.NODE_ENV || "dev" });
  });
  //===========api start==
 app.get("/api/missionjeet/content-details", async (req, res) => {
  try {
    const entityId = req.query.content_id;
    const courseId = req.query.courseid;

    if (!entityId || !courseId) {
      return res.status(400).json({ error: "Missing content_id or courseid" });
    }

    const url = `https://apiserver-m8ea.onrender.com/api/missionjeet/content-details?content_id=${entityId}&course_id=${courseId}`;

    const response = await fetchfn(url);

    // ✅ check response ok or not
    if (!response.ok) {
      return res.status(response.status).json({
        error: `External API error: ${response.status}`
      });
    }

    const data = await response.json();

    res.json(data);

  } catch (err) {
    console.error("/api/missionjeet/content-details error:", err);
    res.status(500).json({ error: err.message });
  }
});
  //========ewrwerw===========
const KEY = Buffer.from("638udh3829162018");
const IV = Buffer.from("fedcba9876543210");

// 🔓 decrypt function
function decryptVibrant(input) {
  try {
    const encryptedPart = input.split(":")[0];

    const encryptedBuffer = Buffer.from(encryptedPart, "base64");

    const decipher = crypto.createDecipheriv("aes-128-cbc", KEY, IV);

    let decrypted = decipher.update(encryptedBuffer, "binary", "utf8");
    decrypted += decipher.final("utf8");

    // PKCS7 padding remove
    const padding = decrypted.charCodeAt(decrypted.length - 1);
    if (padding > 0 && padding <= 16) {
      decrypted = decrypted.slice(0, -padding);
    }

    return decrypted;
  } catch (err) {
    console.error("Decrypt error:", err);
    return null;
  }
}

// 🎬 PLAY API



//=============weqewqe==========

//======== rtrtrrttt=====
app.get("/api/vibrant/previous-live", async (req, res) => {
  try {
    const courseid = req.query.course_id || req.query.c;

    if (!courseid) {
      return res.status(400).json({ error: "Missing courseid" });
    }

    // External API call
    const url = `https://apiserver-m8ea.onrender.com/api/vibrant/previous-live?course_id=${courseid}`;
    
    const response = await fetchfn(url);

if (!response.ok) {
  return res.status(response.status).json({
    error: "External API failed"
  });
}

const data = await response.json();
res.json(data);
  } catch (err) {
    console.error("/api/vibrant/previous-live error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
  
//=========uwqeuiweyqi====
 app.get("/api/missionjeet/course-details", async (req, res) => {
  try {
    const courseid = req.query.courseid;

    if (!courseid) {
      return res.status(400).json({ error: "Missing courseid" });
    }

    // External API call
    const url = `https://apiserver-m8ea.onrender.com/api/missionjeet/course-details?courseid=${courseid}`;
    
    const response = await fetchfn(url);

if (!response.ok) {
  return res.status(response.status).json({
    error: "External API failed"
  });
}

const data = await response.json();
res.json(data);
  } catch (err) {
    console.error("/api/missionjeet/course-details error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
  const BASE_URL = "https://apiserver-m8ea.onrender.com";
//=============454534534==========
  app.post("/api/pw/login", async (req, res) => {
  try {
    const { phoneNumber, username } = req.body || {};

    if (!phoneNumber || !username) {
      return res.status(400).json({
        success: false,
        message: "phoneNumber and username are required"
      });
    }

    const upstream1 = await fetch(`${BASE_URL}/api/pw/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/plain, */*"
      },
      body: JSON.stringify({
        phoneNumber,
        username
      })
    });

    const text = await upstream1.text();

    res.status(upstream1.status);
    res.setHeader(
      "Content-Type",
      upstream1.headers.get("content-type") || "application/json"
    );
    return res.send(text);
  } catch (error) {
    console.error("PW LOGIN ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Proxy error in /api/pw/login"
    });
  }
});

// PW VERIFY
app.post("/api/pw/verify", async (req, res) => {
  try {
    const { otp, phoneNumber, username } = req.body || {};

    if (!otp || !phoneNumber || !username) {
      return res.status(400).json({
        success: false,
        message: "otp, phoneNumber and username are required"
      });
    }

    const upstream1 = await fetch(`${BASE_URL}/api/pw/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/plain, */*"
      },
      body: JSON.stringify({
        otp,
        phoneNumber,
        username
      })
    });

    const text = await upstream1.text();

    res.status(upstream1.status);
    res.setHeader(
      "Content-Type",
      upstream.headers.get("content-type") || "application/json"
    );
    return res.send(text);
  } catch (error) {
    console.error("PW VERIFY ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Proxy error in /api/pw/verify"
    });
  }
});
  
//============ attttttttt======
app.get("/api/missionjeet/all-content/:courseid", async (req, res) => {
  try {
    const { courseid } = req.params;
    const id = req.query.id || courseid;  // Default id to courseid if missing

    if (!courseid) {
      return res.status(400).json({ error: "Missing :courseid param" });
    }

    // Build external URL matching exact path pattern
    let externalUrl;
    if (id && id !== courseid) {
      externalUrl = `https://apiserver-m8ea.onrender.com/api/missionjeet/all-content/${courseid}?id=${id}`;
    } else {
      externalUrl = `https://apiserver-m8ea.onrender.com/api/missionjeet/all-content/${courseid}`;
    }

    const response = await fetchfn(externalUrl);
    if (!response.ok) {
      throw new Error(`External: ${response.status}`);
    }
    const data = await response.json();

    res.json(data);
  } catch (err) {
    console.error("/api/missionjeet/all-content error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
  // ========= YOUR TWO PROXY ROUTES =========

  // Endpoint for /api/batches
  app.get("/api/batches", async (req, res) => {
    try {
      const r = await fetchfn(
        "https://apiserver-m8ea.onrender.com/api/pw/batches"
      );
      const data = await r.json();
      res.json(data);
    } catch (e) {
      console.error("/api/batches error:", e);
      res.json({ error: e.toString() });
    }
  });
//===============ytryutuytyu======
    app.get("/api/vibrant/batches", async (req, res) => {
    try {
      const r = await fetchfn(
        "https://apiserver-m8ea.onrender.com/api/vibrant/batches"
      );
      const data = await r.json();
      res.json(data);
    } catch (e) {
      console.error("/api/vibrant/batches error:", e);
      res.json({ error: e.toString() });
    }
  });
  
//==============
 app.get("/api/vibrant/content", async (req, res) => {
  try {
    // 🔥 support both
    const course_id = req.query.course_id;
    const parent_id = req.query.parent_id || req.query.id;

    if (!course_id) {
      return res.status(400).json({
        status: 400,
        message: "Missing course_id"
      });
    }

    // 🔗 original API
    const url = new URL("https://apiserver-m8ea.onrender.com/api/vibrant/content");

    url.searchParams.set("course_id", course_id);

    // 👇 IMPORTANT: only send if exists
    if (parent_id) {
      url.searchParams.set("parent_id", parent_id);
    }

    const response = await fetchfn(url.toString());

    if (!response.ok) {
      throw new Error(`API failed: ${response.status}`);
    }

    const data = await response.json();

    // 🔥 normalize response
    res.json({
      status: 200,
      data: data.data || data,
      message: "success"
    });

  } catch (err) {
    console.error("API ERROR:", err);

    res.status(500).json({
      status: 500,
      message: err.message
    });
  }
});
  //==============uyutyutyuu
app.get("/api/vibrant/video-details", async (req, res) => {
  try {
    // Support both old (r/e) and new (courseid/id) param formats
    const video_id = req.query.D || req.query.video_id;
    const course_id = req.query.P || req.query.course_id;

    if (!course_id) {
      return res.status(400).json({ error: "Missing courseid (r or courseid)" });
    }

    const url = new URL("https://apiserver-m8ea.onrender.com/api/vibrant/video-details");
    url.searchParams.set("course_id", course_id);

    if (video_id) {
      url.searchParams.set("video_id", video_id);
    }

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    console.error("/api/vibrant/video-details error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
  
  //ddfddfdfdf=======
app.get("/api/nexttoppers/all-content", async (req, res) => {
  try {
    // Support both old (r/e) and new (courseid/id) param formats
    const courseid = req.query.r || req.query.courseid;
    const id = req.query.e || req.query.id;

    if (!courseid) {
      return res.status(400).json({ error: "Missing courseid (r or courseid)" });
    }

    const url = new URL("https://apiserver-m8ea.onrender.com/api/nexttoppers/all-content");
    url.searchParams.set("courseid", courseid);

    if (id) {
      url.searchParams.set("id", id);
    }

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    console.error("/api/nexttoppers/all-content error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
//-===============00-99
function buildCloudFrontUrl(pathOrUrl) {
  if (!pathOrUrl) return null;

  // already full URL
  if (/^https?:\/\//i.test(pathOrUrl)) {
    return pathOrUrl;
  }

  // normalize leading slash
  const clean = pathOrUrl.startsWith("/") ? pathOrUrl.slice(1) : pathOrUrl;

  return `https://liveclasses.cloud-front.in/live/${clean}`;
}

function guessContentType(fileOrUrl, upstreamType = "") {
  if (upstreamType && upstreamType !== "application/octet-stream") {
    return upstreamType;
  }

  const lower = (fileOrUrl || "").toLowerCase();

  if (lower.includes(".m3u8")) return "application/vnd.apple.mpegurl";
  if (lower.includes(".ts")) return "video/mp2t";
  if (lower.includes(".m4s")) return "video/iso.segment";
  if (lower.includes(".mp4")) return "video/mp4";
  if (lower.includes(".aac")) return "audio/aac";
  if (lower.includes(".mp3")) return "audio/mpeg";
  if (lower.includes(".key")) return "application/octet-stream";

  return "application/octet-stream";
}

function rewriteM3U8(body) {
  return body
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();

      if (!trimmed) return line;

      // comments/tags keep as is, but key URI rewrite separately below
      if (trimmed.startsWith("#EXT-X-KEY")) {
        return line.replace(/URI="([^"]+)"/, (_, uri) => {
          return `URI="/api/vibrant/live-file?file=${encodeURIComponent(uri)}"`;
        });
      }

      if (trimmed.startsWith("#")) return line;

      // segment / nested playlist / absolute URL -> proxy route
      return `/api/vibrant/live-file?file=${encodeURIComponent(trimmed)}`;
    })
    .join("\n");
}

/**
 * MASTER LIVE PLAYLIST
 * Example:
 * /api/vibrant/live-proxy?schedule=T_177461124062612850_Id
 */
app.get("/api/vibrant/live-proxy", async (req, res) => {
  try {
    const { schedule } = req.query;

    if (!schedule) {
      return res.status(400).json({ error: "Missing schedule" });
    }

    const targetUrl = `https://liveclasses.cloud-front.in/live/${schedule}_appxabr.m3u8`;
    console.log("LIVE MASTER TARGET:", targetUrl);

    const upstream = await fetchfn(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Referer": "https://liveclasses.cloud-front.in/",
        "Origin": "https://liveclasses.cloud-front.in"
      }
    });

    if (!upstream.ok) {
      const text = await upstream.text();
      console.error("LIVE MASTER FAIL:", upstream.status, text);
      return res
        .status(upstream.status)
        .send(text || "Failed to fetch live stream");
    }

    const contentType =
      upstream.headers.get("content-type") || "application/vnd.apple.mpegurl";

    const body = await upstream.text();
    const proxiedBody = rewriteM3U8(body);

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", contentType);

    return res.send(proxiedBody);
  } catch (err) {
    console.error("live-proxy error:", err);
    return res.status(500).json({
      error: err.message || "Proxy failed"
    });
  }
});

/**
 * SEGMENT / NESTED PLAYLIST / KEY FILE / ABSOLUTE URL
 * Example:
 * /api/vibrant/live-file?file=chunk_00001.ts
 * /api/vibrant/live-file?file=720p/index.m3u8
 * /api/vibrant/live-file?file=https://some-domain/file.m3u8
 */
app.all("/api/vibrant/live-file", async (req, res) => {
  try {
    const { file } = req.query;

    if (!file) {
      return res.status(400).json({ error: "Missing file" });
    }

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");

    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }

    const targetUrl = buildCloudFrontUrl(file);
    console.log("LIVE FILE TARGET:", targetUrl);

    const upstream = await fetchfn(targetUrl, {
      method: req.method === "HEAD" ? "HEAD" : "GET",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Referer": "https://liveclasses.cloud-front.in/",
        "Origin": "https://liveclasses.cloud-front.in"
      }
    });

    if (!upstream.ok) {
      const text = req.method === "HEAD" ? "" : await upstream.text();
      console.error("LIVE FILE FAIL:", upstream.status, text);
      return res
        .status(upstream.status)
        .send(text || "Failed to fetch segment/file");
    }

    const upstreamType = upstream.headers.get("content-type") || "";
    const finalType = guessContentType(file, upstreamType);

    res.setHeader("Content-Type", finalType);

    const contentLength = upstream.headers.get("content-length");
    if (contentLength) {
      res.setHeader("Content-Length", contentLength);
    }

    const cacheControl = upstream.headers.get("cache-control");
    if (cacheControl) {
      res.setHeader("Cache-Control", cacheControl);
    } else {
      res.setHeader("Cache-Control", "no-store");
    }

    const acceptRanges = upstream.headers.get("accept-ranges");
    if (acceptRanges) {
      res.setHeader("Accept-Ranges", acceptRanges);
    }

    if (req.method === "HEAD") {
      return res.status(200).end();
    }

    // nested playlist ko rewrite karo
    if (
      finalType.includes("mpegurl") ||
      String(file).toLowerCase().includes(".m3u8")
    ) {
      const body = await upstream.text();
      const proxiedBody = rewriteM3U8(body);
      return res.send(proxiedBody);
    }

    // बाकी binary files
    const buffer = Buffer.from(await upstream.arrayBuffer());
    return res.send(buffer);
  } catch (err) {
    console.error("live-file error:", err);
    return res.status(500).json({
      error: err.message || "Segment proxy failed"
    });
  }
});
  //======live of mission jeet=====
  app.get("/api/missionjeet/live", async (req, res) => {
  try {
    const response = await fetch(
      "https://apiserver-m8ea.onrender.com/api/missionjeet/live",
      {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0",
          "Accept": "application/json",
          "Origin": "https://learnbyakp.onrender.com",
          "Referer": "https://learnbyakp.onrender.com/"
        }
      }
    );

    const text = await response.text();

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/json");

    res.status(response.status).send(text);

  } catch (error) {
    console.error("LIVE API ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch live classes"
    });
  }
});
  
  //====================asdasdasd============
app.get("/api/nexttoppers/live", async (req, res) => {
  try {
    const response = await fetch(
      "https://apiserver-m8ea.onrender.com/api/nexttoppers/live",
      {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0",
          "Accept": "application/json",
          "Origin": "https://learnbyakp.onrender.com",
          "Referer": "https://learnbyakp.onrender.com/"
        }
      }
    );

    const text = await response.text();

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/json");

    res.status(response.status).send(text);

  } catch (error) {
    console.error("LIVE API ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch live classes"
    });
  }
});

  //==========live api for nexttoppers======
  app.all("/api/vibrant/play", async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).send("Missing url");

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");

    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }

    const proxyUrl =
      "https://apiserver-m8ea.onrender.com/api/vibrant/play?url=" +
      encodeURIComponent(url);

    const upstream = await fetchfn(proxyUrl, {
      method: req.method === "HEAD" ? "HEAD" : "GET",
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }
    });

    if (!upstream.ok) {
      const text = req.method === "HEAD" ? "" : await upstream.text();
      console.error("deltaserver failed:", upstream.status, text);
      return res.status(upstream.status).send(text || "Failed to fetch video");
    }

    let contentType = upstream.headers.get("content-type") || "";

    // Agar upstream content-type weak ho, to URL se guess karo
    if (!contentType || contentType.includes("application/octet-stream")) {
      if (url.includes(".m3u8")) {
        contentType = "application/x-mpegURL";
      } else if (url.includes(".mpd")) {
        contentType = "application/dash+xml";
      } else if (url.includes(".ts")) {
        contentType = "video/mp2t";
      } else {
        contentType = "application/octet-stream";
      }
    }

    res.setHeader("Content-Type", contentType);

    const contentLength = upstream.headers.get("content-length");
    if (contentLength) res.setHeader("Content-Length", contentLength);

    const acceptRanges = upstream.headers.get("accept-ranges");
    if (acceptRanges) res.setHeader("Accept-Ranges", acceptRanges);

    const cacheControl = upstream.headers.get("cache-control");
    if (cacheControl) res.setHeader("Cache-Control", cacheControl);

    // HEAD request me body mat bhejo, bas headers bhejo
    if (req.method === "HEAD") {
      return res.status(200).end();
    }

    const buffer = await upstream.arrayBuffer();
    return res.status(200).send(Buffer.from(buffer));
  } catch (err) {
    console.error("/api/vibrant/play error:", err);
    return res.status(500).send("Failed to fetch video");
  }
});

  


  
  //jkdsyututyt======
  app.get("/api/nexttoppers/course-details", async (req, res) => {
  try {
    const courseid = req.query.courseid;

    if (!courseid) {
      return res.status(400).json({ error: "Missing courseid" });
    }

    // External API call
    const url = `https://apiserver-m8ea.onrender.com/api/nexttoppers/course-details?courseid=${courseid}`;
    
   const response = await fetchfn(url);

if (!response.ok) {
  return res.status(response.status).json({
    error: "External API failed"
  });
}

const data = await response.json();
res.json(data);
  } catch (err) {
    console.error("/api/nexttoppers/course-details error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
//tetyryr ytyu========
app.get("/api/nexttoppers/content-details", async (req, res) => {
  try {
    const entityId = req.query.content_id;
    const courseId = req.query.courseid;

    if (!entityId || !courseId) {
      return res.status(400).json({ error: "Missing content_id or courseid" });
    }

    const url = `https://apiserver-m8ea.onrender.com/api/nexttoppers/content-details?content_id=${entityId}&courseid=${courseId}`;

    const response = await fetchfn(url);

if (!response.ok) {
  return res.status(response.status).json({
    error: "External API failed"
  });
}



    // ✅ check response ok or not
    if (!response.ok) {
      return res.status(response.status).json({
        error: `External API error: ${response.status}`
      });
    }

    const data = await response.json();

    res.json(data);

  } catch (err) {
    console.error("/api/nexttoppers/content-details error:", err);
    res.status(500).json({ error: err.message });
  }
});


  // Endpoint for /api/nexttoppers/batches
 app.get("/api/nexttoppers/drm", async (req, res) => {
  try {
    const { videoid } = req.query;

    if (!videoid) {
      return res.status(400).json({ error: "videoid is required" });
    }

    const upstream = `https://apiserver-henna.vercel.app/api/nexttoppers/getVideoDetailsDrm?videoid=${encodeURIComponent(videoid)}`;

    const response = await fetch(upstream, {
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Referer": "https://course.nexttoppers.com/"
      }
    });

    const text = await response.text();

    res.status(response.status).send(text);
  } catch (err) {
    console.error("DRM proxy error:", err);
    res.status(500).json({ error: "Proxy failed" });
  }
});
 
// Endpoint for /api/jeet/batches
  app.get("/api/missionjeet/batches", async (req, res) => {
    try {
      const r = await fetchfn(
        "https://apiserver-m8ea.onrender.com/api/missionjeet/batches"
      );
      const data = await r.json();
      res.json(data);
    } catch (e) {
      console.error("/api/missionjeet/batches error:", e);
      res.json({ error: e.toString() });
    }
  });

  // Endpoint for /api/pw/li

//=============pw batch details
const UPSTREAM = "https://apiserver-m8ea.onrender.com";

app.post("/api/pw/live", async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  try {
    const batchId = req.body?.batchId;

    if (!batchId) {
      return res.status(400).json({
        success: false,
        message: "batchId required",
      });
    }

    const upstream = await fetchfn(`${UPSTREAM}/api/pw/live`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({ batchId }),
    });

    const text = await upstream.text();

    console.log("LIVE upstream status:", upstream.status);
    console.log("LIVE upstream body:", text);

    if (!upstream.ok) {
      return res.status(upstream.status).send(text);
    }

    res.setHeader("Content-Type", "application/json");
    return res.send(text);
  } catch (err) {
    console.error("live route error:", err);
    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});

app.options("/api/pw/live", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return res.sendStatus(204);
});

/**
 * 2) BATCH DETAILS API
 * Page expects:
 * POST /api/pw/batchdetails
 * body: { searchParams: { BatchId: "..." } }
 */
app.post("/api/pw/batchdetails", async (req, res) => {
  try {
    const batchId = req.body?.searchParams?.BatchId;

    if (!batchId) {
      return res.status(400).json({
        success: false,
        message: "searchParams.BatchId required",
      });
    }

    const upstream1 = await fetchfn(`https://apiserver-henna.vercel.app/api/pw/batchdetails`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        searchParams: {
          BatchId: batchId,
        },
      }),
    });

    const text = await upstream1.text();

    if (!upstream1.ok) {
      console.error("batchdetails upstream error:", upstream1.status, text);
      return res.status(upstream1.status).send(text);
    }

    res.setHeader("Content-Type", "application/json");
    return res.send(text);
  } catch (err) {
    console.error("batchdetails route error:", err);
    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});
/**
 * Optional health check
 */
app.get("/api/test", (req, res) => {
  res.json({ ok: true });
});

  // Endpoint for /api/pw/topics
app.get("/api/pw/topics", async (req, res) => {
  return proxyGet(req, res, "/api/pw/topics", {
    BatchId: "BatchId",
    SubjectId: "SubjectId",
  });
});
  //============dasdddd=====
  async function proxyJson(req, res, targetUrl, extraHeaders = {}) {
  try {
    const upstream = await fetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/plain, */*",
        ...extraHeaders,
      },
    });

    const contentType = upstream.headers.get("content-type") || "";
    const text = await upstream.text();

    res.status(upstream.status);
    if (contentType) res.setHeader("Content-Type", contentType);
    return res.send(text);
  } catch (err) {
    console.error("Proxy error:", err);
    return res.status(500).json({
      success: false,
      error: err.message || "Proxy request failed",
    });
  }
}

/**
 * 1) /api/pw/video
 * frontend call:
 * /api/pw/video?batchId=...&subjectId=...&childId=...
 */
app.get("/api/pw/video", async (req, res) => {
  const { batchId, subjectId, childId } = req.query;

  if (!batchId || !subjectId || !childId) {
    return res.status(400).json({
      success: false,
      error: "Missing batchId, subjectId, or childId",
    });
  }

  const url =
    `${UPSTREAM}/api/pw/video?batchId=${encodeURIComponent(batchId)}` +
    `&subjectId=${encodeURIComponent(subjectId)}` +
    `&childId=${encodeURIComponent(childId)}`;

  return proxyJson(req, res, url);
});

/**
 * 2) /api/pw/videoplay
 * frontend call:
 * /api/pw/videoplay?batchId=...&subjectId=...&childId=...
 */
app.get("/api/pw/videoplay", async (req, res) => {
  const { batchId, subjectId, childId } = req.query;

  if (!batchId || !subjectId || !childId) {
    return res.status(400).json({
      success: false,
      error: "Missing batchId, subjectId, or childId",
    });
  }

  const url =
    `${UPSTREAM}/api/pw/videoplay?batchId=${encodeURIComponent(batchId)}` +
    `&subjectId=${encodeURIComponent(subjectId)}` +
    `&childId=${encodeURIComponent(childId)}`;

  return proxyJson(req, res, url);
});

/**
 * 3) /api/pw/get-url
 * frontend call:
 * /api/pw/get-url?batchId=...&subjectId=...&childId=...
 */
app.get("/api/pw/get-url", async (req, res) => {
  const { batchId, subjectId, childId } = req.query;

  if (!batchId || !subjectId || !childId) {
    return res.status(400).json({
      success: false,
      error: "Missing batchId, subjectId, or childId",
    });
  }

  const url =
    `${UPSTREAM}/api/pw/get-url?batchId=${encodeURIComponent(batchId)}` +
    `&subjectId=${encodeURIComponent(subjectId)}` +
    `&childId=${encodeURIComponent(childId)}`;

  return proxyJson(req, res, url);
});

/**
 * 4) /api/pw/attachments-url
 * frontend call:
 * /api/pw/attachments-url?BatchId=...&SubjectId=...&ContentId=...
 */
app.get("/api/pw/attachments-url", async (req, res) => {
  try {
    const { BatchId, SubjectId, ContentId } = req.query;

    if (!BatchId || !SubjectId || !ContentId) {
      return res.status(400).json({
        success: false,
        message: "BatchId, SubjectId and ContentId are required"
      });
    }

    const targetUrl =
      `https://apiserver-henna.vercel.app/api/pw/attachments-url` +
      `?BatchId=${encodeURIComponent(BatchId)}` +
      `&SubjectId=${encodeURIComponent(SubjectId)}` +
      `&ContentId=${encodeURIComponent(ContentId)}`;

    const response = await fetch(targetUrl, {
      headers: {
        accept: "application/json, text/plain, */*",
        "user-agent": "Mozilla/5.0"
      }
    });

    const text = await response.text();

    res.status(response.status);
    res.setHeader(
      "content-type",
      response.headers.get("content-type") || "application/json"
    );
    return res.send(text);
  } catch (error) {
    console.error("attachments-url proxy error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch attachments-url",
      error: error.message
    });
  }
});

app.get("/api/pw/attachment-link", async (req, res) => {
  try {
    const batchId = req.query.batchId || req.query.BatchId;
    const subjectId = req.query.subjectId || req.query.SubjectId;
    const scheduleId = req.query.scheduleId || req.query.ContentId || req.query.schedule_id;

    if (!batchId || !subjectId || !scheduleId) {
      return res.status(400).json({
        success: false,
        message: "batchId, subjectId and scheduleId are required"
      });
    }

    const targetUrl =
      `https://apiserver-henna.vercel.app/api/pw/attachment-link` +
      `?batchId=${encodeURIComponent(batchId)}` +
      `&subjectId=${encodeURIComponent(subjectId)}` +
      `&scheduleId=${encodeURIComponent(scheduleId)}`;

    const response = await fetch(targetUrl, {
      headers: {
        accept: "application/json, text/plain, */*",
        "user-agent": "Mozilla/5.0"
      }
    });

    const text = await response.text();

    res.status(response.status);
    res.setHeader(
      "content-type",
      response.headers.get("content-type") || "application/json"
    );
    return res.send(text);
  } catch (error) {
    console.error("attachment-link proxy error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch attachment-link",
      error: error.message
    });
  }
});

  
/**
 * 5) /api/pw/kid
 * frontend call:
 * /api/pw/kid?mpdUrl=...
 */
app.get("/api/pw/kid", async (req, res) => {
  const { mpdUrl } = req.query;

  if (!mpdUrl) {
    return res.status(400).json({
      success: false,
      error: "Missing mpdUrl",
    });
  }

  const url = `${UPSTREAM}/api/pw/kid?mpdUrl=${encodeURIComponent(mpdUrl)}`;
  return proxyJson(req, res, url);
});

/**
 * 6) /api/pw/otp
 * frontend call:
 * /api/pw/otp?kid=...
 */
app.get("/api/pw/otp", async (req, res) => {
  const { kid } = req.query;

  if (!kid) {
    return res.status(400).json({
      success: false,
      error: "Missing kid",
    });
  }

  const url = `${UPSTREAM}/api/pw/otp?kid=${encodeURIComponent(kid)}`;
  return proxyJson(req, res, url);
});


//===========corckes====
  function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

app.options("*", (req, res) => {
  setCors(res);
  res.sendStatus(204);
});

async function proxyGet(req, res, upstreamPath, queryMap = null) {
  try {
    setCors(res);

    const params = new URLSearchParams();

    if (queryMap) {
      for (const [from, to] of Object.entries(queryMap)) {
        const value = req.query[from];
        if (value !== undefined && value !== null && value !== "") {
          params.set(to, value);
        }
      }
    } else {
      for (const [key, value] of Object.entries(req.query)) {
        if (value !== undefined && value !== null && value !== "") {
          params.set(key, value);
        }
      }
    }

    const url = `${UPSTREAM}${upstreamPath}?${params.toString()}`;
    const upstream = await fetchfn(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0",
      },
    });

    const contentType = upstream.headers.get("content-type") || "application/json";
    const text = await upstream.text();

    if (!upstream.ok) {
      return res.status(upstream.status).type(contentType).send(text);
    }

    return res.status(200).type(contentType).send(text);
  } catch (err) {
    console.error(`Proxy error for ${upstreamPath}:`, err);
    return res.status(500).json({ success: false, message: err.message });
  }
}
  
//===========656567============
app.get("/api/pw/datacontent", async (req, res) => {
  return proxyGet(req, res, "/api/pw/datacontent", {
    batchId: "batchId",
    subjectSlug: "subjectSlug",
    topicSlug: "topicSlug",
    contentType: "contentType",
  });
});
// ================= HELPER =================
const safeFetch = async (url) => {
  const res = await fetchfn(url);
  if (!res.ok) throw new Error(`API Error: ${res.status}`);
  return res.json();
};
// ==========343=============

  
// ================= DATACONTENT =================
app.get("/api/pw/videonew", async (req, res) => {
  return proxyGet(req, res, "/api/pw/videonew", {
    batchId: "batchId",
    subjectId: "subjectId",
    childId: "childId",
  });
});
// ================= VIDEO COMBINED =================
app.get("/api/pw/videosuper", async (req, res) => {
  return proxyGet(req, res, "/api/pw/videosuper", {
    batchId: "batchId",
    childId: "childId",
  });
});

// ================= VIDEO PLAY =================

// ================= VIEW =================
app.get("/api/pw/view", async (req, res) => {
  try {
    setCors(res);

    const { url, filename } = req.query;
    if (!url) {
      return res.status(400).send("Missing url");
    }

    const upstream = await fetchfn(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0",
        Accept: "*/*",
      },
    });

    const contentType =
      upstream.headers.get("content-type") || "application/octet-stream";

    const buffer = await upstream.arrayBuffer();

    res.setHeader("Content-Type", contentType);
    if (filename) {
      res.setHeader("Content-Disposition", `inline; filename="${filename}"`);
    }
    return res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("view error:", err);
    return res.status(500).send(err.message);
  }
});

// ================= DOWNLOAD =================
app.get("/api/pw/download", async (req, res) => {
  try {
    setCors(res);

    const { url, filename } = req.query;
    if (!url) {
      return res.status(400).send("Missing url");
    }

    const upstream = await fetchfn(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0",
        Accept: "*/*",
      },
    });

    const contentType =
      upstream.headers.get("content-type") || "application/octet-stream";

    const buffer = await upstream.arrayBuffer();

    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename || "file"}"`
    );

    return res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("download error:", err);
    return res.status(500).send(err.message);
  }
});

// ================= ATTACHMENT LINKS =================


// ================= OTP =================

// ================= KID =================

  // ========== EMAIL OTP (GENERIC) ==========
  app.post("/api/send-email-otp", async (req, res) => {
    try {
      const { email } = req.body;
      if (!email) {
        return res
          .status(400)
          .json({ success: false, message: "Email required" });
      }

      const otp = generateOtp();
      const expiresAt = Date.now() + OTP_EXPIRY_MS;
      emailOtpStore.set(email, { otp, expiresAt });

      if (EMAIL_SERVICE_API_KEY) {
        await axios.post(
          "https://api.resend.com/emails",
          {
            from: "no-reply@learnbyakp.online",
            to: email,
            subject: "✅ Your Verification Code – Learn by AKP",
            html: emailOtpHtml(otp),
          },
          {
            headers: { Authorization: `Bearer ${EMAIL_SERVICE_API_KEY}` },
          }
        );
      } else {
        console.log(`EMAIL OTP for ${email}: ${otp}`);
      }

      return res.json({
        success: true,
        message: "Verification code sent to email, please check",
        emailSent: !!EMAIL_SERVICE_API_KEY,
      });
    } catch (e) {
      console.error("send-email-otp error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  app.post("/api/verify-email-otp", async (req, res) => {
    try {
      const { email, otp } = req.body;
      const stored = emailOtpStore.get(email);

      if (!stored || stored.expiresAt < Date.now()) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid or expired OTP" });
      }

      if (stored.otp !== otp) {
        return res
          .status(400)
          .json({ success: false, message: "Wrong OTP" });
      }

      emailOtpStore.delete(email);
      return res.json({ success: true, verified: true });
    } catch (e) {
      console.error("verify-email-otp error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  // ========== PHONE OTP via 2FACTOR ==========
  app.post("/api/send-otp", async (req, res) => {
    try {
      const { phone } = req.body;

      if (!phone || phone.length !== 10) {
        return res.status(400).json({
          success: false,
          message: "Invalid phone (10 digit required)",
        });
      }

      const url = `https://2factor.in/API/V1/${TWOFACTOR_API_KEY}/SMS/${phone}/AUTOGEN`;
      const apiRes = await axios.get(url);

      if (!apiRes.data || apiRes.data.Status !== "Success") {
        console.error("2Factor send error:", apiRes.data);
        return res
          .status(500)
          .json({ success: false, message: "OTP send failed" });
      }

      const sessionId = apiRes.data.Details;
      return res.json({
        success: true,
        message: "OTP sent via SMS",
        sessionId,
      });
    } catch (e) {
      console.error("send-otp error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  app.post("/api/verify-otp", async (req, res) => {
  try {
    const { sessionId, otp, phone } = req.body;

    if (!sessionId || !otp) {
      return res.status(400).json({
        success: false,
        message: "Missing sessionId/otp",
      });
    }

    // 🔐 Verify OTP from 2Factor
    const url = `https://2factor.in/API/V1/${TWOFACTOR_API_KEY}/SMS/VERIFY/${sessionId}/${otp}`;
    const apiRes = await axios.get(url);

    if (!apiRes.data || apiRes.data.Status !== "Success") {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // 📱 Normalize phone (ensure 91 prefix)
    let userPhone = phone;
    if (userPhone && !userPhone.startsWith("91")) {
      userPhone = "91" + userPhone;
    }

    // fallback (rare case)
    if (!userPhone) {
      userPhone = "91" + sessionId;
    }

    // 🔍 Check if user already exists
    let existingUser = Array.from(users.values()).find(
      (u) => u.phone === userPhone
    );

    let user;

    if (existingUser) {
      // ✅ Existing user login
      user = existingUser;
    } else {
      // 🆕 New user create
      user = {
        id: "phone-" + userPhone,
        name: "Student",
        phone: userPhone,
        loginType: "phone",
        role: "user",
        active: true,
        createdAt: new Date().toISOString(),
      };

      // 💾 SAVE USER (IMPORTANT FIX)
      users.set(userPhone, user);
    }

    // 🎟️ Generate token
    const token = generateToken({
      userId: user.id,
      phone: user.phone,
      role: user.role,
    });

    return res.json({
      success: true,
      token,
      user,
      isNewUser: !existingUser,
    });
  } catch (e) {
    console.error("verify-otp error:", e);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

  // ========== EMAIL REGISTER + VERIFY ==========
  app.post("/api/register-email", async (req, res) => {
    try {
      const { email, password, name } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ success: false, message: "Missing email/password" });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Password must be at least 6 characters",
        });
      }

      if (users.has(email)) {
        return res.status(400).json({
          success: false,
          message:
            "Email already registered(Bhai aapka email pahle se he registred hai",
        });
      }

      const otp = generateOtp();
      const expiresAt = Date.now() + OTP_EXPIRY_MS;

      emailOtpStore.set(email, {
        otp,
        expiresAt,
        action: "register",
        tempData: { password, name },
      });

      if (EMAIL_SERVICE_API_KEY) {
        await axios.post(
          "https://api.resend.com/emails",
          {
            from: "no-reply@learnbyakp.online",
            to: email,
            subject: "✨ Verify your email – Learn by AKP",
            html: registerOtpHtml(otp),
          },
          {
            headers: { Authorization: `Bearer ${EMAIL_SERVICE_API_KEY}` },
          }
        );
      } else {
        console.log(`REGISTER OTP for ${email}: ${otp}`);
      }

      return res.json({
        success: true,
        message:
          "Verification code sent to your registrated email. Enter OTP to complete registration.",
        nextStep: "verify-email",
      });
    } catch (e) {
      console.error("register-email error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  app.post("/api/complete-registration", async (req, res) => {
    try {
      const { email, otp } = req.body;
      const stored = emailOtpStore.get(email);

      if (
        !stored ||
        stored.action !== "register" ||
        stored.expiresAt < Date.now()
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid/expired verification",
        });
      }

      if (stored.otp !== otp) {
        return res
          .status(400)
          .json({ success: false, message: "Wrong OTP" });
      }

      const { password, name } = stored.tempData;
      const passwordHash = await bcrypt.hash(password, 10);

      const user = {
        id: "email-" + Date.now(),
        email,
        passwordHash,
        name: name || email.split("@")[0],
        loginType: "email",
        role: "user",
        createdAt: new Date().toISOString(),
        active: true,
      };

      users.set(email, user);
      emailOtpStore.delete(email);

      const token = generateToken({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      return res.json({
        success: true,
        message: "Registration completed",
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      });
    } catch (e) {
      console.error("complete-registration error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  // ========== EMAIL LOGIN ==========
  app.post("/api/login-email", async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ success: false, message: "Missing email/password" });
      }

      const user = users.get(email);
      if (!user) {
        return res
          .status(400)
          .json({ success: false, message: "User not found" });
      }

      if (!user.active) {
        return res
          .status(403)
          .json({ success: false, message: "User disabled" });
      }

      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) {
        return res
          .status(400)
          .json({ success: false, message: "Wrong password" });
      }

      const token = generateToken({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      return res.json({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          loginType: user.loginType,
        },
      });
    } catch (e) {
      console.error("login-email error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  // ========== FORGOT / RESET PASSWORD ==========
  app.post("/api/forgot-password", async (req, res) => {
    try {
      const { email } = req.body;
      const user = users.get(email);

      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "Email not found" });
      }

      const otp = generateOtp();
      const expiresAt = Date.now() + OTP_EXPIRY_MS;

      emailOtpStore.set(email, {
        otp,
        expiresAt,
        action: "reset-password",
      });

      if (EMAIL_SERVICE_API_KEY) {
        await axios.post(
          "https://api.resend.com/emails",
          {
            from: "no-reply@learnbyakp.online",
            to: email,
            subject: "🔐 Password Reset Code – Learn by AKP",
            html: resetOtpHtml(otp),
          },
          {
            headers: { Authorization: `Bearer ${EMAIL_SERVICE_API_KEY}` },
          }
        );
      } else {
        console.log(`RESET OTP for ${email}: ${otp}`);
      }

      return res.json({
        success: true,
        message: "Reset code sent to email",
      });
    } catch (e) {
      console.error("forgot-password error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  app.post("/api/reset-password", async (req, res) => {
    try {
      const { email, otp, newPassword } = req.body;
      const stored = emailOtpStore.get(email);

      if (
        !stored ||
        stored.action !== "reset-password" ||
        stored.expiresAt < Date.now()
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid/expired reset code",
        });
      }

      if (stored.otp !== otp) {
        return res
          .status(400)
          .json({ success: false, message: "Wrong OTP" });
      }

      const user = users.get(email);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      user.passwordHash = newPasswordHash;
      users.set(email, user);
      emailOtpStore.delete(email);

      return res.json({
        success: true,
        message: "Password reset successful",
      });
    } catch (e) {
      console.error("reset-password error:", e);
      return res
        .status(500)
        .json({ success: false, message: "Server error" });
    }
  });

  // ========== GOOGLE OAUTH ==========
  app.get("/api/auth/google", (req, res) => {
    const redirectUri = encodeURIComponent(
      `${req.protocol}://${req.get("host")}/api/auth/google/callback`
    );
    const clientId =
      "847746135637-lb9hik8u8ae10204sp9d0cj40ds2a755.apps.googleusercontent.com";
    const scope = encodeURIComponent("profile email");

    const googleAuthUrl =
      `https://accounts.google.com/o/oauth2/v2/auth` +
      `?client_id=${clientId}` +
      `&redirect_uri=${redirectUri}` +
      `&response_type=code` +
      `&scope=${scope}`;

    res.redirect(googleAuthUrl);
  });

  app.get("/api/auth/google/callback", async (req, res) => {
    try {
      const code = req.query.code;
      if (!code) {
        return res.status(400).json({ error: "No code received" });
      }

      const redirectUri = `${req.protocol}://${req.get(
        "host"
      )}/api/auth/google/callback`;

      const tokenResponse = await axios.post(
        "https://oauth2.googleapis.com/token",
        {
          code,
          client_id:
            "847746135637-lb9hik8u8ae10204sp9d0cj40ds2a755.apps.googleusercontent.com",
          client_secret: "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",
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
        }
      );

      const { access_token } = tokenResponse.data;

      const userInfo = await axios.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        {
          headers: { Authorization: `Bearer ${access_token}` },
        }
      );

      const { email, name, picture } = userInfo.data;
      let user = users.get(email);

      if (!user) {
        user = {
          id: "google-" + Date.now(),
          email,
          name,
          picture,
          loginType: "google",
          role: "user",
          active: true,
          createdAt: new Date().toISOString(),
        };
        users.set(email, user);
      }

      if (!user.active) {
        return res
          .status(403)
          .json({ success: false, message: "User disabled" });
      }

      const token = generateToken({
        userId: user.id,
        email: user.email,
        role: user.role,
      });

      res.redirect(
        `https://learnbyakp.online/login.html?token=${encodeURIComponent(
          token
        )}&user=${encodeURIComponent(JSON.stringify(user))}`
      );
    } catch (e) {
      console.error("Google callback error:", e.response?.data || e);
      res.status(500).json({ error: "Google auth failed" });
    }
  });

  // ========== PROTECTED ROUTES ==========
  app.get("/api/check-login", authenticateToken, (req, res) => {
    res.json({
      success: true,
      loggedIn: true,
      user: req.user,
      message: "User verified successfully",
    });
  });

  app.get("/api/user-profile", authenticateToken, (req, res) => {
  try {
    let fullUser = null;

    // 🔍 find user from memory (email users)
    if (req.user.email) {
      fullUser = users.get(req.user.email);
    }

    // 🔍 find user from phone users
    if (!fullUser && req.user.phone) {
      fullUser = Array.from(users.values()).find(
        (u) => u.phone === req.user.phone
      );
    }

    // ⚡ अगर user नहीं मिला तो token वाला return कर
    const userData = fullUser || req.user;

    return res.json({
      success: true,
      user: {
        id: userData.id || req.user.userId,
        name: userData.name || "Student",
        email: userData.email || null,
        phone: userData.phone || null,
        role: userData.role || "user",
        loginType: userData.loginType || "unknown",
        createdAt: userData.createdAt || null,
      },
      features: [
        "📺 Watch videos",
        "💾 Save progress",
        "⭐ Premium content",
      ],
    });
  } catch (err) {
    console.error("/api/user-profile error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

  // ========== ADMIN USER MANAGEMENT ==========
  app.get("/api/admin/users", authenticateAdmin, (req, res) => {
    const allUsers = Array.from(users.values());
    res.json({
      success: true,
      users: allUsers.map((u) => ({
        id: u.id,
        email: u.email,
        name: u.name,
        role: u.role,
        active: u.active,
        loginType: u.loginType,
        createdAt: u.createdAt,
      })),
    });
  });

  app.post("/api/admin/users/:action", authenticateAdmin, (req, res) => {
    const { email } = req.body;
    const user = users.get(email);
    const action = req.params.action;

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    switch (action) {
      case "delete":
        users.delete(email);
        break;
      case "disable":
        user.active = false;
        break;
      case "enable":
        user.active = true;
        break;
      case "promote":
        user.role = "admin";
        break;
      case "demote":
        user.role = "user";
        break;
      default:
        return res
          .status(400)
          .json({ success: false, message: "Invalid action" });
    }

    if (action !== "delete") {
      users.set(email, user);
    }

    return res.json({ success: true, message: `User ${action}d` });
  });

  // ========== LOGOUT ==========
  app.post("/api/logout", (req, res) => {
    return res.json({ success: true, message: "Logged out" });
  });

  return app;
}

// Express app instance (reuse)
const appInstance = createApp();

// Single Express function

  // ===== START SERVER FOR RENDER =====
const PORT = process.env.PORT || 3000;

appInstance.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
