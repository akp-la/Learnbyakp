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


const BASE = "https://deltaserver-vvcb.onrender.com";
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
const corsFn = cors({ origin: true });

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

    const url = `https://deltaserver-vvcb.onrender.com/api/missionjeet/content-details?content_id=${entityId}&course_id=${courseId}`;

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
  app.get("/api/vibrant/live", async (req, res) => {
  try {
    const courseid = req.query.course_id || req.query.c;

    if (!courseid) {
      return res.status(400).json({ error: "Missing courseid" });
    }

    // External API call
    const url = `https://deltaserver-vvcb.onrender.com/api/vibrant/live?course_id=${courseid}`;
    
    const response = await fetchfn(url);

if (!response.ok) {
  return res.status(response.status).json({
    error: "External API failed"
  });
}

const data = await response.json();
res.json(data);
  } catch (err) {
    console.error("/api/vibrant/live error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
//======== rtrtrrttt=====
app.get("/api/vibrant/previous-live", async (req, res) => {
  try {
    const courseid = req.query.course_id || req.query.c;

    if (!courseid) {
      return res.status(400).json({ error: "Missing courseid" });
    }

    // External API call
    const url = `https://deltaserver-vvcb.onrender.com/api/vibrant/previous-live?course_id=${courseid}`;
    
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
    const url = `https://deltaserver-vvcb.onrender.com/api/missionjeet/course-details?courseid=${courseid}`;
    
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
      externalUrl = `https://deltaserver-vvcb.onrender.com/api/missionjeet/all-content/${courseid}?id=${id}`;
    } else {
      externalUrl = `https://deltaserver-vvcb.onrender.com/api/missionjeet/all-content/${courseid}`;
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
        "https://deltaserver-vvcb.onrender.com/api/pw/batches"
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
        "https://deltaserver-vvcb.onrender.com/api/vibrant/batches"
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
    const url = new URL("https://deltaserver-vvcb.onrender.com/api/vibrant/content");

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

    const url = new URL("https://deltaserver-vvcb.onrender.com/api/vibrant/video-details");
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

    const url = new URL("https://deltaserver-vvcb.onrender.com/api/nexttoppers/all-content");
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
//==============2423432===

appInstance.all("/api/vibrant/play", async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).send("Missing url");

    res.setHeader("Access-Control-Allow-Origin", "*");

    if (req.method === "HEAD") {
      return res.status(200).end();
    }

    const proxyUrl =
      "https://deltaserver-vvcb.onrender.com/api/vibrant/play?url=" +
      encodeURIComponent(url);

    const upstream = await fetchfn(proxyUrl, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }
    });

    if (!upstream.ok) {
      const text = await upstream.text();
      console.error("deltaserver failed:", upstream.status, text);
      return res.status(upstream.status).send(text || "Failed to fetch video");
    }

    const contentType =
      upstream.headers.get("content-type") || "application/octet-stream";

    res.setHeader("Content-Type", contentType);

    const buffer = await upstream.arrayBuffer();
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("/api/vibrant/play error:", err);
    res.status(500).send("Failed to fetch video");
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
    const url = `https://deltaserver-vvcb.onrender.com/api/nexttoppers/course-details?courseid=${courseid}`;
    
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

    const url = `https://deltaserver-vvcb.onrender.com/api/nexttoppers/content-details?content_id=${entityId}&courseid=${courseId}`;

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
  app.get("/api/nexttoppers/batches", async (req, res) => {
    try {
      const r = await fetchfn(
        "https://deltaserver-vvcb.onrender.com/api/nexttoppers/batches"
      );
      const data = await r.json();
      res.json(data);
    } catch (e) {
      console.error("/api/nexttoppers/batches error:", e);
      res.json({ error: e.toString() });
    }
  });
 
// Endpoint for /api/jeet/batches
  app.get("/api/missionjeet/batches", async (req, res) => {
    try {
      const r = await fetchfn(
        "https://deltaserver-vvcb.onrender.com/api/missionjeet/batches"
      );
      const data = await r.json();
      res.json(data);
    } catch (e) {
      console.error("/api/missionjeet/batches error:", e);
      res.json({ error: e.toString() });
    }
  });

  // Endpoint for /api/pw/li
  app.get("/api/pw/lives", async (req, res) => {
    try {
      const r = await fetchfn(
        "https://deltaserver-vvcb.onrender.com/api/pw/lives"
      );
      const data = await r.json();
      res.json(data);
    } catch (e) {
      console.error("/api/pw/lives error:", e);
      res.json({ error: e.toString() });
    }
  });

  // Endpoint for /api/pw/topics
 app.get("/api/pw/topics", async (req, res) => {
  try {
    // 🔥 multiple param support (old + new)
    const BatchId = req.query.bid || req.query.BatchId;
    const SubjectId = req.query.su || req.query.SubjectId;

    // ❗ validation
    if (!BatchId || !SubjectId) {
      return res.status(400).json({
        error: "Missing BatchId (bid/BatchId) or SubjectId (su/SubjectId)"
      });
    }

    // 🔥 target API (deltaserver-vvcb)
    const url = new URL("https://deltaserver-vvcb.onrender.com/api/pw/topics");
    url.searchParams.set("BatchId", BatchId);
    url.searchParams.set("SubjectId", SubjectId);

    // 🔥 fetch data
    const response = await fetch(url.toString());
    const data = await response.json();

    res.json(data);

  } catch (err) {
    console.error("/api/pw/topics error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
//===========656567============
app.get("/api/pw/datacontent", async (req, res) => {
  try {
    // ✅ lowercase params lo
    const { batchId, subjectSlug, topicSlug, contentType } = req.query;

    const url = new URL(`${BASE}/api/pw/datacontent`);

    // ✅ SAME param names use karo jo working URL me hai
    if (batchId) url.searchParams.set("batchId", batchId);
    if (subjectSlug) url.searchParams.set("subjectSlug", subjectSlug);
    if (topicSlug) url.searchParams.set("topicSlug", topicSlug);
    if (contentType) url.searchParams.set("contentType", contentType);

    console.log("Final URL:", url.toString());

    const response = await fetchfn(url.toString(), {
      method: "GET",
      headers: {
        "accept": "application/json"
      }
    });

    const text = await response.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    // ✅ status bhi return karo debug ke liye
    res.json({
      status: response.status,
      data
    });

  } catch (err) {
    console.error("datacontent error:", err);
    res.status(500).json({ error: err.message });
  }
});
// ================= HELPER =================
const safeFetch = async (url) => {
  const res = await fetchfn(url);
  if (!res.ok) throw new Error(`API Error: ${res.status}`);
  return res.json();
};
// ==========343=============
app.get("/api/pw/video", async (req, res) => {
  try {
    const batchId = req.query.batchId || req.query.bid;
    const subjectId = req.query.subjectId || req.query.su;
    const childId = req.query.childId || req.query.childid;

    if (!batchId || !subjectId) {
      return res.status(400).json({ error: "Missing batchId or subjectId" });
    }

    const url = new URL(`${BASE}/api/pw/video`);
    url.searchParams.set("batchId", batchId);
    url.searchParams.set("subjectId", subjectId);
    if (childId) url.searchParams.set("childId", childId);

    console.log("VIDEO URL:", url.toString());

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    console.error("video error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
// ================= DATACONTENT =================
app.get("/api/pw/videonew", async (req, res) => {
  try {
    const batchId = req.query.batchId || req.query.bid;
    const subjectId = req.query.subjectId || req.query.su;
    const childId = req.query.childId || req.query.childid;

    if (!batchId || !subjectId) {
      return res.status(400).json({ error: "Missing batchId or subjectId" });
    }

    const url = new URL(`${BASE}/api/pw/videonew`);
    url.searchParams.set("batchId", batchId);
    url.searchParams.set("subjectId", subjectId);
    if (childId) url.searchParams.set("childId", childId);

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});
// ================= VIDEO COMBINED =================
app.get("/api/pw/videosuper", async (req, res) => {
  try {
    const batchId = req.query.batchId || req.query.bid;
    const childId = req.query.childId || req.query.childid;

    if (!batchId || !childId) {
      return res.status(400).json({ error: "Missing batchId or childId" });
    }

    const url = new URL(`${BASE}/api/pw/videosuper`);
    url.searchParams.set("batchId", batchId);
    url.searchParams.set("childId", childId);

    console.log("VIDEOSUPER URL:", url.toString());

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});

// ================= VIDEO PLAY =================
app.get("/api/pw/videoplay", async (req, res) => {
  try {
    const batchId = req.query.batchId || req.query.bid;
    const childId = req.query.childId || req.query.childid;

    if (!batchId || !childId) {
      return res.status(400).json({ error: "Missing batchId or childId" });
    }

    const url = new URL(`${BASE}/api/pw/videoplay`);
    url.searchParams.set("batchId", batchId);
    url.searchParams.set("childId", childId);

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});
// ================= ATTACHMENTS =================
app.get("/api/pw/attachments", async (req, res) => {
  try {
    // 🔥 auto लेने वाला (multiple formats support)
    const batchId =
      req.query.batchId ||
      req.query.bid ||
      req.query.BatchId;

    const subjectId =
      req.query.subjectId ||
      req.query.sid ||
      req.query.SubjectId;

    const scheduleId =
      req.query.scheduleId ||
      req.query.cid ||
      req.query.ContentId ||
      req.query.schedule_id;

    if (!batchId || !subjectId || !scheduleId) {
      return res.status(400).json({
        error: "Missing params",
        received: { batchId, subjectId, scheduleId }
      });
    }

    const urls = [
      `${BASE}/api/pw/attachments-url?BatchId=${batchId}&SubjectId=${subjectId}&ContentId=${scheduleId}`
      
    ];

    let debug = [];

    for (let u of urls) {
      try {
        console.log("Trying:", u);

        const data = await safeFetch(u);

        if (data?.data || data?.success) {
          return res.json({
            source: u,
            result: data
          });
        }

        debug.push({ url: u, status: "no data" });

      } catch (err) {
        debug.push({ url: u, error: err.message });
      }
    }

    res.status(404).json({
      error: "No attachment found",
      tried: debug
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ================= VIEW =================
app.get("/api/pw/view", (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send("Missing URL");

  res.redirect(url);
});


// ================= DOWNLOAD =================
app.get("/api/pw/download", async (req, res) => {
  try {
    const { url, filename } = req.query;

    if (!url) return res.status(400).send("Missing URL");

    const response = await fetchfn(url);

if (!response.ok) {
  return res.status(response.status).json({
    error: "External API failed"
  });
}



    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename || "file"}"`
    );

   const buffer = await response.arrayBuffer();
res.send(Buffer.from(buffer));

  } catch (err) {
    res.status(500).send(err.message);
  }
});


// ================= ATTACHMENT LINKS =================
app.get("/api/pw/contents/attachment-links", async (req, res) => {
  try {
    const { batchId, subjectId, scheduleId } = req.query;

    const url = `${BASE}/api/pw/contents/attachment-links?batchId=${batchId}&subjectId=${subjectId}&scheduleId=${scheduleId}`;
     if (!batchId || !subjectId || !scheduleId) {
  return res.status(400).json({ error: "Missing params" });
}
    res.json(await safeFetch(url));

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ================= OTP =================
app.get("/api/pw/otp", async (req, res) => {
  try {
    const { kid } = req.query;

    const url = `${BASE}/api/pw/otp?kid=${kid}`;

    res.json(await safeFetch(url));

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ================= KID =================
app.get("/api/pw/kid", async (req, res) => {
  try {
    // 🔥 multiple param support (old + new)
    const BatchId = req.query.bid || req.query.BatchId;
    const ContentId = req.query.childid || req.query.ContentId;
    // ❗ validation
    if (!BatchId || !SubjectId) {
      return res.status(400).json({
        error: "Missing BatchId (bid/BatchId) or SubjectId (su/SubjectId)"
      });
    }

    // 🔥 target API (deltaserver-vvcb)
    const url = new URL("https://deltaserver-vvcb.onrender.com/api/pw/kid?mpdUrl=${encodeURIComponent(mpdUrl)}");

    // 🔥 fetch data
    const response = await fetch(url.toString());
    const data = await response.json();

    res.json(data);

  } catch (err) {
    console.error("/api/pw/kid error:", err);
    res.status(500).json({ error: err.toString() });
  }
}); 
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
