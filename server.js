// ================== IMPORTS ==================
const functions = require("firebase-functions/v1"); // v1 import
const admin = require("firebase-admin");
const cors = require("cors");
const express = require("express");
const jwt = require("jsonwebtoken");


const cloudscraper = require('cloudscraper');

const webpush = require("web-push");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const fetch = require("node-fetch");
const corsFn = cors();
const CHANGE = "https://apiserver.deltastudy.site";
const BASE = "https://apiserver.deltastudy.site";
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

//=====================etertert=================
const allowedOrigins = [
  "https://learnbyakp.onrender.com",
  "https://learnbyakp.online",
  "https://studyakp-d8cfa.web.app",
  "https://pw.notjitu.in",
  "https://notjitu.in"
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
//app



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
// nexttoppers 

const TARGET_URL = 'https://course.nexttoppers.com/course/classes';

// All headers in ONE object (including app_id, authorization, user_id)
const headersnt = {
  'accept': 'application/json, text/plain, */*',
  'content-type': 'application/json',
  'origin': 'https://nexttoppers.com',
  'platform': '3',
  'referer': 'https://nexttoppers.com/',
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  'version': '1',
  'app_id': '1770981347',
  'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0MTc4MTQ4LCJhcHBfaWQiOiIxNzcyMTAwNjAwIiwiZGV2aWNlX2lkIjoiYWQxY2FlODMtODc1YS00MmE5LWEwZjQtNjkwZDM2MTNmZTNkIiwicGxhdGZvcm0iOiIzIiwidXNlcl90eXBlIjoxLCJpYXQiOjE3Nzg4NjI5NDksImV4cCI6MTc4MTQ1NDk0OX0.4nwzl8l_wMjMFKihpXSkLq45bEVNqIBt5LtFem22vws',
  'user_id': '3652828'
};

// Proxy endpoint
app.all('/api/nexttoppers/live', async (req, res) => {
  try {
    // Make request to target API with all headers in one object
    const response = await axios({
      method: req.method,
      url: TARGET_URL,
      headers: headersnt,
      data: req.body,
      timeout: 10000
    });

    // Send response back to client
    res.status(response.status).json(response.data);
    
  } catch (error) {
    console.error('Proxy error:', error.message);
    
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({
        error: 'Proxy server error',
        message: error.message
      });
    }
  }
});

//=============missionjeet==========
const headersmj = {
  'accept': 'application/json, text/plain, */*',
  'content-type': 'application/json',
  'origin': 'https://nexttoppers.com',
  'platform': '3',
  'referer': 'https://nexttoppers.com/',
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  'version': '1',
  'app_id': '1772100600',
  'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjozNjUyODI4LCJhcHBfaWQiOiIxNzcwOTgxMzQ3IiwiZGV2aWNlX2lkIjoiYzZmZTNjYWYtOWRkMS00ZTE0LTgyMGEtNGIyZDVjMjJjNDViIiwicGxhdGZvcm0iOiIzIiwidXNlcl90eXBlIjoxLCJpYXQiOjE3ODAxMjEwNjQsImV4cCI6MTc4MjcxMzA2NF0.sFVc3OuVvIfZfLkyDWbkQNmV92oRIzycNh7e-bMMck8',
  'user_id': '3652828'
};
  
app.all('/api/missionjeet/live', async (req, res) => {
  try {
    // Make request to target API with all headers in one object
    const response = await axios({
      method: req.method,
      url: TARGET_URL,
      headers: headersmj,
      data: req.body,
      timeout: 10000
    });

    // Send response back to client
    res.status(response.status).json(response.data);
    
  } catch (error) {
    console.error('Proxy error:', error.message);
    
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({
        error: 'Proxy server error',
        message: error.message
      });
    }
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
    const url = `${BASE}/api/vibrant/previous-live?course_id=${courseid}`;
    
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
//frytdrtdtsdf
//========science===
  const PW_HEADERS = {
    "Accept-Encoding": "gzip",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A707F Build/RP1A.200720.012)",
    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODE3OTg1NTIuNjk5LCJkYXRhIjp7Il9pZCI6IjY1ZTA0MDBjYjllNmRjYjZhYTM0YjQxYSIsInVzZXJuYW1lIjoiOTM0MTc5Mzg5OSIsImZpcnN0TmFtZSI6IlByaXlhbnNodSIsImxhc3ROYW1lIjoiS3VtYXIgVXBhZGhheWF5Iiwib3JnYW5pemF0aW9uIjp7Il9pZCI6IjVlYjM5M2VlOTVmYWI3NDY4YTc5ZDE4OSIsIndlYnNpdGUiOiJwaHlzaWNzd2FsbGFoLmNvbSIsIm5hbWUiOiJQaHlzaWNzd2FsbGFoIn0sImVtYWlsIjoiYW51ai51cGFkaHlheTM2OUBnbWFpbC5jb20iLCJyb2xlcyI6WyI1YjI3YmQ5NjU4NDJmOTUwYTc3OGM2ZWYiXSwiY291bnRyeUdyb3VwIjoiSU4iLCJvbmVSb2xlcyI6W10sInR5cGUiOiJVU0VSIn0sImp0aSI6IlZTX01pdkdyUlZhdnBqUmZWV2pWUVFfNjVlMDQwMGNiOWU2ZGNiNmFhMzRiNDFhIiwiaWF0IjoxNzgxMTkzNzUyfQ.yCow88dcTVSa7vYyj3yyGRf8S22BKU5bVWiIj-I5fk4",
    "client-id": "ADMIN",
    "client-type": "MOBILE",
    "client-version": "538",
    "content-type": "application/json",
    "device-meta": "{\"APP_VERSION\":\"538\",\"APP_VERSION_NAME\":\"15.32.0\",\"DEVICE_MAKE\":\"Samsung\",\"DEVICE_MODEL\":\"SM-A707F\",\"OS_VERSION\":\"11\",\"PACKAGE_NAME\":\"xyz.penpencil.physicswala\",\"network\":\"wifi_data\",\"carrier\":\"UNDEFINED\"}",
    "randomid": "d054aefb-8a77-4ae1-bbf6-77c0e1931374",
    "referer": "https://android.pw.live"
};

// ✅ Dynamic slides endpoint with query parameters
app.get('/slides', async (req, res) => {
    // Query parameters से data ले
    const batchId = req.query.batch_id;
    const subjectId = req.query.subject_id;
    const scheduleId = req.query.schedule_id;
    const type = req.query.type
    // Validation - सभी parameters ज़रूरी हैं
    if (!batchId || !subjectId || !scheduleId) {
        return res.status(400).json({
            error: 'Missing required parameters',
            required: ['batch_id', 'subject_id', 'schedule_id'],
            example: '/get-slides?batch_id=6920510a70e5cf316c9e3000&subject_id=6926c4dadef5ac36c3b2c108&schedule_id=6a19aefc5a7d6b0adfbd1c2b'
        });
    }

    // Dynamic API URL build करें
    const apiUrl = `https://api.penpencil.co/v1/batches/${batchId}/subject/${subjectId}/schedule/${scheduleId}/${type}`;

    console.log('📡 Calling API:', apiUrl);

    try {
        const response = await axios.get(apiUrl, {
            headers: PW_HEADERS,
            timeout: 10000,
        });

        res.status(200).json(response.data);
    } catch (error) {
        console.error('API Error:', error.message);
        
        const errorStatus = error.response?.status || 500;
        const errorData = error.response?.data || { message: error.message };
        
        res.status(errorStatus).json({
            error: errorData.message || error.message,
            status: errorStatus,
            details: errorData,
            api_url: apiUrl
        });
    }
});

 // PW Headers constant - आपके दिए headers use कर रहे हैं
const AUTHORIZATION = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyODc2MDAiLCJ0aW1lc3RhbXAiOjE3ODE0MDk4OTEsIml2X3ZlciI6Miwic2Vzc2lvbiI6ImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSklVekkxTmlKOS5leUpwWkNJNklqRXlPRGMyTURBaUxDSmxiV0ZwYkNJNklqazFOVGs1TnpVek56QkFaMjFoYVd3dVkyOXRJaXdpYm1GdFpTSTZJaUlzSW5SbGJtRnVkRlI1Y0dVaU9pSjFjMlZ5SWl3aWRHVnVZVzUwVG1GdFpTSTZJbUZ5YldGMGFITmZaR0lpTENKMFpXNWhiblJKWkNJNklpSXNJbVJwYzNCdmMyRmliR1VpT21aaGJITmxmUS5EbmNwSzhSWWd6ZzJsSHUxVkZKaVluYjVGMjlwTk52eW1ZdUZqUkxIV004In0.ftduhO--p4Ku0CHqlfbstlPH9PezVtGmWYKaBmSv5UI";
const USERID = "1287600";
const AUTHTOKEN = "appxapi";

// Common headers function
function getCommonHeaders() {
  return {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'https://armaths.akamai.net.in',
    'Referer': 'https://armaths.akamai.net.in/',
    'source': 'website',
    'client-service': 'Appx',
    'Device-Type': '',
    'Authorization': AUTHORIZATION,
    'User-Id': USERID,
    'Auth-Key': AUTHTOKEN,
    'X-Forwarded-For': '127.0.0.1',
    'X-Real-IP': '127.0.0.1',
  };
}

// 1. Proxy folder_contentsv3
app.get('/api/folder-contents', async (req, res) => {
  const { course_id, parent_id } = req.query;
  
  const targetUrl = new URL('https://armathsapi.akamai.net.in/get/folder_contentsv3');
  targetUrl.searchParams.set('course_id', course_id);
  targetUrl.searchParams.set('parent_id', parent_id || '');
  targetUrl.searchParams.set('windowsapp', 'false');
  targetUrl.searchParams.set('start', '0');

  try {
    const response = await axios.get(targetUrl.toString(), {
      headers: getCommonHeaders(),
      timeout: 10000,
    });

    res.json(response.data);
  } catch (error) {
    console.error('Folder contents proxy error:', error.message);
    res.status(error.response?.status || 500).json({
      error: error.message,
      status: error.response?.status
    });
  }
});

// 2. Proxy course_contents_by_live_status
app.get('/api/live-courses', async (req, res) => {
  const { course_id, start, live_status } = req.query;
  
  const targetUrl = new URL('https://armathsapi.akamai.net.in/get/course_contents_by_live_status');
  targetUrl.searchParams.set('course_id', course_id || '74');
  targetUrl.searchParams.set('start', start || '-1');
  targetUrl.searchParams.set('live_status', live_status || '1');

  try {
    const response = await axios.get(targetUrl.toString(), {
      headers: getCommonHeaders(),
      timeout: 10000,
    });

    res.json(response.data);
  } catch (error) {
    console.error('Live courses proxy error:', error.message);
    res.status(error.response?.status || 500).json({
      error: error.message,
      status: error.response?.status
    });
  }
});

// 3. Proxy get_previous_live_videos
app.get('/api/previous-live-videos', async (req, res) => {
  const { course_id, start, folder_wise_course, userid } = req.query;
  
  const targetUrl = new URL('https://armathsapi.akamai.net.in/get/get_previous_live_videos');
  targetUrl.searchParams.set('course_id', course_id || '74');
  targetUrl.searchParams.set('start', start || '0');
  targetUrl.searchParams.set('folder_wise_course', folder_wise_course || '1');
  targetUrl.searchParams.set('userid', userid || USERID);

  try {
    const response = await axios.get(targetUrl.toString(), {
      headers: getCommonHeaders(),
      timeout: 10000,
    });

    res.json(response.data);
  } catch (error) {
    console.error('Previous live videos proxy error:', error.message);
    res.status(error.response?.status || 500).json({
      error: error.message,
      status: error.response?.status
    });
  }
});
  app.get('/api/video-details', async (req, res) => {
  const { course_id, video_id, ytflag, folder_wise_course, lc_app_api_url } = req.query;
  
  const targetUrl = new URL('https://armathsapi.akamai.net.in/get/fetchVideoDetailsById');
  targetUrl.searchParams.set('course_id', course_id || '74');
  targetUrl.searchParams.set('video_id', video_id);
  targetUrl.searchParams.set('ytflag', ytflag || '0');
  targetUrl.searchParams.set('folder_wise_course', folder_wise_course || '1');
  targetUrl.searchParams.set('lc_app_api_url', lc_app_api_url || '');

  try {
    const response = await axios.get(targetUrl.toString(), {
      headers: getCommonHeaders(),
      timeout: 10000,
    });

    res.json(response.data);
  } catch (error) {
    console.error('Video details proxy error:', error.message);
    res.status(error.response?.status || 500).json({
      error: error.message,
      status: error.response?.status
    });
  }
});
// vikaramjeet
  const AUTHORIZATION2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjE0OTQxMzgiLCJ0aW1lc3RhbXAiOjE3ODE4NDUzNTMsIml2X3ZlciI6Mywic2Vzc2lvbiI6ImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSklVekkxTmlKOS5leUpwWkNJNklqRTBPVFF4TXpnaUxDSmxiV0ZwYkNJNkltTm9ZVzVrWVc1d2NtRnFZWEJoZEdrNU1UazRRR2R0WVdsc0xtTnZiU0lzSW01aGJXVWlPaUpqYUdGdVpHRnVJSEJ5WVdwaGNHRjBhU0lzSW5SbGJtRnVkRlI1Y0dVaU9pSjFjMlZ5SWl3aWRHVnVZVzUwVG1GdFpTSTZJbkpuZG1scmNtRnRhbVZsZEY5a1lpSXNJblJsYm1GdWRFbGtJam9pSWl3aVpHbHpjRzl6WVdKc1pTSTZabUZzYzJWOS5aaGpacUFiYXFuWlZUQkFBQTdYOHRtQ2ZpTWpMRjlLYloxYnNETHNIVWc4In0.aPfneNhOlCiI4aKqz6-a78RPMJ_tbvvonFw1S-Ozius";
const USERID2 = "1494138";
const AUTHTOKEN2 = "appxapi";

// Common headers function
function getCommonHeaders2() {
  return {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'https://rankersgurukul.com',
    'Referer': 'https://rankersgurukul.com/',
    'source': 'website',
    'client-service': 'Appx',
    'Device-Type': '',
    'Authorization': AUTHORIZATION2,
    'User-Id': USERID2,
    'Auth-Key': AUTHTOKEN2,
    'X-Forwarded-For': '127.0.0.1',
    'X-Real-IP': '127.0.0.1',
  };
}
// Slides API Proxy (पहले जैसा)
  app.get('/api/vikaram/video-details', async (req, res) => {
  const { course_id, video_id, user, ytflag, folder_wise_course, lc_app_api_url } = req.query;
  
  const targetUrl = new URL('https://rgvikramjeetapi.classx.co.in/get/fetchVideoDetailsById');
  targetUrl.searchParams.set('course_id', course_id || '74');
  targetUrl.searchParams.set('video_id', video_id);
  targetUrl.searchParams.set('user', user || '0');
  targetUrl.searchParams.set('ytflag', ytflag || '0');
  targetUrl.searchParams.set('folder_wise_course', folder_wise_course || '1');
  targetUrl.searchParams.set('lc_app_api_url', lc_app_api_url || '');

  try {
    const response = await axios.get(targetUrl.toString(), {
      headers: getCommonHeaders2(),
      timeout: 10000,
    });

    res.json(response.data);
  } catch (error) {
    console.error('Video details proxy error:', error.message);
    res.status(error.response?.status || 500).json({
      error: error.message,
      status: error.response?.status
    });
  }
});
  //=====xdcfdsfsd


//=============454534534==========

  //==========rty




// PW VERIFY

  // -==========temp mail ===========
  
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "BBw7Jxh7FSFdTT2GrcXb9YFgcbCEKVoJWj4vSKu_pzkghrq3VgWznY7oNLxufJUrZWhkzJKIyTzTrXeSPlQgoLI";
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "56GFuWTszD2eLvMzyFJa51XRC6O4KS0YaTQgXT0VFEo";

// Ye sirf web-push spec ke hisaab se contact info hai
// Yahan se user ko koi email Nahi jayega
webpush.setVapidDetails(
  "mailto:admin@learnbyakp.online",
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

// Simple in-memory store (demo ke liye)
// Production me DB use kar sakte ho
const subscriptions = [];

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Health check route


// 1) Subscription save karne ka API (frontend se call hota hai)
app.post("/api/save-subscription", (req, res) => {
  const { subscription } = req.body;
  if (!subscription) {
    return res.status(400).json({ success: false, message: "No subscription found" });
  }

  const exists = subscriptions.find(
    (sub) => JSON.stringify(sub) === JSON.stringify(subscription)
  );
  if (!exists) {
    subscriptions.push(subscription);
    console.log("✅ New subscription saved. Total:", subscriptions.length);
  }

  res.json({ success: true });
});

// 2) Notification send karne ka API (frontend se)
// Ye endpoint koi email nahi bhejta, sirf push service ko hit karta hai
app.post("/api/send-notification", async (req, res) => {
  const { title, body, icon, data } = req.body;

  if (!subscriptions.length) {
    return res.json({ success: false, message: "No subscribers yet" });
  }

  // Brand prefix yahan bhi ensure kar sakte ho (frontend already kar raha hai, phir bhi safe)
  const finalTitle = title || "LearnByAKP.online";
  const finalBody = body || "New notification from LearnByAKP.online";
  const finalIcon = icon || "https://learnbyakp.online/lo.png";

  const payload = JSON.stringify({
    title: finalTitle,
    body: finalBody,
    icon: finalIcon,
    data: data || {}
  });

  let sentCount = 0;

  await Promise.all(
    subscriptions.map(async (sub, index) => {
      try {
        await webpush.sendNotification(sub, payload);
        sentCount++;
      } catch (err) {
        console.error("❌ Failed for subscription", index, err.message);
      }
    })
  );

  console.log(`📨 Notification sent to ${sentCount}/${subscriptions.length} subscribers`);
  res.json({ success: true, sent: sentCount });
});

// 3) Debug ke liye subscription count
app.get("/api/subscriptions", (req, res) => {
  res.json({ count: subscriptions.length });
});
  //============ attttttttt======

  // ========= YOUR TWO PROXY ROUTES =========

  // Endpoint for /api/batches
 
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
    const url = new URL(`${BASE}/api/vibrant/course-hehe`);

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
  //==========science==========
  app.get("/api/science/content", async (req, res) => {
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
    const url = new URL(`${BASE}/api/scienceandfun/content`);

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
  //============yfdghf==========
  // Testing ke liye GET endpoint

  //==============uyutyutyuu
app.get("/api/vibrant/video-details", async (req, res) => {
  try {
    // Support both old (r/e) and new (courseid/id) param formats
    const video_id = req.query.D || req.query.video_id;
    const course_id = req.query.P || req.query.course_id;

    if (!course_id) {
      return res.status(400).json({ error: "Missing courseid (r or courseid)" });
    }

    const url = new URL(`${BASE}/api/vibrant/video-details`);
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


  //===================science========
  app.get("/api/science/video-details", async (req, res) => {
  try {
    // Support both old (r/e) and new (courseid/id) param formats
    const video_id = req.query.D || req.query.video_id;
    const course_id = req.query.P || req.query.course_id;

    if (!course_id) {
      return res.status(400).json({ error: "Missing courseid (r or courseid)" });
    }

    const url = new URL(`${BASE}/api/scienceandfun/video-details`);
    url.searchParams.set("course_id", course_id);

    if (video_id) {
      url.searchParams.set("video_id", video_id);
    }

    const response = await fetchfn(url.toString());
    const data = await response.json();

    res.json(data);
  } catch (err) {
    console.error("/api/scienceand fun/video-details error:", err);
    res.status(500).json({ error: err.toString() });
  }
});
  //ddfddfdfdf=======

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
//========dsdfd===
 const allowedSites = ["learnbyakp.online","localhost:5600", "www.notjitu.in", "notjitu.in","jitu-test.vercel.app"];
app.get("/apv/:file", (req, res) => {

    try {

        const referer = req.get("referer") || "";

        // Sirf tumhari site allow
       

if (!allowedSites.some(site => referer.includes(site))) {
    return res.status(403).send("Some genius error. don't try again");
}

        const fileName = req.params.file;

        // Only JS
        if (!fileName.endsWith(".js")) {
            return res.status(404).send("Invalid file");
        }

        const filePath = path.join(
            __dirname,
            "apv",
            fileName
        );

        // File exists check
        if (!fs.existsSync(filePath)) {
            return res.status(404).send("File not found");
        }

        res.sendFile(filePath);

    } catch (err) {

        console.error(err);

        res.status(500).send("Server Error");

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
  // vibrant live ====
  // GET /api/vibrant/live?course_id=123
app.get("/api/vibrant/live", async (req, res) => {
  try {
    const courseId = req.query.course_id || req.query.courseid || req.query.id;

    if (!courseId) {
      return res.status(400).json({
        success: false,
        message: "course_id is required"
      });
    }

    const upstreamUrl =
      `${CHANGE}/api/vibrant/live?course_id=${encodeURIComponent(courseId)}`;

    const response = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0"
      }
    });

    const text = await response.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    return res.status(response.status).json({
      success: response.ok,
      status: response.status,
      source: "vibrant-live",
      data
    });

  } catch (error) {
    console.error("Vibrant live proxy error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch Vibrant live data",
      error: error.message
    });
  }
});

  
  //======science==========
  app.get("/api/science/live", async (req, res) => {
  try {
    const courseId = req.query.course_id || req.query.courseid || req.query.id;

    if (!courseId) {
      return res.status(400).json({
        success: false,
        message: "course_id is required"
      });
    }

    const upstreamUrl =
      `${CHANGE}/api/scienceandfun/live?course_id=${encodeURIComponent(courseId)}`;

    const response = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0"
      }
    });

    const text = await response.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    return res.status(response.status).json({
      success: response.ok,
      status: response.status,
      source: "vibrant-live",
      data
    });

  } catch (error) {
    console.error("Vibrant live proxy error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch Vibrant live data",
      error: error.message
    });
  }
});
  //======live of mission jeet=====
 
  
  //====================asdasdasd============

//================fgdfg==========

  app.get('/api/pw/dpp-quiz-proxy', async (req, res) => {
    try {
        // Target URL
        const targetUrl = 'https://streamfiles.eu.org/api/dpp_quiz.php';

        // Fake Headers create karna taaki API block na kare
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            // Agar API kisi specific website ko hi allow karti hai, toh uska Origin aur Referer yahan daalo
             'Origin': 'https://streamfiles.eu.org/', 
             'Referer': 'https://streamfiles.eu.org/' 
        };

        // Backend se request bhejna (yahan req.query me aapke frontend ke saare params automatic aayenge)
        const response = await axios.get(targetUrl, {
            params: req.query, 
            headers: headers
        });

        // Response frontend ko bhej do
        res.status(200).json({ success: true, data: response.data });

    } catch (error) {
        console.error('Error fetching DPP Quiz:', error.message);
        
        // Agar fir bhi 403 aaye backend par
        if (error.response && error.response.status === 403) {
            return res.status(403).json({ success: false, message: "Token expired or IP restricted" });
        }
        
        res.status(500).json({ success: false, message: "Backend Proxy Error" });
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
      `${BASE}/api/vibrant/play?url=` +
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

  
//=======================================================
const MAILTM_BASE = "https://api.mail.tm";

app.use(express.json({ limit: "1mb" }));

app.use(cors({
  origin: [
    "http://localhost:5600",
    "http://127.0.0.1:5600",
    "https://learnbyakp.online",
    "https://learnbyakp.onrender.com"
  ],
  credentials: false
}));

function buildHeaders(req, hasBody = false) {
  const headers = {
    Accept: "application/json"
  };

  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }

  const auth = req.headers.authorization;
  if (auth) {
    headers["Authorization"] = auth;
  }

  return headers;
}

async function proxyMailTm(req, res, upstreamUrl, options = {}) {
  try {
    const response = await fetch(upstreamUrl, options);
    const text = await response.text();

    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    if (!response.ok) {
      return res.status(response.status).json(
        typeof data === "object" && data ? data : { message: data || `HTTP ${response.status}` }
      );
    }

    return res.status(response.status).json(
      typeof data === "object" && data !== null ? data : { data }
    );
  } catch (error) {
    return res.status(500).json({
      message: "Proxy request failed",
      error: error.message
    });
  }
}

// GET /api/tempmail/domains?page=1
app.get("/api/tempmail/domains", async (req, res) => {
  const page = req.query.page || "1";
  const url = `${MAILTM_BASE}/domains?page=${encodeURIComponent(page)}`;

  await proxyMailTm(req, res, url, {
    method: "GET",
    headers: buildHeaders(req)
  });
});

// POST /api/tempmail/accounts
app.post("/api/tempmail/accounts", async (req, res) => {
  const url = `${MAILTM_BASE}/accounts`;

  await proxyMailTm(req, res, url, {
    method: "POST",
    headers: buildHeaders(req, true),
    body: JSON.stringify(req.body || {})
  });
});

// POST /api/tempmail/token
app.post("/api/tempmail/token", async (req, res) => {
  const url = `${MAILTM_BASE}/token`;

  await proxyMailTm(req, res, url, {
    method: "POST",
    headers: buildHeaders(req, true),
    body: JSON.stringify(req.body || {})
  });
});

// GET /api/tempmail/messages?page=1
app.get("/api/tempmail/messages", async (req, res) => {
  const page = req.query.page || "1";
  const url = `${MAILTM_BASE}/messages?page=${encodeURIComponent(page)}`;

  await proxyMailTm(req, res, url, {
    method: "GET",
    headers: buildHeaders(req)
  });
});

// GET /api/tempmail/messages/:id
app.get("/api/tempmail/messages/:id", async (req, res) => {
  const id = req.params.id;
  const url = `${MAILTM_BASE}/messages/${encodeURIComponent(id)}`;

  await proxyMailTm(req, res, url, {
    method: "GET",
    headers: buildHeaders(req)
  });
});

// optional health
app.get("/api/tempmail/health", (req, res) => {
  res.json({ ok: true, service: "tempmail-proxy" });
});

  
  //jkdsyututyt======
 
  // Endpoint for /api/pw/li

//=============pw batch details


/**
 * 2) BATCH DETAILS API
 * Page expects:
 * POST /api/pw/batchdetails
 * body: { searchParams: { BatchId: "..." } }
 */

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

  //================mobile otp====

  
  //============dasdddd=====

  //=========eter========
 

/**
 * 4) /api/pw/attachments-url
 * frontend call:
 * /api/pw/attachments-url?BatchId=...&SubjectId=...&ContentId=...
 */

/**
 * 5) /api/pw/kid
 * frontend call:
 * /api/pw/kid?mpdUrl=...
 */


/**
 * 6) /api/pw/otp
 * frontend call:
 * /api/pw/otp?kid=...
 */

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
