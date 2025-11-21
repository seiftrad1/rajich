import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { bearerAuth } from "./middleware/bearerAuth";
import { registerTokenCheck } from "./middleware/registerTokenCheck";
import { requireSuperAdmin } from "./middleware/requireSuperAdmin";
dotenv.config();
/* ─────────────────────────────────────────────
   env & helpers
───────────────────────────────────────────── */
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
const DB_HOST = process.env.DB_HOST;
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD ?? "";
const DB_NAME = process.env.DB_NAME;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "2h";
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "false") === "true";
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || "lax";
function signToken(payload) {
    const options = { expiresIn: JWT_EXPIRES_IN };
    return jwt.sign(payload, JWT_SECRET, options);
}
function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
}
/* ─────────────────────────────────────────────
   app & security
───────────────────────────────────────────── */
const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
// app.use(
//   cors({
//     origin: (origin, cb) => {
//       if (!origin) return cb(null, true); // allow Postman/curl
//       if (CORS_ORIGINS.includes(origin)) return cb(null, true);
//       return cb(new Error("Not allowed by CORS"));
//     },
//     credentials: true,
//   })
// );
// 🚧 Block direct browser access
const allowedOrigins = [
    "https://smsereus.com",
    "https://www.smsereus.com",
    "https://phpstack-1546497-5981865.cloudwaysapps.com",
    "http://localhost:3000"
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            console.warn(`❌ CORS blocked request from: ${origin}`);
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true, // ✅ allows cookies (important for your /me login session)
}));
app.options("*", cors());
app.use(bearerAuth);
app.use((req, res, next) => {
    const referer = req.get("referer");
    const origin = req.get("origin");
    const userAgent = req.get("user-agent") || "";
    // If it's a manual browser visit (no origin or from browser address bar)
    const isNavigator = !origin && req.method === "GET" && userAgent.includes("Mozilla");
    // Allow your frontend or API clients
    const allowedOrigins = ["https://smsereus.com", "https://www.smsereus.com"];
    const isAllowedOrigin = origin && allowedOrigins.some(o => origin.startsWith(o));
    if (isNavigator && !isAllowedOrigin) {
        console.log("🚫 Blocked direct browser access:", req.url);
        return res.status(403).send("Forbidden");
    }
    next();
});
app.use(rateLimit({
    windowMs: 60000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
}));
/* ─────────────────────────────────────────────
   mysql & twilio
───────────────────────────────────────────── */
const db = mysql.createPool({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
});
/* ─────────────────────────────────────────────
   middlewares
───────────────────────────────────────────── */
function authMiddleware(req, res, next) {
    const token = req.cookies?.token;
    if (!token)
        return res.status(401).json({ success: false, message: "No auth cookie" });
    try {
        const decoded = verifyToken(token);
        req.user = decoded;
        next();
    }
    catch {
        return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }
}
function adminOnly(req, res, next) {
    const user = req.user;
    if (!user?.isAdmin) {
        return res.status(403).json({ success: false, message: "Admins only" });
    }
    next();
}
/* ─────────────────────────────────────────────
   helpers
───────────────────────────────────────────── */
function tokenCookieOptions() {
    return {
        httpOnly: true,
        secure: COOKIE_SECURE || NODE_ENV === "production",
        sameSite: COOKIE_SAME_SITE, // "lax" (local), "none" (prod across domains w/ https)
        maxAge: 2 * 60 * 60 * 1000,
        path: "/",
    };
}
// REGISTER (with optional role)
app.post("/register", registerTokenCheck, async (req, res) => {
    const { username, email, password, role } = req.body || {};
    if (!username || !email || !password) {
        return res
            .status(400)
            .json({ success: false, message: "Username, email, and password required." });
    }
    try {
        const [existing] = await db.query("SELECT id FROM users WHERE username = ? OR email = ?", [username, email]);
        if (existing.length > 0)
            return res
                .status(400)
                .json({ success: false, message: "Username or email already exists." });
        const hashed = await bcrypt.hash(password, 12);
        // 👇 Default to "user" unless specified (e.g. "admin")
        const userRole = role && role.toLowerCase() === "admin" ? "admin" : "user";
        await db.query("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", [username, email, hashed, userRole]);
        res.json({ success: true, message: `Registered successfully as ${userRole}.` });
    }
    catch (e) {
        console.error("Register error:", e);
        res.status(500).json({ success: false, message: "Database error." });
    }
});
app.post("/login", async (req, res) => {
    const { username, email, password } = req.body || {};
    const identifier = username || email;
    if (!identifier || !password) {
        return res.status(400).json({
            success: false,
            message: "Username/email and password required."
        });
    }
    // REAL USER IP (Cloudways compatible)
    let ip = req.headers["cf-connecting-ip"] ||
        req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
        req.socket.remoteAddress ||
        "unknown";
    // Remove IPv6 prefix (like ::ffff:)
    if (ip.startsWith("::ffff:"))
        ip = ip.replace("::ffff:", "");
    const userAgent = req.headers["user-agent"] || "unknown";
    try {
        const [rows] = await db.query("SELECT * FROM users WHERE username = ? OR email = ?", [identifier, identifier]);
        const user = rows[0];
        /* ---------------------------------------------------------
           1️⃣ USER NOT FOUND → log failed attempt
        --------------------------------------------------------- */
        if (!user) {
            await db.query(`INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
         VALUES (?, ?, ?, ?, ?)`, [null, identifier, ip, userAgent, false]);
            return res.status(404).json({ success: false, message: "User not found." });
        }
        /* ---------------------------------------------------------
           2️⃣ ACCOUNT DEACTIVATED → block + log failed attempt
        --------------------------------------------------------- */
        if (user.status === "inactive") {
            await db.query(`INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
         VALUES (?, ?, ?, ?, ?)`, [user.id, user.username, ip, userAgent, false]);
            return res.status(403).json({
                success: false,
                message: "Account is deactivated. Contact administrator."
            });
        }
        /* ---------------------------------------------------------
           3️⃣ WRONG PASSWORD → log failed attempt
        --------------------------------------------------------- */
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            await db.query(`INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
         VALUES (?, ?, ?, ?, ?)`, [user.id, user.username, ip, userAgent, false]);
            return res.status(401).json({
                success: false,
                message: "Invalid credentials."
            });
        }
        /* ---------------------------------------------------------
           4️⃣ SUCCESS LOGIN → generate JWT + log success
        --------------------------------------------------------- */
        const token = signToken({
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            isAdmin: user.role === "admin" || user.role === "superadmin",
            isSuperAdmin: user.role === "superadmin",
        });
        res.cookie("token", token, tokenCookieOptions());
        await db.query(`INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?)`, [user.id, user.username, ip, userAgent, true]);
        return res.json({
            success: true,
            message: "Login successful.",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                isAdmin: user.role === "admin" || user.role === "superadmin",
                isSuperAdmin: user.role === "superadmin"
            }
        });
    }
    catch (e) {
        console.error("Login error:", e);
        return res.status(500).json({
            success: false,
            message: "Database error."
        });
    }
});
app.post("/logout", (_req, res) => {
    res.clearCookie("token", { path: "/" });
    res.json({ success: true, message: "Logged out" });
});
app.get("/user", authMiddleware, (req, res) => {
    const u = req.user;
    return res.json({
        success: true,
        user: {
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role,
            isAdmin: u.role === "admin" || u.role === "superadmin",
            isSuperAdmin: u.role === "superadmin"
        },
    });
});
// Fix "__dirname" for ES Modules (used by TypeScript when compiled to ESM)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Serve frontend build folder
const frontendPath = path.join(__dirname, "../frontend/dist"); // 👈 change if different
app.use(express.static(frontendPath));
// Example test route (optional)
app.get("/hello", (_req, res) => {
    res.json({ message: "Hello from backend!" });
});
// Fallback — send React index.html for all non-API routes
// app.get("*", (req, res, next) => {
//   if (req.path.startsWith("/")) return next(); // don't interfere with API
//   res.sendFile(path.join(frontendPath, "index.html"));
// });
// All your API routes here (login, sms, logs, etc.)
// 👇 Always at the very bottom:
/* ─────────────────────────────────────────────
   start
───────────────────────────────────────────── */
app.get("/health", (_req, res) => res.json({ ok: true, env: NODE_ENV }));
app.get("/login-history", authMiddleware, requireSuperAdmin, async (req, res) => {
    try {
        const [rows] = await db.query(`SELECT lh.*, u.username AS user_username, u.email AS user_email
       FROM login_history lh
       LEFT JOIN users u ON u.id = lh.user_id
       ORDER BY lh.id DESC
       LIMIT 200`);
        res.json({ success: true, history: rows });
    }
    catch (err) {
        console.error("Login history error:", err);
        res.status(500).json({ success: false, message: "Cannot load login history" });
    }
});
app.get("/users", authMiddleware, requireSuperAdmin, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM users ORDER BY id DESC");
        res.json({ success: true, users: rows });
    }
    catch (err) {
        console.error("Users fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch users" });
    }
});
app.post("/users", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: "Missing fields" });
    }
    try {
        const hashed = await bcrypt.hash(password, 12);
        await db.query("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", [username, email, hashed, role || "user"]);
        res.json({ success: true, message: "User created" });
    }
    catch (err) {
        console.error("User create error:", err);
        res.status(500).json({ success: false, message: "Cannot create user" });
    }
});
app.patch("/users/:id", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { username, email, role } = req.body;
    const { id } = req.params;
    try {
        await db.query("UPDATE users SET username=?, email=?, role=? WHERE id=?", [username, email, role, id]);
        res.json({ success: true, message: "User updated" });
    }
    catch (err) {
        console.error("User update error:", err);
        res.status(500).json({ success: false, message: "Cannot update user" });
    }
});
app.patch("/users/:id/password", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { newPassword } = req.body;
    const { id } = req.params;
    if (!newPassword)
        return res.status(400).json({ success: false, message: "New password required" });
    try {
        const hashed = await bcrypt.hash(newPassword, 12);
        await db.query("UPDATE users SET password=? WHERE id=?", [hashed, id]);
        res.json({ success: true, message: "Password updated" });
    }
    catch (err) {
        console.error("Password update error:", err);
        res.status(500).json({ success: false, message: "Cannot update password" });
    }
});
app.delete("/users/:id", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query("DELETE FROM users WHERE id=?", [id]);
        res.json({ success: true, message: "User deleted" });
    }
    catch (err) {
        console.error("User delete error:", err);
        res.status(500).json({ success: false, message: "Cannot delete user" });
    }
});
app.patch("/users/:id/toggle-active", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query("SELECT status FROM users WHERE id = ?", [id]);
        const user = rows[0];
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });
        const newStatus = user.status === "active" ? "inactive" : "active";
        await db.query("UPDATE users SET status = ? WHERE id = ?", [newStatus, id]);
        return res.json({ success: true, status: newStatus });
    }
    catch (err) {
        console.error("Toggle error:", err);
        res.status(500).json({ success: false, message: "Toggle failed" });
    }
});
app.get("*", (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
});
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server running on port ${PORT} (${NODE_ENV})`));
