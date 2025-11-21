import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { bearerAuth } from "./middleware/bearerAuth.js";
import { registerTokenCheck } from "./middleware/registerTokenCheck.js";
import { requireSuperAdmin } from "./middleware/requireSuperAdmin.js";
// 🔥 NEW — Supabase PostgreSQL via Pooler
import postgres from "postgres";
// Load env
dotenv.config();
/* ─────────────────────────────────────────────
    ENV
───────────────────────────────────────────── */
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "2h";
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "false") === "true";
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || "lax";
// 🔥 PostgreSQL (Supabase Pooler)
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
    console.error("❌ Missing DATABASE_URL in .env");
    process.exit(1);
}
export const sql = postgres(DATABASE_URL, { ssl: "require" });
/* ─────────────────────────────────────────────
    HELPERS
───────────────────────────────────────────── */
function signToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
}
function tokenCookieOptions() {
    return {
        httpOnly: true,
        secure: COOKIE_SECURE || NODE_ENV === "production",
        sameSite: COOKIE_SAME_SITE,
        maxAge: 2 * 60 * 60 * 1000,
        path: "/",
    };
}
/* ─────────────────────────────────────────────
    EXPRESS INIT & SECURITY
───────────────────────────────────────────── */
const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
// CORS
const allowedOrigins = [
    "https://smsereus.com",
    "https://www.smsereus.com",
    "https://phpstack-1546497-5981865.cloudwaysapps.com",
    "http://localhost:3000",
];
app.use(cors({
    origin: (origin, cb) => {
        if (!origin || allowedOrigins.includes(origin))
            return cb(null, true);
        console.log("❌ CORS blocked:", origin);
        return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
}));
app.options("*", cors());
// bearerAuth stays
app.use(bearerAuth);
// Block direct browser access
app.use((req, res, next) => {
    const origin = req.get("origin");
    const ua = req.get("user-agent") || "";
    const isNavigator = !origin && req.method === "GET" && ua.includes("Mozilla");
    const isAllowed = origin && allowedOrigins.some((o) => origin.startsWith(o));
    if (isNavigator && !isAllowed) {
        console.log("🚫 Blocked browser access:", req.url);
        return res.status(403).send("Forbidden");
    }
    next();
});
// Rate limit
app.use(rateLimit({
    windowMs: 60000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
}));
/* ─────────────────────────────────────────────
    AUTH MIDDLEWARE (unchanged)
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
/* ─────────────────────────────────────────────
    REGISTER
───────────────────────────────────────────── */
app.post("/register", registerTokenCheck, async (req, res) => {
    const { username, email, password, role } = req.body || {};
    if (!username || !email || !password)
        return res.status(400).json({
            success: false,
            message: "Username, email, and password required.",
        });
    try {
        // EXISTS?
        const existing = await sql `SELECT id FROM users WHERE username = ${username} OR email = ${email}`;
        if (existing.length > 0)
            return res
                .status(400)
                .json({ success: false, message: "Username or email exists." });
        const hashed = await bcrypt.hash(password, 12);
        const userRole = role?.toLowerCase() === "admin" ? "admin" : "user";
        await sql `
      INSERT INTO users (username, email, password, role)
      VALUES (${username}, ${email}, ${hashed}, ${userRole})
    `;
        return res.json({
            success: true,
            message: `Registered successfully as ${userRole}.`,
        });
    }
    catch (e) {
        console.error("Register error:", e);
        res.status(500).json({ success: false, message: "Database error." });
    }
});
/* ─────────────────────────────────────────────
    LOGIN
───────────────────────────────────────────── */
app.post("/login", async (req, res) => {
    const { username, email, password } = req.body || {};
    const identifier = username || email;
    if (!identifier || !password)
        return res.status(400).json({
            success: false,
            message: "Username/email and password required.",
        });
    // Real IP
    let ip = req.headers["cf-connecting-ip"] ||
        req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
        req.socket.remoteAddress ||
        "unknown";
    if (ip.startsWith("::ffff:"))
        ip = ip.replace("::ffff:", "");
    const userAgent = req.headers["user-agent"] || "unknown";
    try {
        // GET USER
        const rows = await sql `SELECT * FROM users WHERE username = ${identifier} OR email = ${identifier}`;
        const user = rows[0];
        if (!user) {
            await sql `
        INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
        VALUES (null, ${identifier}, ${ip}, ${userAgent}, false)
      `;
            return res.status(404).json({ success: false, message: "User not found." });
        }
        if (user.status === "inactive") {
            await sql `
        INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
        VALUES (${user.id}, ${user.username}, ${ip}, ${userAgent}, false)
      `;
            return res.status(403).json({
                success: false,
                message: "Account is deactivated. Contact administrator.",
            });
        }
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            await sql `
        INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
        VALUES (${user.id}, ${user.username}, ${ip}, ${userAgent}, false)
      `;
            return res.status(401).json({ success: false, message: "Invalid credentials." });
        }
        // JWT
        const token = signToken({
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            isAdmin: user.role === "admin" || user.role === "superadmin",
            isSuperAdmin: user.role === "superadmin",
        });
        res.cookie("token", token, tokenCookieOptions());
        await sql `
      INSERT INTO login_history (user_id, username, ip_address, user_agent, success)
      VALUES (${user.id}, ${user.username}, ${ip}, ${userAgent}, true)
    `;
        return res.json({
            success: true,
            message: "Login successful.",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                isAdmin: user.role === "admin" || user.role === "superadmin",
                isSuperAdmin: user.role === "superadmin",
            },
        });
    }
    catch (e) {
        console.error("Login error:", e);
        return res.status(500).json({ success: false, message: "Database error." });
    }
});
/* ─────────────────────────────────────────────
    LOGOUT + /USER
───────────────────────────────────────────── */
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
            isAdmin: u.isAdmin,
            isSuperAdmin: u.isSuperAdmin,
        },
    });
});
/* ─────────────────────────────────────────────
    USERS LIST (ADMIN)
───────────────────────────────────────────── */
app.get("/users", authMiddleware, requireSuperAdmin, async (req, res) => {
    try {
        const rows = await sql `SELECT * FROM users ORDER BY id DESC`;
        res.json({ success: true, users: rows });
    }
    catch (err) {
        console.error("Users fetch error:", err);
        res.status(500).json({ success: false, message: "Cannot fetch users" });
    }
});
/* ─────────────────────────────────────────────
    CREATE USER (ADMIN)
───────────────────────────────────────────── */
app.post("/users", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password)
        return res
            .status(400)
            .json({ success: false, message: "Missing fields" });
    try {
        const hashed = await bcrypt.hash(password, 12);
        await sql `
      INSERT INTO users (username, email, password, role)
      VALUES (${username}, ${email}, ${hashed}, ${role || "user"})
    `;
        res.json({ success: true, message: "User created" });
    }
    catch (err) {
        console.error("User create error:", err);
        res.status(500).json({ success: false, message: "Cannot create user" });
    }
});
/* ─────────────────────────────────────────────
    UPDATE USER (ADMIN)
───────────────────────────────────────────── */
app.patch("/users/:id", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { username, email, role } = req.body;
    const { id } = req.params;
    try {
        await sql `
      UPDATE users
      SET username = ${username}, email = ${email}, role = ${role}
      WHERE id = ${id}
    `;
        res.json({ success: true, message: "User updated" });
    }
    catch (err) {
        console.error("User update error:", err);
        res.status(500).json({ success: false, message: "Cannot update user" });
    }
});
/* ─────────────────────────────────────────────
    CHANGE USER PASSWORD (ADMIN)
───────────────────────────────────────────── */
app.patch("/users/:id/password", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { newPassword } = req.body;
    const { id } = req.params;
    if (!newPassword)
        return res
            .status(400)
            .json({ success: false, message: "New password required" });
    try {
        const hashed = await bcrypt.hash(newPassword, 12);
        await sql `UPDATE users SET password = ${hashed} WHERE id = ${id}`;
        res.json({ success: true, message: "Password updated" });
    }
    catch (err) {
        console.error("Password update error:", err);
        res.status(500).json({ success: false, message: "Cannot update password" });
    }
});
/* ─────────────────────────────────────────────
    DELETE USER (ADMIN)
───────────────────────────────────────────── */
app.delete("/users/:id", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await sql `DELETE FROM users WHERE id = ${id}`;
        res.json({ success: true, message: "User deleted" });
    }
    catch (err) {
        console.error("User delete error:", err);
        res.status(500).json({ success: false, message: "Cannot delete user" });
    }
});
/* ─────────────────────────────────────────────
    TOGGLE ACTIVE / INACTIVE (ADMIN)
───────────────────────────────────────────── */
app.patch("/users/:id/toggle-active", authMiddleware, requireSuperAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const rows = await sql `SELECT status FROM users WHERE id = ${id}`;
        const user = rows[0];
        if (!user)
            return res.status(404).json({ success: false, message: "User not found" });
        const newStatus = user.status === "active" ? "inactive" : "active";
        await sql `UPDATE users SET status = ${newStatus} WHERE id = ${id}`;
        res.json({ success: true, status: newStatus });
    }
    catch (err) {
        console.error("Toggle error:", err);
        res.status(500).json({ success: false, message: "Toggle failed" });
    }
});
/* ─────────────────────────────────────────────
    LOGIN HISTORY (ADMIN)
───────────────────────────────────────────── */
app.get("/login-history", authMiddleware, requireSuperAdmin, async (_req, res) => {
    try {
        const rows = await sql `
      SELECT lh.*, u.username AS user_username, u.email AS user_email
      FROM login_history lh
      LEFT JOIN users u ON u.id = lh.user_id
      ORDER BY lh.id DESC
      LIMIT 200
    `;
        res.json({ success: true, history: rows });
    }
    catch (err) {
        console.error("Login history error:", err);
        res.status(500).json({ success: false, message: "Cannot load login history" });
    }
});
/* ─────────────────────────────────────────────
    FRONTEND BUILD SERVING
───────────────────────────────────────────── */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendPath = path.join(__dirname, "../frontend/dist");
app.use(express.static(frontendPath));
app.get("/hello", (_req, res) => {
    res.json({ message: "Hello from backend!" });
});
// Single Page App Fallback
app.get("*", (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
});
/* ─────────────────────────────────────────────
    START SERVER
───────────────────────────────────────────── */
app.get("/health", (_req, res) => res.json({ ok: true, env: NODE_ENV }));
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server running on port ${PORT} (${NODE_ENV})`));
