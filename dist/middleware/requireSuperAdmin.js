export function requireSuperAdmin(req, res, next) {
    const user = req.user;
    if (!user || user.role !== "superadmin") {
        return res.status(403).json({ success: false, message: "Super admin only" });
    }
    next();
}
