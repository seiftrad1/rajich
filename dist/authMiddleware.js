import jwt from "jsonwebtoken";
export function authMiddleware(req, res, next) {
    try {
        // Check for "Authorization: Bearer <token>"
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Missing or invalid Authorization header",
            });
        }
        const token = authHeader.split(" ")[1];
        const secret = process.env.JWT_SECRET;
        const decoded = jwt.verify(token, secret);
        req.user = decoded; // attach user data for later use
        next();
    }
    catch (error) {
        console.error("Auth error:", error.message);
        return res.status(403).json({
            success: false,
            message: "Unauthorized or expired token",
        });
    }
}
