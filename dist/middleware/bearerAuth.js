export function bearerAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    const expected = `Bearer ${process.env.API_BEARER_TOKEN}`;
    // If missing or doesn't match your .env secret
    if (!authHeader || authHeader !== expected) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized: invalid or missing bearer token",
        });
    }
    next();
}
