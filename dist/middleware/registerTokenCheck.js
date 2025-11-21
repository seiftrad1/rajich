export function registerTokenCheck(req, res, next) {
    const token = req.query.token;
    const expected = process.env.REGISTER_TOKEN;
    if (!token || token !== expected) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized: invalid or missing register token",
        });
    }
    next();
}
