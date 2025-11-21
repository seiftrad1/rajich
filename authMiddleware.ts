import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload, Secret } from "jsonwebtoken";

export interface AuthRequest extends Request {
  user?: string | JwtPayload;
}

export function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
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
    const secret = process.env.JWT_SECRET as Secret;

    const decoded = jwt.verify(token, secret);
    req.user = decoded; // attach user data for later use

    next();
  } catch (error: any) {
    console.error("Auth error:", error.message);
    return res.status(403).json({
      success: false,
      message: "Unauthorized or expired token",
    });
  }
}
