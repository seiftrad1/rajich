import { Request, Response, NextFunction } from "express";

export function requireSuperAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;

  if (!user || user.role !== "superadmin") {
    return res.status(403).json({ success: false, message: "Super admin only" });
  }

  next();
}
