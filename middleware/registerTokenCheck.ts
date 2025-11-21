import { Request, Response, NextFunction } from "express";

export function registerTokenCheck(req: Request, res: Response, next: NextFunction) {
  const token = req.query.token as string;
  const expected = process.env.REGISTER_TOKEN;

  if (!token || token !== expected) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: invalid or missing register token",
    });
  }

  next();
}
