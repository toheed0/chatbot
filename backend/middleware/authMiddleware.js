import jwt from "jsonwebtoken";
import User from "../model/User.js";

export const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Access token is required",
      });
    }

    const accessToken = authHeader.split(" ")[1];

    let decoded;

    try {
      decoded = jwt.verify(
        accessToken,
        process.env.JWT_ACCESS_SECRET
      );
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired access token",
      });
    }

    const user = await User.findById(decoded.id).select(
      "-password -refreshToken"
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists",
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error("Auth Middleware Error:", error);

    return res.status(500).json({
      success: false,
      message: "Authentication failed",
    });
  }
};

export const adminOnly = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Access denied. Admin only.",
    });
  }

  next();
};