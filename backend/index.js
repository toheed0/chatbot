
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import authRouter from "./routers/authRouter.js";
import cookieParser from "cookie-parser";

dotenv.config();

connectDB();
const app = express();
app.use(cookieParser());
app.use(express.json());

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("Hello, World!");
});

app.use("/api/auth", authRouter);


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
