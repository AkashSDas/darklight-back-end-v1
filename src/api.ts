import cors from "cors";
import express, { Request, Response } from "express";
import morgan from "morgan";

// App
export const app = express();

// Middlewares
app.use(cors()); // Enable CORS
app.use(express.json()); // for parsing incoming data
app.use(express.urlencoded({ extended: true })); // parses incoming requests with urlencoded payloads
app.use(morgan("tiny")); // Log requests to the console

// Routes

// Test route
app.get("/api/test", (req: Request, res: Response) => {
  res.status(200).json({ msg: "🌗 DarkLight back-end (REST APIs)" });
});
