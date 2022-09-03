import cors from "cors";
import express from "express";
import morgan from "morgan";

import { sendResponse } from "./utils/response";

// App
export const app = express();

// Middlewares
app.use(cors()); // Enable CORS
app.use(express.json()); // for parsing incoming data
app.use(express.urlencoded({ extended: true })); // parses incoming requests with urlencoded payloads
app.use(morgan("tiny")); // Log requests to the console

// Routes

// Test route
// app.get("/api/test", (req: Request, res: Response) => {
//   res.status(200).json({ msg: "🌗 DarkLight back-end (REST APIs)" });
// });

app.use("/api/auth", require("./routes/auth").router);
app.all("*", (req, res) => {
  sendResponse(res, {
    status: 404,
    error: true,
    msg: `Cannot find ${req.originalUrl} on this server!`,
  });
});
