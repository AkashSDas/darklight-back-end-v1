import { config } from "dotenv";

import { app } from "./api";
import { connectToMongoDB } from "./config/db";
import logger from "./logger";

// Load env variables
if (process.env.NODE_ENV !== "production") config();

// Connect to MongoDB
connectToMongoDB();

// Start the server
const port = process.env.PORT || 8002;
app.listen(port, () =>
  logger.info(`API is available on http://localhost:${port}/api`)
);
