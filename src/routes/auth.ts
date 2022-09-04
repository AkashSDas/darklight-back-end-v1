import { Router } from "express";

import { confirmEmail, signup } from "../controllers/auth";
import { validateResource } from "../middlewares/validate-resourse";
import { signupUserSchema } from "../schema/user";
import { runAsync } from "../utils/async";
import { errorHandler } from "../utils/error";

export const router = Router();

// Routes

router.post(
  "/signup",
  validateResource(signupUserSchema),
  runAsync(signup),
  errorHandler
);

router.get("/confirm-email/:token", runAsync(confirmEmail), errorHandler);
