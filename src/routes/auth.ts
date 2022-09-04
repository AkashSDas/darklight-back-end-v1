import { Router } from "express";

import { confirmEmail, signup } from "../controllers/auth";
import { validateResource } from "../middlewares/validate-resourse";
import { confirmEmailSchema, signupUserSchema } from "../schema/user";
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

router.get(
  "/confirm-email/:token",
  validateResource(confirmEmailSchema),
  runAsync(confirmEmail),
  errorHandler
);
