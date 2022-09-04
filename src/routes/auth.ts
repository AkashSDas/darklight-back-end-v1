import { Router } from "express";

import { confirmEmail, confirmPasswordReset, forgotPassword, signup } from "../controllers/auth";
import { validateResource } from "../middlewares/validate-resourse";
import { confirmEmailSchema, confirmPasswordResetSchema, forgotPasswordSchema, signupUserSchema } from "../schema/user";
import { runAsync } from "../utils/async";
import { errorHandler } from "../utils/error";

export const router = Router();

// Routes

router
  .post(
    "/signup",
    validateResource(signupUserSchema),
    runAsync(signup),
    errorHandler
  )
  .get(
    "/confirm-email/:token",
    validateResource(confirmEmailSchema),
    runAsync(confirmEmail),
    errorHandler
  )
  .post(
    "/forgot-password",
    validateResource(forgotPasswordSchema),
    runAsync(forgotPassword),
    errorHandler
  )
  .post(
    "/confirm-password-reset/:token",
    validateResource(confirmPasswordResetSchema),
    runAsync(confirmPasswordReset),
    errorHandler
  );
