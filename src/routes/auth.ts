import { Router } from "express";

import { checkAuth, confirmEmail, confirmPasswordReset, forgotPassword, login, logout, refresh, signup } from "../controllers/auth";
import { validateResource } from "../middlewares/validate-resourse";
import { verifyJwt } from "../middlewares/verify-jwt";
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
  )
  .post("/login", runAsync(login), errorHandler) // loginLimiter,
  .get("/refresh", runAsync(refresh), errorHandler)
  .get("/logout", runAsync(logout), errorHandler)
  .get("/check", runAsync(verifyJwt), runAsync(checkAuth), errorHandler);
