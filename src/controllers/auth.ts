import { NextFunction, Request, Response } from "express";

import logger from "../logger";
import { SignupUserInput } from "../schema/user";
import { createUser, getUser } from "../services/user";
import { BaseApiError } from "../utils/error";
import { sendResponse } from "../utils/response";

/**
 * Signup user controller
 */
export const signup = async (
  req: Request<{}, {}, SignupUserInput>,
  res: Response,
  next: NextFunction
) => {
  const { fullName, username, email, password: plainTextPwd } = req.body;

  // Check if the user already exists
  const exists = await Promise.all([getUser({ username }), getUser({ email })]);
  if (exists.some((user) => (user ? true : false))) {
    return next(new BaseApiError(400, "Username or email already exists"));
  }

  // Creating a user document
  const user = await createUser({
    fullName,
    username,
    email,
    passwordDigest: plainTextPwd, // it will be conveted to hash in `pre` Mongoose middleware
  });
  logger.info(user);
  user.passwordDigest = undefined; // remove the password digest from the response
  const token = user.getJwtToken();
  sendResponse(res, {
    status: 200,
    error: false,
    msg: "User created successfully",
    data: { user, token },
  });
};
