import crypto from "crypto";
import { NextFunction, Request, Response } from "express";

import logger from "../logger";
import { ConfirmEmailInput, ConfirmForgotPasswordInput, ForgotPasswordInput, SignupUserInput } from "../schema/user";
import { createUser, getUser, updateUser } from "../services/user";
import { BaseApiError } from "../utils/error";
import { sendResponse } from "../utils/response";
import { sendEmail } from "../utils/send-email";

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

  const jwtToken = user.getJwtToken();

  // Email verify token
  const emailVerifyToken = user.getEmailVerifiedToken();
  await user.save({ validateModifiedOnly: true }); // saving token info to DB
  logger.info(user);

  // Doing this after the user is saved to DB because if it is done above the passwordDigest will be undefined
  // and it will give error in `pre` save hook (in the bcrypt.hash function) that
  // Error: Illegal arguments: undefined, number (undefined is the passwordDigest)
  user.passwordDigest = undefined; // remove the password digest from the response

  // URL sent to user for verifying user's email
  // const emailVerificationUrl = `${process.env.APP_URL}/auth/verify-email?token=${emailVerificationToken}`;
  const url = `/api/auth/confirm-email/${emailVerifyToken}`;
  const confirmEmailURL = `${req.protocol}://${req.get("host")}${url}`;

  const opts = {
    to: user.email,
    subject: "Confirm your email",
    text: "Confirm your email",
    html: `<p>Confirm your email with this 🔗 <a href="${confirmEmailURL}">link</a></p>`,
  };

  try {
    // Sending email
    await sendEmail(opts);
    return sendResponse(res, {
      status: 200,
      error: false,
      msg: "Account created successfully. Please verify your email",
      data: { user, token: jwtToken },
    });
  } catch (err) {
    // If the email fails to send them make emailVerify token and expirt to undefined
    await updateUser(
      { userId: user.userId },
      {
        emailVerificationToken: null,
        emailVerificationTokenExpires: null,
      }
    );

    if (user) {
      sendResponse(res, {
        status: 200,
        error: false,
        msg: "Account created successfully. Login and verify your email",
        data: { user, token: jwtToken },
      });
    }

    logger.error(err);
    throw new BaseApiError(500, "Something went wrong, Please try again");
  }
};

/**
 * `Verfiy` user's email account and make it `active`
 */
export const confirmEmail = async (
  req: Request<ConfirmEmailInput>,
  res: Response
) => {
  // Encrypting the token, to see if the token sent the same token OR not
  const encryptToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  // User having the token and token is not expired
  const user = await getUser({
    emailVerificationToken: encryptToken,
    emailVerificationTokenExpires: { $gt: new Date(Date.now()) },
  });
  logger.info(req.params.token);
  if (!user) throw new BaseApiError(400, "Invalid or expired token");

  // Updating the user's emailVerified field to true
  await updateUser(
    { userId: user.userId },
    {
      isActive: true,
      emailVerified: true,
      emailVerificationToken: null,
      emailVerificationTokenExpires: null,
    }
  );

  return sendResponse(res, {
    status: 200,
    error: false,
    msg: "Email is verified and your account is activated",
  });
};

/**
 * Send user forgot password token
 */
export const forgotPassword = async (
  req: Request<{}, {}, ForgotPasswordInput>,
  res: Response
) => {
  // User having the token and token is not expired
  const user = await getUser({ email: req.body.email });
  if (!user) throw new BaseApiError(400, "User does not exists");

  // Generating forgot password token
  const forgotPasswordToken = user.getPasswordResetToken();
  await user.save({ validateModifiedOnly: true }); // saving token info to DB

  // URL sent to user to reset user's password
  const url = `/api/auth/confirm-password-reset/${forgotPasswordToken}`;
  const passwordResetURL = `${req.protocol}://${req.get("host")}${url}`;

  const opts = {
    to: user.email,
    subject: "Reset your password",
    text: "Reset your password",
    html: `<p>Reset your password with this 🔗 <a href="${passwordResetURL}">link</a></p>`,
  };

  try {
    // Sending email
    await sendEmail(opts);
    return sendResponse(res, {
      status: 200,
      error: false,
      msg: "Password reset instructions sent to your email",
    });
  } catch (err) {
    // If password reset failed then make forgotPasswordToken and expiry to undefined
    await updateUser(
      { userId: user.userId },
      {
        passwordResetToken: null,
        passwordResetTokenExpires: null,
      }
    );

    throw new BaseApiError(500, "Something went wrong, Please try again");
  }
};

/**
 * Reset user's password reset if they have valid token
 */
export const confirmPasswordReset = async (
  req: Request<
    ConfirmForgotPasswordInput["params"],
    {},
    ConfirmForgotPasswordInput["body"]
  >,
  res: Response
) => {
  // Encrypting the token, to see if the token sent the same token OR not
  const encryptToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  // User having the token and token is not expired
  const user = await getUser({
    passwordResetToken: encryptToken,
    passwordResetTokenExpires: { $gt: new Date(Date.now()) },
  });
  if (!user) throw new BaseApiError(400, "Invalid or expired token");

  user.passwordDigest = req.body.password; // this will be converted to hash in `pre` Mongoose middleware
  user.passwordResetToken = null;
  user.passwordResetTokenExpires = null;

  // Here no validateModifiedOnly needs to be given since we're updating few fields
  // and user has already registered meaning all necessary feilds are filled
  await user.save();
  user.passwordDigest = undefined; // remove the password digest from the response

  const jwtToken = user.getJwtToken();
  sendResponse(res, {
    status: 200,
    error: false,
    msg: "Password reset is successful",
    data: { user, token: jwtToken },
  });
};
