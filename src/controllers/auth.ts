import { NextFunction, Request, Response } from "express";

import logger from "../logger";
import { ConfirmEmailInput, SignupUserInput } from "../schema/user";
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

  // Send email verification token
  const emailVerificationToken = user.getEmailVerifiedToken();
  await user.save({ validateModifiedOnly: true }); // saving token info to DB
  logger.info(user);

  // Doing this after the user is saved to DB because if it is done above the passwordDigest will be undefined
  // and it will give error in `pre` save hook (in the bcrypt.hash function) that
  // Error: Illegal arguments: undefined, number (undefined is the passwordDigest)
  user.passwordDigest = undefined; // remove the password digest from the response

  // URL sent to user for verifying user's email
  // const emailVerificationUrl = `${process.env.APP_URL}/auth/verify-email?token=${emailVerificationToken}`;
  const url = `/api/auth/confirm-email/${emailVerificationToken}`;
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
        emailVerificationToken: undefined,
        emailVerificationTokenExpires: undefined,
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
  // User having the token and token is not expired
  const user = await getUser({
    emailVerificationToken: req.params.token,
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
      emailVerificationToken: undefined,
      emailVerificationTokenExpires: undefined,
    }
  );

  return sendResponse(res, {
    status: 200,
    error: false,
    msg: "Email is verified and your account is activated",
  });
};
