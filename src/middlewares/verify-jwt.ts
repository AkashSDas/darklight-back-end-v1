import jwt, { JwtPayload } from "jsonwebtoken";

import logger from "../logger";
import { getUser } from "../services/user.service";
import { BaseApiError } from "../utils/error";
import { AsyncMiddleware } from "../utils/types";

export const verifyJwt: AsyncMiddleware = async (req, res, next) => {
  const authHeader =
    req.headers.authorization || (req.headers.Authorization as string);

  if (!authHeader?.startsWith("Bearer ")) {
    throw new BaseApiError(401, "Unauthorized");
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET) as JwtPayload;
    const user = await getUser({ userId: decoded.userId });
    req.user = user;
    next();
  } catch (err) {
    logger.error(err);
    throw new BaseApiError(500, "Something went wrong, Please try agian");
  }
};
