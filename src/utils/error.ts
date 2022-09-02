import { NextFunction, Request, Response } from "express";

import logger from "../logger";
import { sendResponse } from "./response";

export class BaseApiError extends Error {
  public msg: string;
  public status: number;
  public isOperational: boolean;

  constructor(status: number, msg: string) {
    super(msg);

    this.msg = msg;
    this.status = status;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error handler
 */
export const errorHandler = (
  err: unknown,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof BaseApiError) {
    return sendResponse(res, {
      status: err.status,
      msg: err.msg,
      error: true,
    });
  }

  logger.error(err);
  const status = (err as any)?.status || 400;
  const msg = (err as any)?.msg || "Something went wrong, Please try again";
  return sendResponse(res, { status, msg, error: true });
};
