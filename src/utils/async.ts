import { NextFunction, Request, Response } from "express";

import { AsyncMiddleware } from "./types";

/**
 * Catching errors in async functions
 *
 * @param fn - Middleware function
 * @returns - Promise<void>
 */
export const runAsync = (fn: AsyncMiddleware) => {
  return (req: Request, res: Response, next: NextFunction) => {
    return fn(req, res, next).catch(next);
  };
};
