import { NextFunction, Request, Response } from "express";

/**
 * All of the controllers should use this type.
 */
export type AsyncController = (req: Request, res: Response) => Promise<void>;

/**
 * All of the middlewares should use this type.
 */
export type AsyncMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void>;

/**
 * All of the middlewares having `id` in query should use this type.
 */
export type AsyncIdMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction,
  id: string
) => Promise<void>;
