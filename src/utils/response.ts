import { Response } from "express";

/**
 * Send reponse options
 */
interface ResponseOptions {
  status: number;
  error: boolean;
  msg: string;
  data?: { [key: string]: any };
}

/**
 * All of the responses should be send using this function.
 *
 * Middlewares shouldn't use this as this send response to the client thus
 * breaking the middleware chain i.e. after this runs nothing else will run
 * as the response is sent to the client.
 *
 * @opts - Options for the response
 * @res - Response object
 * @returns - void
 * @example
 * sendResponse(res, { status: 200, msg: "Success" });
 */
export const sendResponse = (res: Response, opts: ResponseOptions) => {
  const { status, error, msg, data } = opts;
  res.status(status).json({ error, msg, data });
};
