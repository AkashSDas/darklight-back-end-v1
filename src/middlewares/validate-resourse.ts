import { NextFunction, Request, Response } from "express";
import { AnyZodObject } from "zod";

import { sendResponse } from "../utils/response";

/**
 * To validate the input of a request and give err is the input is invalid
 * as per the schema else move to the next middleware
 *
 * @param schema - zod schema to validate the request body
 */
export const validateResource = (schema: AnyZodObject) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // If the schema is able to parse the given field then it means that
      // user has provided the required field
      schema.parse({
        body: req.body,
        query: req.query,
        params: req.params,
      });

      next();
    } catch (err: any) {
      return sendResponse(res, {
        status: 400,
        error: true,
        msg: "Missing or invalid fields",
        data: {
          errors: err.errors.map((err) => ({
            field: err.path[1], // undefined for refine error where path is ['body'] and not ['body', '<field>']
            msg: err.message,
          })),
        },
      });
    }
  };
};
