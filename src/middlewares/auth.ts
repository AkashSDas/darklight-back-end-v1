import rateLimit from "express-rate-limit";

import logger from "../logger";

/**
 * This middleware is used to limit the number of requests to the login endpoint.
 */
export const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    message: "Too many login attempts. Please try again after 60 seconds.",
  },

  handler: (req, res, next, opts) => {
    logger.error(
      `Too Many Requests: ${opts.message}\t${req.method}\t${req.url}\t${req.headers.origin}\t${req.ip}`
    );
    res.status(opts.statusCode).send(opts.message);
  },

  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
