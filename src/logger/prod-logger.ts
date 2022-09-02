import { createLogger, format, transports } from "winston";

const customFormat = format.printf(({ level, message, timestamp }) => {
  return `[${level}] ${timestamp} ${message}`;
});

const prodLogger = () =>
  createLogger({
    level: "info",
    format: format.combine(
      format.timestamp(), // server timestamp
      customFormat
    ),
    transports: [
      new transports.Console({}),
      new transports.File({ filename: "./logs/error.log" }),
    ],
  });

export default prodLogger;
