import { createLogger, format, transports } from "winston";

const customFormat = format.printf(({ level, message, timestamp }) => {
  return `[${level}] ${timestamp} ${message}`;
});

const devLogger = () =>
  createLogger({
    level: "debug",
    format: format.combine(
      format.colorize(),
      format.timestamp({ format: "HH:mm:ss" }),
      customFormat
    ),
    transports: [new transports.Console({})],
  });

export default devLogger;
