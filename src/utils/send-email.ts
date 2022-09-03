import { createTransport } from "nodemailer";

interface ISendEmailOptions {
  to: string; // to email address
  subject: string;
  text: string;
  html?: string;
}

/**
 * Send email
 *
 * @param opts - Send email options
 * @returns Promise<SMTPTransport.SentMessageInfo>
 */
export const sendEmail = async (opts: ISendEmailOptions) => {
  const transporter = createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 0,
    auth: {
      user: process.env.SMTP_USERNAME,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  const msg = {
    from: process.env.FROM_EMAIL,
    to: opts.to,
    subject: opts.subject,
    text: opts.text,
    html: opts.html,
  };

  return transporter.sendMail(msg);
};
