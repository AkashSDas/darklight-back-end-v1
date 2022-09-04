import { object, string, TypeOf } from "zod";

export const signupUserSchema = object({
  body: object({
    fullName: string({ required_error: "Full name is required" }),
    username: string({ required_error: "Username is required" }),
    email: string({ required_error: "Email is required" }).email(
      "Email is invalid"
    ),
    password: string({ required_error: "Password is required" }).min(
      6,
      "Password must be more than 6 characters"
    ),
    confirmPassword: string({ required_error: "Confirm password is required" }),
  }).refine((data) => data.password === data.confirmPassword, {
    message: "Password and confirm password does not match",
  }),
});

export const confirmEmailSchema = object({
  params: object({
    token: string(),
  }),
});

export type SignupUserInput = TypeOf<typeof signupUserSchema>["body"];
export type ConfirmEmailInput = TypeOf<typeof confirmEmailSchema>["params"];
