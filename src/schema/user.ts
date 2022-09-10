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
    path: ["confirmPassword"],
  }),
});

export const confirmEmailSchema = object({
  params: object({
    token: string(),
  }),
});

export const forgotPasswordSchema = object({
  body: object({
    email: string({ required_error: "Email is required" }).email(
      "Email is invalid"
    ),
  }),
});

export const confirmPasswordResetSchema = object({
  params: object({
    token: string(),
  }),
  body: object({
    password: string({ required_error: "Password is required" }).min(6, {
      message: "Password must be more than 6 characters",
    }),
    confirmPassword: string({ required_error: "Confirm password is required" }),
  }).refine((data) => data.password === data.confirmPassword, {
    message: "Password and confirm password does not match",
    path: ["confirmPassword"],
  }),
});

export const loginSchema = object({
  body: object({
    email: string({ required_error: "Email is required" }).email(
      "Email is invalid"
    ),
    password: string({ required_error: "Password is required" }),
    confirmPassword: string({ required_error: "Confirm password is required" }),
  }).refine((data) => data.password === data.confirmPassword, {
    message: "Password and confirm password does not match",
    path: ["confirmPassword"],
  }),
});

export type SignupUserInput = TypeOf<typeof signupUserSchema>["body"];
export type ConfirmEmailInput = TypeOf<typeof confirmEmailSchema>["params"];
export type ForgotPasswordInput = TypeOf<typeof forgotPasswordSchema>["body"];
export type ConfirmForgotPasswordInput = TypeOf<
  typeof confirmPasswordResetSchema
>;
export type LoginInput = TypeOf<typeof loginSchema>["body"];
