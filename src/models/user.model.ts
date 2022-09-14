/**
 * ✅ Using Typegoose (actively maintained / mostly used)
 *
 * https://typegoose.github.io/typegoose/docs/guides/quick-start-guide
 *
 * An issue that arieses when using multiple interfaces to define schema, instance
 * and static methods for our class is that they have to kept in sync with each other.
 * Now this will become a problem when lot of devs will be working on the project and
 * sooner or later someone the interface and schema will be out of sync.
 *
 * Read more on how to integrate TypeScript with Mongoose here:
 * https://stackoverflow.com/questions/34482136/mongoose-the-typescript-way
 */

import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { SchemaTypes, Types } from "mongoose";
import { nanoid } from "nanoid";
import validator from "validator";

import { getModelForClass, modelOptions, post, pre, prop, Severity } from "@typegoose/typegoose";

enum ProviderEnum {
  GOOGLE = "google",
  FACEBOOK = "facebook",
  LOCAL = "local",
}

export enum RoleEnum {
  ADMIN = "admin",
  STUDENT = "student",
  INSTRUCTOR = "instructor",
}

// SOCIAL AUTHENTICATION PROVIDER MODEL
class SocialAuthenticationProvider {
  // 0 value as default to represent no value
  @prop({
    type: SchemaTypes.String,
    required: [true, "Provider ID is required"],
    default: "0",
  })
  public id: string;

  @prop({
    type: SchemaTypes.String,
    required: [true, "Provider is required"],
    enum: ProviderEnum,
  })
  public provider: ProviderEnum;
}

// Profile pic sub-document
class ProfilePic {
  @prop({ type: SchemaTypes.String })
  public id: string;

  @prop({ type: SchemaTypes.String })
  public URL: string;
}

// USER SCHEMA

@pre<UserClass>("save", async function (next) {
  // Encrypt user's plain text password before saving user
  // Only go ahead if the password was modified (not on other update functions)
  if (!this.isModified("passwordDigest")) return next();
  this.passwordDigest = await bcrypt.hash(this.passwordDigest, 12);
})
@post<UserClass>("save", function (error, user, next) {
  // Handle error for trying to create user with duplicate email
  if (error.name === "MongoServerError" && error.code === 11000) {
    next(new Error(`User with ${user.email} already exists`));
  } else {
    next();
  }
})
@modelOptions({
  schemaOptions: {
    timestamps: true,
    toJSON: { virtuals: true },
    typeKey: "type",
  },
  options: { allowMixed: Severity.ALLOW, customName: "user" },
})
export class UserClass {
  // PROPERTIES

  @prop({
    type: SchemaTypes.String,
    required: [true, "User ID is required"],
    unique: true,
    maxlength: [24, "User ID must be less than 24 characters"],
    immutable: true,
    default: () => nanoid(24),
  })
  public userId: string;

  @prop({
    type: SchemaTypes.String,
    required: [true, "Full name is required"],
    maxlength: [240, "Full name must be less than 240 characters"],
    minlength: [6, "Full name must be more than 6 characters"],
    trim: true,
  })
  public fullName: string;

  @prop({
    type: SchemaTypes.String,
    required: [true, "Username is required"],
    maxlength: [120, "Username must be less than 120 characters"],
    minlength: [3, "Username must be more than 3 characters"],
    unique: true,
    trim: true,
  })
  public username: string;

  @prop({
    type: SchemaTypes.String,
    required: [true, "Email is required"],
    unique: true,
    validate: [validator.isEmail, "Email is invalid"],
  })
  public email: string;

  @prop({ type: () => ProfilePic })
  public profilePic?: ProfilePic;

  @prop({
    // ValidationError: user validation failed: roles: Cast to string failed for value "[ 'student' ]" (type Array) at path "roles" at model.Document.invalidate
    // type: () => [String],
    type: () => SchemaTypes.Array,

    // InvalidEnumTypeError: Invalid Type used for options "enum" at "user.roles"! [E012]
    // enum: RoleEnum,

    required: true,
    default: [RoleEnum.STUDENT],
  })
  public roles: ("admin" | "instructor" | "student")[];

  @prop({ type: SchemaTypes.String, select: false })
  public passwordDigest?: string;

  @prop({ type: SchemaTypes.String, select: false })
  public passwordResetToken?: string | null;

  @prop({ type: SchemaTypes.Date, select: false })
  public passwordResetTokenExpires?: Date | null;

  @prop({
    type: SchemaTypes.Boolean,
    required: [true, "Active status is required"],
    default: false,
  })
  public isActive: boolean;

  @prop({
    type: SchemaTypes.Boolean,
    required: [true, "Email verified is required"],
    default: false,
  })
  public emailVerified: boolean;

  @prop({ type: SchemaTypes.String, select: false })
  public emailVerificationToken?: string | null;

  @prop({ type: SchemaTypes.Date, select: false })
  public emailVerificationTokenExpires?: Date | null;

  // Sub doc array
  @prop({ type: () => SocialAuthenticationProvider })
  public socialAuthentication?: SocialAuthenticationProvider[];

  // INSTANCE METHODS

  /**
   * Validate user's password with given password
   *
   * @param givenPassword - password given by the user
   * @returns true if the given password matches the user's password else false
   */
  async isAuthenticated(givenPassword: string): Promise<boolean> {
    return bcrypt.compare(givenPassword, this.passwordDigest);
  }

  /**
   * Get a JWT token for the user
   *
   * @returns the generated JWT token
   */
  getJwtToken(): string {
    const payload = { id: this._id, username: this.username };
    return jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRY,
    });
  }

  /**
   * Generate a password reset token and set it to the user
   *
   * @returns the generated password reset token
   */
  getPasswordResetToken(): string {
    // Generate long and random string, this will be sent to user
    // and user is excepted to sent back this token to the backend which then will be
    // hashed and then compared with this.verifyToken
    const token = crypto.randomBytes(20).toString("hex");

    // Hash the token and store it in the database
    this.passwordResetToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // Set the token expiry time to 10 minutes
    this.passwordResetTokenExpires = new Date(Date.now() + 10 * 60 * 1000);

    return token;
  }

  /**
   * Generate a email verification token and set it to the user
   *
   * @returns the generated email verification token
   */
  getEmailVerifiedToken(): string {
    const token = crypto.randomBytes(20).toString("hex");
    this.emailVerificationToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // Set the token expiry time to 10 minutes
    this.emailVerificationTokenExpires = new Date(Date.now() + 10 * 60 * 1000);

    return token;
  }

  // VIRUTALS

  _id!: Types.ObjectId;
  public get id() {
    return this._id.toHexString();
  }
}

const UserModel = getModelForClass(UserClass);
export default UserModel;
