/**
 * ✅ This way of creating models is recommended by Mongoose.
 *
 * https://mongoosejs.com/docs/typescript.html
 * https://mongoosejs.com/docs/typescript/statics-and-methods.html
 *
 * 👎🏾 The one downside to this approach is that you will define your schema twice.
 * Once in the model and once in the interface. So both of them have to be in sync
 * (it's the work of dev). Now this will become a problem when lot of devs will be
 * working on the project and sooner or later someone the interface and schema will
 * be out of sync.
 *
 * Read more on how to integrate TypeScript with Mongoose here:
 * https://stackoverflow.com/questions/34482136/mongoose-the-typescript-way
 */

import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { model, Model, Schema, SchemaTypes } from "mongoose";
import validator from "validator";

// Interface representing a document in MongoDB.
interface IUser {
  userId: string;
  fullName: string;
  username: string;
  email: string;
  profilePic?: { id?: string; URL?: string };
  roles: ("student" | "instructor" | "admin")[];
  dateOfBirth: Date;
  gender: "male" | "female" | "transgender" | "prefer not to answer";

  // Password hash
  passwordDigest?: string;

  // Reset password
  passwordResetToken?: string;
  passwordResetTokenExpiry?: Date;

  // Is email verified
  emailVerified?: boolean;
  emailVerificationToken?: string;
  emailVerificationTokenExpiry?: Date;

  // OAuth data
  socialAuthentication?: {
    google?: { id: string };
    facebook?: { id: string };
    twitter?: { id: string };
  };
}

// All of the instance methods
interface IUserMethods {
  isAuthenticated: (givenPassword: string) => Promise<boolean>;
  getJwtToken: () => string;
  getPasswordResetToken: (expiresIn: Date) => string;
  getEmailVerifiedToken: (expiresIn: Date) => string;
}

// All of the static methods
interface UserModel extends Model<IUser, {}, IUserMethods> {
  myStaticMethod(): string;
}

// Model type that knows about IUserMethods
// type UserModel = Model<IUser, {}, IUserMethods>;

// Schema corresponding to the document interface.
// Schema should also know about IUserMethods
const userSchema = new Schema<IUser, UserModel, IUserMethods>(
  {
    userId: {
      type: SchemaTypes.String,
      required: [true, "User ID is required"],
      unique: true,
      maxlength: [12, "User ID must be less than 12 characters"],
    },
    fullName: {
      type: SchemaTypes.String,
      required: [true, "Full name is required"],
      trim: true,
      maxlength: [240, "Full name must be less than 240 characters"],
      minlength: [6, "Full name must be greater than 6 characters"],
    },
    username: {
      type: SchemaTypes.String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
      maxlength: [128, "Username must be less than 240 characters"],
      minlength: [3, "Username must be greater than 6 characters"],
    },
    email: {
      type: SchemaTypes.String,
      required: [true, "Email is required"],
      unique: true,
      validate: [validator.isEmail, "Email is invalid"],
    },
    profilePic: {
      _id: false,
      type: {
        id: { type: SchemaTypes.String },
        URL: { type: SchemaTypes.String },
      },
    },
    roles: {
      type: [SchemaTypes.String],
      required: [true, "A single role is required"],
      default: ["student"],
    },

    dateOfBirth: {
      type: SchemaTypes.Date,
      required: [true, "Date of birth is required"],
      validate: [
        {
          validator: (date: Date) => date && validator.isDate(date.toString()),
          msg: "Date of birth is invalid",
        },
        {
          validator: (date: Date) => {
            // User should not be of born in the future and user's age should not be more than 130 years
            return (
              date &&
              date.getTime() > Date.now() * 130 * 365 * 24 * 60 * 60 * 1000 && // 130 yrs back from now
              date.getTime() < Date.now() * 1 * 24 * 60 * 60 * 1000 // current time
            );
          },
          msg: "Date of birth is invalid",
        },
      ],
    },

    gender: {
      type: SchemaTypes.String,
      // enum: ["male", "female", "transgender", "prefer not to answer"],
      enum: {
        values: ["male", "female", "transgender", "prefer not to answer"],
        message: "{VALUE} option is not available",
      },
      default: "prefer not to answer",
      required: [true, "Gender is required info"],
    },

    passwordDigest: { type: SchemaTypes.String, select: false },
    passwordResetToken: { type: SchemaTypes.String, select: false },
    passwordResetTokenExpiry: { type: SchemaTypes.Date, select: false },
    emailVerified: {
      type: SchemaTypes.Boolean,
      required: [true, "Email verified field is required"],
      default: false,
    },
    emailVerificationToken: { type: SchemaTypes.String, select: false },
    emailVerificationTokenExpiry: { type: SchemaTypes.Date, select: false },

    socialAuthentication: {
      type: {
        google: { id: { type: SchemaTypes.String, required: true } },
        facebook: { id: { type: SchemaTypes.String, required: true } },
        twitter: { id: { type: SchemaTypes.String, required: true } },
      },
    },
  },

  {
    timestamps: true,
    // No typing for static method here
    // statics: {
    //   myStaticMethod() {
    //     return "static method";
    //   },
    // },
  }
);

// Static method, no typing for static methods
userSchema.statics.myStaticMethod = function () {
  return "static method";
};
// userSchema.static("myStaticMethod", function () {
//   return "static method";
// });

// USER SCHEMA HOOKS

// Encrypt user's plain text password before saving user
userSchema.pre("save", async function (this, next) {
  // Only go ahead if the password was modified (not on other update functions)
  if (!this.isModified("passwordDigest")) return next();
  this.passwordDigest = await bcrypt.hash(this.passwordDigest, 12);
});

// Handle error for trying to create user with duplicate email
userSchema.post(
  "save",
  function (error: any, doc: IUser, next: (err?: NativeError) => void) {
    if (error.name === "MongoServerError" && error.code === 11000) {
      next(new Error(`User with ${doc.email} already exists`));
    } else {
      next();
    }
  }
);

// USER INSTANCE METHODS

// This is a better approach for defining methods to the model
// as it enforces type safety
//
// Validate user password with given password
userSchema.methods.isAuthenticated = async function (
  this: IUser,
  givenPassword: string
) {
  return bcrypt.compare(givenPassword, this.passwordDigest);
};

// Create and return JWT token
userSchema.method("getJwtToken", function (this: IUser) {
  const payload = { id: (this as any)._id, username: this.username };
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRY,
  });
});

// Create password reset token
userSchema.methods.getPasswordResetToken = function (
  this: IUser,
  expiresIn: Date
) {
  // Generate long and random string, this will be sent to user
  // and user is excepted to sent back this token to the backend which then will be
  // hashed and then compared with this.verifyToken
  const token = crypto.randomBytes(20).toString("hex");

  // Getting a hash
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  this.passwordResetTokenExpiry = expiresIn;

  return token;
};

// Create email verified token
userSchema.methods.getEmailVerifiedToken = function (
  this: IUser,
  expiresIn: Date
) {
  const token = crypto.randomBytes(20).toString("hex");

  this.emailVerificationToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  this.emailVerificationTokenExpiry = expiresIn;

  return token;
};

// Duplicate the ID field.
userSchema.virtual("id").get(function (this: IUser) {
  return (this as any)._id.toHexString();
});

// Ensure virtual fields are serialised.
userSchema.set("toJSON", { virtuals: true });

const User = model<IUser, UserModel>("User2", userSchema);
const tmpUser = new User({}); // types not forcing required fields, enum values, etc.

const run = async () => {
  const user = await User.create({
    userId: "123",
    fullName: "james bond",
    username: "jamesbond",
    email: "james@hotmail.io",
    dateOfBirth: new Date(),
    roles: "student",
    passwordDigest: "password",
  });

  await user.isAuthenticated("password");
  User.myStaticMethod();
};
