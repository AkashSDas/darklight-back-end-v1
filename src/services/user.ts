import { FilterQuery } from "mongoose";

import UserModel, { UserClass } from "../models/user";

/**
 * Find one user
 *
 * @param filter - filter query for filtering out the user
 * @returns A promise of finding the one user that matches the filter
 */
export const getUser = async (filter: FilterQuery<UserClass>) => {
  return UserModel.findOne(filter, "-_id -__v").exec();
};

/**
 * Creates an new user document in the database.
 *
 * @param data - user data
 * @returns A promise for saving the new user document
 */
export const createUser = (data: Partial<UserClass>) => {
  const user = new UserModel(data);
  return user.save();
};
