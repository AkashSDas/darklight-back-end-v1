import { FilterQuery } from "mongoose";

import UserModel, { UserClass } from "../models/user";

/**
 * Find one user
 *
 * @param filter - filter query for filtering out the user
 * @returns A promise of finding the one user that matches the filter
 */
export const getUser = async (filter: FilterQuery<UserClass>) => {
  return UserModel.findOne(filter, "-__v").exec();
};

/**
 * Get user count that matches the filter
 *
 * @param filter - filter query for filtering out the user
 * @returns A promise of getting the number of users matching the filter
 */
export const userExists = async (filter: FilterQuery<UserClass>) => {
  return UserModel.count(filter).exec();
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

/**
 * Updater user document
 *
 * @param filter - filter query for filtering out the user
 * @param data - user data
 * @returns A promise for updating the user document
 */
export const updateUser = (
  filter: FilterQuery<UserClass>,
  data: Partial<UserClass>
) => {
  return UserModel.findOneAndUpdate(filter, data, {
    new: true,
    fields: "-_id -_v",
  });
};
