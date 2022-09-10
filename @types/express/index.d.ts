/**
 * Extending the properties of `Request` interface by using `Declaration Merging`.
 *
 * Declaration Merging is a feature of TypeScript that allows you to combine multiple
 * declarations of the same name into one. This is useful when you want to extend
 * the properties of an interface, or add new properties to an interface.
 *
 * Creating an interface with extending `Request` would work in controllers but it
 * will give error while working with router. Also code can be repeated for just having
 * same properties in Request. So using Declaration Merging is a better way to extend
 * the properties of `Request` interface.
 *
 * Below is the post that has lots of solution, some are out-date but the one used
 * for this project is working fine as of now.
 * https://stackoverflow.com/questions/37377731/extend-express-request-object-using-typescript
 *
 * Step for the the working method - To extend Express interface properties:
 * 1. create folder ${PROJECT_ROOT}/@types/express/index.d.ts
 * 2. add what's added below in that file (the code)
 * 3. in tsconfig.json, add / merge the property such that:
 *      {"compilerOptions": "typeRoots": [ "@types" ] }
 */

import { UserClass } from "../../src/models/user.model";

declare module "express-serve-static-core" {
  interface Request {
    user?: UserClass;
  }
}
