# darklight back-end

REST API back-end for the 🌗 DarkLight project.

## Conventions

- Write `controllers` and `routes` filenames sames where `controller` is for a `route`
- Write file/folder names using `kebab-case`
- All of the APIs should be under the route `/api` (Eg: `/api/users`)
- The `/controllers` don't talk to databases, `/services` do

## Nodemailer

- The `nodemailer` module is used to send emails
- `Mailtrap` is used to test the emails
