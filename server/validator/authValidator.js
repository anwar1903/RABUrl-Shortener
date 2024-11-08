const { body } = require("express-validator");

const registerValidator = [
  body("email").isEmail().withMessage("Please enter a valid email address."),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long."),
];

const loginValidator = [
  body("email").isEmail().withMessage("Please enter a valid email address."),
  body("password").exists().withMessage("Password is required."),
];

module.exports = {
  registerValidator,
  loginValidator,
};
