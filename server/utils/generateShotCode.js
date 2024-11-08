const crypto = require('crypto');

const generateShortCode = (length = 6) => {
  return crypto.randomBytes(length).toString('hex').slice(0, length);
};

module.exports = generateShortCode;
