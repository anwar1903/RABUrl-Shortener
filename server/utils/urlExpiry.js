const isExpired = (expiry_date) => {
    return expiry_date && new Date() > expiry_date;
}

module.exports = { isExpired }