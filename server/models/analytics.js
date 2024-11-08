const mongoose = require("mongoose");

const analyticsSchema = new mongoose.Schema({
  url_id: { type: mongoose.Schema.Types.ObjectId, ref: "Url", required: true },
  click_date: { type: Date, default: Date.now },
  referrer: { type: String, default: null },
  user_agent: { type: String, default: null },
  ip_address: { type: String, required: true },
  country: { type: String, default: null },
  city: { type: String, default: null },
  platform: { type: String },
  browser: { type: String },
});

module.exports = mongoose.model("Analytics", analyticsSchema);
