const mongoose = require("mongoose");

const urlSchema = new mongoose.Schema({
  original_url: { type: String, required: true },
  short_url: { type: String, unique: true },
  alias: { type: String, unique: true, sparse: true },
  expiry_date: {
    type: Date,
    default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  },
  password: { type: String },
  created_at: { type: Date, default: Date.now },
  access_count: { type: Number, default: 0 },
  is_active: { type: Boolean, default: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

urlSchema.index({ expiry_date: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("Url", urlSchema);
