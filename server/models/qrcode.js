const mongoose = require("mongoose");

const qrCodeSchema = new mongoose.Schema({
  url_id: { type: mongoose.Schema.Types.ObjectId, ref: "Url", required: true },
  qr_code_image: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model("QRCode", qrCodeSchema);
