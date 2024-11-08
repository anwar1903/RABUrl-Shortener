const QRCode = require("qrcode");

async function generateQRCode(url) {
  try {
    const qrCodeData = await QRCode.toDataURL(url, {
      margin: 1.5,
      color: {
        dark: "#000000",
        light: "#ffffff",
      },
    });
    return qrCodeData;
  } catch (error) {
    console.error("Error generating QR code:", error);
    throw new Error("QR code generation failed");
  }
}

module.exports = generateQRCode;
