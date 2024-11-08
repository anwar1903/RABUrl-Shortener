const express = require("express");
const router = express.Router();
const Url = require("../models/url");
const generateShortCode = require("../utils/generateShortCode");
const bcrypt = require("bcryptjs");
const { isExpired } = require("../utils/urlExipry");
const Analytics = require("../models/analytics");
const User = require("../models/user");
const QRCode = require("../models/qrcode");
const generateQRCode = require("../utils/qrcodeGenerator");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const authenticate = require("../middleware/auth");
const { loginValidator } = require("../validators/authValidators");
const sendEmail = require("../utils/emailService");
const checkUrlSafety = require("../utils/spamCheck");
const logAnalytics = require("../utils/logAnalytics");

// Test route
router.get("/", (req, res) => {
  res.send("Hello World!!");
});

router.get("/getUrls", authenticate, async (req, res) => {
  console.log("Authenticated user ID:", req.user.id);
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    console.log("User ID: ", req.user.id);
    const urls = await Url.find({ user_id: req.user.id });
    if (!urls.length) {
      return res.status(404).json({ message: "No URLs found" });
    }

    const urlIds = urls.map((url) => url._id);

    const qrcodes = await QRCode.find({ url_id: { $in: urlIds } });
    if (!qrcodes.length) {
      return res.status(404).json({ message: "No QR Codes found" });
    }

    // Combine URLs and their corresponding QR codes
    const urlsWithQrCodes = urls.map((url) => {
      return {
        ...url._doc,
        qr_code:
          qrcodes.find((qr) => qr.url_id.toString() === url._id.toString()) ||
          null,
      };
    });

    res.status(200).json(urlsWithQrCodes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error });
  }
});

// Fetch all URLs (for testing or admin purposes)
router.get("/getAll", async (req, res) => {
  try {
    const urls = await Url.find();
    res.json(urls);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/getUser", authenticate, (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(404).json("User Not Found");
  }

  const user = req.user.id;
  res.status(200).json({ userId: user });
});

router.get("/checkAuth", (req, res) => {
  const token = req.cookies.token; // Access token from cookies
  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized", isAuthenticated: false });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .json({ message: "Unauthorized", isAuthenticated: false });
    }
    // Token is valid; return user data
    res.status(201).json({ isAuthenticated: true });
  });
});

router.get("/analytics/:shortUrl", authenticate, async (req, res) => {
  const { shortUrl } = req.params;
  console.log("Short ID: ", shortUrl);

  try {
    const url = await Url.findOne({
      $or: [{ short_url: shortUrl }, { alias: shortUrl }],
    });

    if (!url) {
      return res.status(404).json({ message: "URL not found" });
    }

    const analyticsData = await Analytics.find({ url_id: url._id });

    if (!analyticsData) {
      return res
        .status(404)
        .json({ message: "No analytics data found for this URL" });
    }

    const qrcodeData = await QRCode.find({ url_id: url._id });

    if (!qrcodeData) {
      return res
        .status(404)
        .json({ message: "No QR Code image found for this URL" });
    }

    res
      .status(200)
      .json({ analytics: analyticsData, url: url, qrcode: qrcodeData });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.post("/shorten", authenticate, async (req, res) => {
  const { original_url, alias, expiry_date, password, user_id } = req.body;

  console.log("Req Body: ", req.body);

  const isUnsafe = await checkUrlSafety(original_url);
  console.log("isSafe: ", isUnsafe);
  if (isUnsafe) {
    return res.status(400).json({
      message:
        "The provided URL is considered unsafe. Please use a different URL.",
    });
  }

  try {
    // **Custom Alias Check**: Verify if a custom alias already exists in the database
    if (alias) {
      const existingAlias = await Url.findOne({ alias: alias });
      if (existingAlias) {
        return res.status(400).json({ error: "Custom alias is already taken" });
      }
    }

    // **Password Hashing**: If a password is provided, hash it for security
    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

    // **Expiry Date**: If no expiry date is given, set it to 1 year from the current date
    const expirationDate = expiry_date
      ? new Date(expiry_date)
      : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    console.log("Expiration Date: ", expirationDate);

    // **Generate Short URL or Use Custom Alias**: Use alias if provided, else generate one
    const shortUrl = alias || generateShortCode(6);

    // **Save URL Document**: Create and save the new URL with the provided features
    const urlData = {
      original_url,
      short_url: shortUrl,
      expiry_date: expirationDate,
      password: hashedPassword,
      user_id,
      access_count: 0, // Initialize access count
    };

    // Only add alias if it is provided
    if (alias) {
      urlData.alias = alias;
    }

    const url = new Url(urlData);
    await url.save();
    console.log("URL saved successfully:", url);

    const qrCodeImage = await generateQRCode(
      `${process.env.BASE_URL}/${url.short_url}`
    );
    const qrCodeData = new QRCode({
      url_id: url._id,
      qr_code_image: qrCodeImage,
    });
    await qrCodeData.save();
    console.log("QR Code saved successfully:", qrCodeData);

    res.status(201).json({
      short_url: url.short_url,
      alias: url.alias ? url.alias : url.short_url,
      qr_code: qrCodeData.qr_code_image,
    });
  } catch (error) {
    console.error("Error in /shorten route:", error); // Log the error
    res.status(500).json({
      message: "An internal server error occurred.",
      error: error.message,
    });
  }
});

router.delete("/delete/:shortUrl", authenticate, async (req, res) => {
  const { shortUrl } = req.params;

  try {
    // Find the URL document
    const url = await Url.findOne({
      $or: [{ short_url: shortUrl }, { alias: shortUrl }],
    });

    if (!url) {
      return res.status(404).json({ message: "URL not found" });
    }

    // Check if the authenticated user is the owner of the URL
    if (url.user_id.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "You can only delete your own URLs" });
    }

    // Delete the URL
    await Url.deleteOne({ _id: url._id });

    // Optionally, delete any associated QR codes
    await QRCode.deleteOne({ url_id: url._id });

    res.status(200).json({ message: "URL deleted successfully" });
  } catch (error) {
    console.error("Error details:", error); // Log the error details
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.get("/:shortUrl", async (req, res) => {
  const { shortUrl } = req.params;
  console.log("Short URL: ", shortUrl);
  try {
    // Find the URL document
    const url = await Url.findOne({
      $or: [{ short_url: shortUrl }, { alias: shortUrl }],
    });

    if (!url) {
      return res.status(404).json({ message: "URL not found" });
    }

    // Expiry check
    if (isExpired(url.expiry_date)) {
      return res.status(410).json({ message: "This link has expired" });
    }

    // Check if URL is password-protected
    if (url.password) {
      // Send response indicating password requirement
      return res.status(403).json({ message: "Password required" });
    }

    // If no password is needed, increment access count and redirect
    url.access_count++;
    await url.save();
    await logAnalytics(url, req);
    // return res.redirect(url.originalUrl);
    return res.json(url);
  } catch (error) {
    console.error("Error details:", error); // Log the error details
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Validate password in POST /validate-password
router.post("/validate-password", async (req, res) => {
  const { shortUrl, password } = req.body;

  try {
    // Find the URL document
    const url = await Url.findOne({
      $or: [{ short_url: shortUrl }, { alias: shortUrl }],
    });

    if (!url) {
      return res.status(404).json({ message: "URL not found" });
    }

    // Check if the password matches
    const isPasswordCorrect = await bcrypt.compare(password, url.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Password is correct, send the original URL for redirection
    url.access_count++;
    await url.save();
    await logAnalytics(url, req);
    res.status(200).json({ original_url: url.original_url });
  } catch (error) {
    console.error("Error details:", error); // Log the error details
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

router.put("/updateExpiry/:linkId", async (req, res) => {
  const { linkId } = req.params;
  const { expiry_date } = req.body;

  console.log("LInk ID: ", linkId);
  console.log("Expiry Date: ", expiry_date);

  try {
    // Validate the incoming data
    if (!expiry_date) {
      return res.status(400).json({ message: "Expiry date is required." });
    }

    const url = await Url.findById(linkId);

    if (!url) {
      return res.status(404).json({ message: "URL not found" });
    }

    url.expiry_date = expiry_date;

    const updatedUrl = await url.save();

    return res.status(200).json({
      success: true,
      message: "Expiry date updated successfully",
      data: updatedUrl,
    });
  } catch (error) {
    console.error("Error updating expiry date:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

router.post("/register", async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });

    // Save the user to the database
    await newUser.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    res.status(500).json({ message: "Server error: " + error.message });
  }
});

router.post("/login", loginValidator, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  console.log(req);

  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json("User Not Found");
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).send("Password is incorrect");
  }

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.status(201).json({
    message: "Logged in",
    user: { id: user._id, email: user.email },
  });
});

router.post("/logout", (req, res) => {
  res.clearCookie("token"); // Clear the cookie
  res.status(200).json({ message: "Logged out successfully" });
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  console.log("Request received for email:", email);
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "10m",
    });
    const resetUrl = `${process.env.BASE_URL}/reset-password/${token}`;

    const sentEmail = await sendEmail(
      email,
      "Password Reset",
      `Click this link to reset your password: ${resetUrl}`
    );
    console.log(sentEmail);
    res.status(200).json({ message: "Password reset link sent to your email" });
  } catch (error) {
    console.error("Error in forgot-password route:", error);
    res.status(500).json({ message: error });
  }
});

// Reset password route
router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  console.log("Passowrd: ", req.body);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: "Password has been reset" });
  } catch (error) {
    console.log(error);
    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Reset token has expired" });
    }
    res.status(400).json({ message: "Invalid token" });
  }
});

router.post("/verify-reset-token/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: "Invalid token" });
    }

    // Token is valid, send a success response
    res.status(200).json({ message: "Token is valid" });
  } catch (error) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }
});

module.exports = router;
