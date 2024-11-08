const Analytics = require("../models/analytics");
const https = require("https");
const UAParser = require("ua-parser-js");

async function logAnalytics(url, req) {
  const ipAddress = req.headers["x-forwarded-for"] || req.ip;
  const userAgentString = req.headers["user-agent"];
  const referrer = req.headers.referrer || null;

  const parser = new UAParser(userAgentString);
  const userAgentDetails = parser.getResult();

  const geoData = await getGeoData(ipAddress);
  console.log("Geo Data: ", geoData);

  const analytics = new Analytics({
    url_id: url._id,
    click_date: new Date(),
    referrer,
    ip_address: ipAddress,
    user_agent: userAgentString,
    browser: userAgentDetails.browser.name || null,
    platform: userAgentDetails.os.name || null,
    device: userAgentDetails.device.type || "Desktop",
    country: geoData.country || null,
    city: geoData.city || null,
  });

  await analytics.save();
  console.log("User Agent: ", userAgentDetails);
}

async function getGeoData(ip) {
  return new Promise((resolve, reject) => {
    https
      .get(`https://ipinfo.io/json`, (resp) => {
        let data = "";
        resp.on("data", (chunk) => {
          data += chunk;
        });
        resp.on("end", () => {
          const geoData = JSON.parse(data);
          console.log(geoData);
          if (geoData && geoData.country) {
            resolve({ country: geoData.country, city: geoData.city });
          } else {
            resolve({ country: null, city: null });
          }
        });
      })
      .on("error", (err) => {
        console.error("Error fetching geolocation data:", err);
        resolve({ country: null, city: null });
      });
  });
}

module.exports = logAnalytics;
