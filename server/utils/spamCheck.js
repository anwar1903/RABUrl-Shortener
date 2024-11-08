const axios = require("axios");

async function checkUrlSafety(url) {
  const requestBody = {
    client: {
      clientId: "raburl",
      clientVersion: "1.0",
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
        ,
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
      requestBody
    );

    const matches = response.data;
    console.log("Matches: ", matches);
    return matches.length > 0;
  } catch (error) {
    console.error("Error checking URL safety:", error);
    return false;
  }
}

module.exports = checkUrlSafety;
