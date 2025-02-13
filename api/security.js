const axios = require("axios");
require("dotenv").config();

async function getSecurityDetails(domain) {
    const API_KEY = process.env.VIRUSTOTAL_API_KEY;
    if (!API_KEY) {
        console.error("VIRUSTOTAL_API_KEY is not defined in environment variables");
        return { error: "VIRUSTOTAL_API_KEY is not defined" };
    }

    if (typeof domain !== 'string' || domain.trim() === '') {
        console.error("Invalid domain provided");
        return { error: "Invalid domain" };
    }

    const URL = `https://www.virustotal.com/api/v3/domains/${domain}`;

    try {
        console.log(`Fetching security details from: ${URL}`); // Debug log
        const response = await axios.get(URL, {
            headers: { "x-apikey": API_KEY }
        });
        return response.data;
    } catch (error) {
        console.error("Security API Error:", error.response?.data || error.message);
        return { error: "Failed to fetch security details" };
    }
}

module.exports = getSecurityDetails;