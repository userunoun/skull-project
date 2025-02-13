const axios = require("axios");
require("dotenv").config();

async function getReputationScore(domain) {
    const API_KEY = process.env.VIRUSTOTAL_API_KEY;
    const URL = `https://www.virustotal.com/api/v3/domains/${domain}`;

    try {
        const response = await axios.get(URL, {
            headers: { "x-apikey": API_KEY }
        });
        return response.data;
    } catch (error) {
        console.error("Reputation API Error:", error.response?.data || error.message);
        return { error: "Failed to fetch reputation score" };
    }
}

module.exports = getReputationScore;