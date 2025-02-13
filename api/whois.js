const axios = require("axios");
require("dotenv").config();

async function getWhoisData(domain) {
    const API_KEY = process.env.WHOIS_API_KEY;
    if (!API_KEY) {
        console.error("API_KEY is not defined in environment variables");
        return { error: "API_KEY is not defined" };
    }

    if (typeof domain !== 'string' || domain.trim() === '') {
        console.error("Invalid domain provided");
        return { error: "Invalid domain" };
    }

    const URL = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${API_KEY}&domainName=${domain}&outputFormat=json`;

    try {
        const response = await axios.get(URL);
        return response.data;
    } catch (error) {
        console.error("WHOIS API Error:", error.response?.data || error.message);
        return { error: "Failed to fetch WHOIS data" };
    }
}

module.exports = getWhoisData;
