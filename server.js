const express = require("express");
const path = require("path");
const getWhoisData = require("./api/whois");
const getReputationScore = require("./api/reputation");
const getSecurityDetails = require("./api/security");

require("dotenv").config();
const app = express();
const port = process.env.PORT || 5000;

app.use(express.static("public"));
app.use(express.json());

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/analyze", async (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: "Domain is required!" });
    }

    try {
        const [whois, reputation, security] = await Promise.all([
            getWhoisData(domain),
            getReputationScore(domain),
            getSecurityDetails(domain),
        ]);

        res.json({ whois, reputation, security });
    } catch (error) {
        console.error("Error fetching data:", error);
        res.status(500).json({ error: "Failed to fetch data" });
    }
});

app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});