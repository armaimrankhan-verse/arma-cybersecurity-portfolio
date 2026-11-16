const express = require("express");

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "10kb" }));

// Show website homepage
app.use(express.static(__dirname));

// Check suspicious URLs
app.post("/api/check-url", (req, res) => {
    const input = req.body.url;

    if (!input || typeof input !== "string") {
        return res.status(400).json({
            error: "Please enter a URL."
        });
    }

    let parsedURL;

    try {
        parsedURL = new URL(input);
    } catch {
        return res.status(400).json({
            error: "Invalid URL. Please enter a complete URL."
        });
    }

    if (!["http:", "https:"].includes(parsedURL.protocol)) {
        return res.status(400).json({
            error: "Only HTTP and HTTPS URLs are allowed."
        });
    }

    const hostname = parsedURL.hostname.toLowerCase();
    const warnings = [];

    if (parsedURL.protocol !== "https:") {
        warnings.push("Website does not use HTTPS.");
    }

    if (parsedURL.username || parsedURL.password) {
        warnings.push("URL contains login credentials.");
    }

    if (hostname.includes("xn--")) {
        warnings.push("Website uses an internationalized domain name.");
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        warnings.push("Website uses an IP address instead of a domain name.");
    }

    if (hostname.split(".").length > 4) {
        warnings.push("Website has many subdomains.");
    }

    if (hostname.length > 50) {
        warnings.push("Website domain is unusually long.");
    }

    if (input.length > 100) {
        warnings.push("URL is unusually long.");
    }

    const suspiciousWords = [
        "login", "verify", "account",
        "password", "bank", "secure",
        "update", "free", "gift"
    ];

    if (suspiciousWords.some(word => hostname.includes(word))) {
        warnings.push("Domain contains suspicious keywords.");
    }

    if ((hostname.match(/-/g) || []).length >= 3) {
        warnings.push("Domain contains many hyphens.");
    }

    const riskScore = Math.min(warnings.length * 15, 100);

    const verdict = riskScore >= 30
        ? "Suspicious"
        : "No obvious warning signs";

    res.json({
        success: true,
        website: hostname,
        riskScore: riskScore,
        verdict: verdict,
        warnings: warnings,
        message: warnings.length
            ? "Review this URL carefully."
            : "No obvious warning signs were detected.",
        disclaimer: "This is a basic heuristic analysis, not a guarantee of website safety."
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`PhishGuard running at http://localhost:${PORT}`);
});