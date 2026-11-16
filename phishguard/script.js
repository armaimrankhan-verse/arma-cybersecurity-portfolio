const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const resultBox = document.getElementById("result");
const errorMessage = document.getElementById("errorMessage");
const historyBody = document.getElementById("historyBody");

const HISTORY_KEY = "phishingGuardHistory";

let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");

const suspiciousKeywords = [
    "login", "verify", "account", "secure",
    "update", "password", "banking",
    "confirm", "wallet", "signin"
];

const shorteners = [
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "ow.ly"
];

function inspectURL(value) {
    let url;

    try {
        const input = value.trim();

        if (!input || /\s/.test(input)) {
            throw new Error("Invalid URL");
        }

        url = new URL(
            /^https?:\/\//i.test(input)
                ? input
                : "https://" + input
        );

        if (!["http:", "https:"].includes(url.protocol)) {
            throw new Error("Unsupported protocol");
        }

        if (!url.hostname.includes(".") ||
            !url.hostname.split(".").pop()) {
            throw new Error("Invalid domain");
        }

    } catch {
        return {
            error: "Please enter a valid website URL."
        };
    }

    const host = url.hostname.toLowerCase();
    const fullURL = url.href.toLowerCase();

    let score = 0;
    const indicators = [];

    function flag(condition, points, message) {
        if (condition) {
            score += points;
            indicators.push(message);
        }
    }

    flag(
        url.protocol !== "https:",
        15,
        "Website does not use HTTPS encryption."
    );

    flag(
        url.username !== "" || url.password !== "",
        30,
        "URL contains an unusual username or password field."
    );

    flag(
        host.startsWith("xn--") || host.includes(".xn--"),
        25,
        "Domain contains an internationalized/punycode label."
    );

    flag(
        /^[0-9.]+$/.test(host),
        25,
        "Website uses an IP address instead of a regular domain name."
    );

    flag(
        host.split(".").length >= 5,
        15,
        "Domain contains an unusually large number of subdomains."
    );

    flag(
        host.length > 45,
        10,
        "Domain name is unusually long."
    );

    flag(
        shorteners.includes(host),
        20,
        "URL uses a known link-shortening service."
    );

    flag(
        (fullURL.match(/-/g) || []).length >= 4,
        10,
        "URL contains an unusual number of hyphens."
    );

    flag(
        (fullURL.match(/\d/g) || []).length >= 10,
        10,
        "URL contains an unusually high number of digits."
    );

    const matchedKeywords = suspiciousKeywords.filter(
        word => fullURL.includes(word)
    );

    flag(
        matchedKeywords.length >= 2,
        15,
        "URL contains multiple sensitive keywords: " +
        matchedKeywords.join(", ")
    );

    score = Math.min(score, 100);

    let level;
    let title;

    if (score >= 50) {
        level = "HIGH RISK";
        title = "High Risk Indicators Detected";
    } else if (score >= 25) {
        level = "SUSPICIOUS";
        title = "Suspicious Patterns Detected";
    } else {
        level = "LOW RISK";
        title = "No Major Warning Patterns Found";
    }

    if (indicators.length === 0) {
        indicators.push(
            "No suspicious patterns were detected by these basic checks."
        );
    }

    return {
        url: url.href,
        host,
        score,
        level,
        title,
        indicators,
        date: new Date().toLocaleString()
    };
}

function displayResult(data) {
    resultBox.classList.remove("hidden");

    document.getElementById("resultTitle").textContent = data.title;

    document.getElementById("riskBadge").textContent = data.level;

    document.getElementById("riskBadge").className =
        "risk-badge " +
        (data.score >= 50 ? "high" :
         data.score >= 25 ? "medium" : "");

    document.getElementById("riskScore").innerHTML =
        `${data.score}<span>/100</span>`;

    document.getElementById("scoreFill").style.width =
        data.score + "%";

    document.getElementById("scoreFill").style.background =
        data.score >= 50 ? "#ff647d" :
        data.score >= 25 ? "#ffb547" : "#20d99a";

    document.getElementById("scannedUrl").textContent =
        "Scanned domain: " + data.host;

    const list = document.getElementById("indicatorList");
    list.replaceChildren();

    data.indicators.forEach(message => {
        const item = document.createElement("li");
        item.textContent = "• " + message;
        list.appendChild(item);
    });

    document.getElementById("resultNote").textContent =
        "Important: This is a basic heuristic assessment, not a verified security verdict. A low score does not guarantee that a website is safe. Do not enter personal information on an untrusted website.";
}

function saveHistory(data) {
    history.unshift({
        url: data.url,
        date: data.date,
        level: data.level,
        score: data.score
    });

    history = history.slice(0, 50);

    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history)
    );

    renderHistory();
}

function renderHistory() {
    historyBody.replaceChildren();

    if (history.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 4;
        cell.className = "empty-state";
        cell.textContent = "No scans performed yet.";

        row.appendChild(cell);
        historyBody.appendChild(row);
    }

    history.forEach(item => {
        const row = document.createElement("tr");

        const values = [
            item.url,
            item.date,
            item.level,
            item.score + "/100"
        ];

        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = value;

            if (index === 2) {
                cell.className =
                    "table-risk " +
                    (item.score >= 50 ? "high-text" :
                     item.score >= 25 ? "medium-text" : "low");
            }

            row.appendChild(cell);
        });

        historyBody.appendChild(row);
    });

    updateStats();
}

function updateStats() {
    document.getElementById("totalScans").textContent =
        history.length;

    document.getElementById("suspiciousScans").textContent =
        history.filter(item => item.score >= 25).length;

    document.getElementById("safeScans").textContent =
        history.filter(item => item.score < 25).length;
}

function scanURL() {
    const value = urlInput.value;

    errorMessage.textContent = "";

    const result = inspectURL(value);

    if (result.error) {
        errorMessage.textContent = result.error;
        return;
    }

    displayResult(result);
    saveHistory(result);
}

scanButton.addEventListener("click", scanURL);

urlInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        scanURL();
    }
});

document.getElementById("clearHistory").addEventListener(
    "click",
    () => {
        if (!history.length) return;

        const confirmed = confirm(
            "Are you sure you want to clear all scan history?"
        );

        if (confirmed) {
            history = [];
            localStorage.removeItem(HISTORY_KEY);
            renderHistory();
        }
    }
);

renderHistory();