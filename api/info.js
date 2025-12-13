import dns from "dns/promises";
import net from "net";
import tls from "tls";
import whois from "whois-json";
import fetch from "node-fetch";

// 🔐 MULTIPLE API KEYS
const VALID_API_KEYS = [
  "zxcracks",
  "ZXOSINT456",
  "ZX-PRIVATE-KEY"
];

const API_BY = "zx osint tg @zxosint";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed",
      api_by: API_BY
    });
  }

  // 🔐 API KEY CHECK
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || !VALID_API_KEYS.includes(apiKey)) {
    return res.status(401).json({
      error: "Invalid or missing API key",
      api_by: API_BY
    });
  }

  const email = req.query.mail;
  if (!email) {
    return res.status(400).json({
      error: "Please provide ?mail= parameter",
      api_by: API_BY
    });
  }

  try {
    const domain = email.split("@")[1]?.toLowerCase();
    if (!domain) {
      return res.status(400).json({
        error: "Invalid email format",
        api_by: API_BY
      });
    }

    // MX RECORDS
    let mxRecords = [];
    try {
      const mx = await dns.resolveMx(domain);
      mxRecords = mx.map(r => r.exchange);
    } catch {
      mxRecords = ["No MX record found"];
    }

    // DOMAIN IP
    let ipAddr = "Unknown";
    try {
      const lookup = await dns.lookup(domain);
      ipAddr = lookup.address;
    } catch {}

    // SSL ISSUER
    let sslIssuer = "Unknown";
    try {
      await new Promise((resolve, reject) => {
        const socket = tls.connect(
          443,
          domain,
          { servername: domain },
          () => {
            const cert = socket.getPeerCertificate();
            sslIssuer =
              cert?.issuer?.O ||
              cert?.issuer?.organizationName ||
              "Unknown";
            socket.end();
            resolve();
          }
        );
        socket.on("error", reject);
      });
    } catch {}

    // WHOIS
    let registrar = "Unknown";
    let creationDate = "Unknown";
    let expirationDate = "Unknown";
    try {
      const w = await whois(domain);
      registrar = w.registrar || "Unknown";
      creationDate = w.creationDate || "Unknown";
      expirationDate = w.registryExpiryDate || "Unknown";
    } catch {}

    // ISP + LOCATION
    let isp = "Unknown";
    let location = "Unknown";
    if (ipAddr !== "Unknown") {
      try {
        const ipInfo = await fetch(`http://ip-api.com/json/${ipAddr}`).then(r => r.json());
        isp = ipInfo.isp || "Unknown";
        location = `${ipInfo.city || "Unknown"}, ${ipInfo.country || "Unknown"}`;
      } catch {}
    }

    // DISPOSABLE CHECK
    const disposableDomains = [
      "tempmail.com",
      "10minutemail.com",
      "yopmail.com",
      "guerrillamail.com"
    ];
    const disposable = disposableDomains.includes(domain) ? "Yes" : "No";

    // RESPONSE
    return res.status(200).json({
      email,
      domain,
      mx_records: mxRecords,
      domain_ip: ipAddr,
      server_location: location,
      isp,
      registrar,
      creation_date: creationDate,
      expiration_date: expirationDate,
      ssl_issuer: sslIssuer,
      disposable,
      api_by: API_BY
    });

  } catch (err) {
    return res.status(500).json({
      error: err.message,
      api_by: API_BY
    });
  }
}
