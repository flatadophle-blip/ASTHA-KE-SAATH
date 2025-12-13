import dns from "dns/promises";
import tls from "tls";
import whois from "whois-json";
import fetch from "node-fetch";

// API keys
const VALID_API_KEYS = ["zxcracks", "ZXOSINT456", "ZX-PRIVATE-KEY"];
const API_BY = "zx osint tg @zxosint";

export default async function handler(req, res) {
  res.setHeader("Content-Type", "application/json");

  try {
    if (req.method !== "GET") throw new Error("Method not allowed");

    // Check API key
    const apiKey = req.headers["x-api-key"];
    if (!apiKey || !VALID_API_KEYS.includes(apiKey)) {
      return res.status(401).json({ error: "Invalid or missing API key", api_by: API_BY });
    }

    const email = req.query.mail;
    if (!email) throw new Error("Please provide ?mail= parameter");

    const domain = email.split("@")[1]?.toLowerCase();
    if (!domain) throw new Error("Invalid email format");

    // MX Records
    let mxRecords = [];
    try { mxRecords = (await dns.resolveMx(domain)).map(r => r.exchange); } 
    catch { mxRecords = ["Unavailable"]; }

    // Domain IP
    let ipAddr = "Unavailable";
    try { ipAddr = (await dns.lookup(domain)).address; } 
    catch {}

    // SSL Issuer
    let sslIssuer = "Unavailable";
    try {
      await new Promise((resolve, reject) => {
        const socket = tls.connect(443, domain, { servername: domain }, () => {
          const cert = socket.getPeerCertificate();
          sslIssuer = cert?.issuer?.O || cert?.issuer?.organizationName || "Unavailable";
          socket.end(); resolve();
        });
        socket.on("error", () => resolve()); // ignore errors
      });
    } catch {}

    // WHOIS
    let registrar = "Unavailable", creationDate = "Unavailable", expirationDate = "Unavailable";
    try {
      const w = await whois(domain).catch(() => ({}));
      registrar = w.registrar || "Unavailable";
      creationDate = w.creationDate || "Unavailable";
      expirationDate = w.registryExpiryDate || "Unavailable";
    } catch {}

    // ISP & Location
    let isp = "Unavailable", location = "Unavailable";
    if (ipAddr !== "Unavailable") {
      try {
        const ipInfo = await fetch(`http://ip-api.com/json/${ipAddr}`).then(r => r.json());
        isp = ipInfo.isp || "Unavailable";
        location = `${ipInfo.city || "Unavailable"}, ${ipInfo.country || "Unavailable"}`;
      } catch {}
    }

    // Disposable
    const disposableDomains = ["tempmail.com","10minutemail.com","yopmail.com","guerrillamail.com"];
    const disposable = disposableDomains.includes(domain) ? "Yes" : "No";

    // Respond
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
    // Always return JSON on crash
    return res.status(500).json({ error: err.message, api_by: API_BY });
  }
}
