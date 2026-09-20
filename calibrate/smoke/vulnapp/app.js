// Planted vulns: eval + proto pollution + ssrf
const http = require("http");
const { execSync } = require("child_process");

function handler(req, res) {
  const q = new URL(req.url, "http://x").searchParams;
  eval(q.get("expr"));                       // RCE
  const obj = {};
  for (const [k, v] of Object.entries(JSON.parse(q.get("o") || "{}")))
    obj[k] = v;                              // proto pollution via __proto__
  http.get(q.get("u"));                      // SSRF
  execSync("ping " + q.get("h"));            // cmd injection
}
