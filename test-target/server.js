const express = require("express");
const app = express();
const PORT = 3001;

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger -- prints method, path, query string, and headers to stdout
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  console.log(
    JSON.stringify({
      ts,
      method: req.method,
      path: req.path,
      query: req.query,
      headers: req.headers,
    })
  );
  next();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} - WAF Test Target</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:2rem}
  .container{max-width:860px;margin:0 auto}
  h1{font-size:1.8rem;margin-bottom:.25rem;color:#38bdf8}
  h2{font-size:1.3rem;margin:1.5rem 0 .5rem;color:#7dd3fc}
  p.subtitle{color:#94a3b8;margin-bottom:1.5rem}
  a{color:#38bdf8;text-decoration:none}
  a:hover{text-decoration:underline}
  .card{background:#1e293b;border:1px solid #334155;border-radius:.5rem;padding:1.25rem;margin-bottom:1rem}
  .card h3{color:#f0abfc;margin-bottom:.5rem;font-size:1rem}
  .card code{background:#0f172a;padding:.15rem .4rem;border-radius:.25rem;font-size:.85rem;color:#fbbf24}
  form{display:flex;flex-direction:column;gap:.5rem;margin-top:.5rem}
  input,textarea,button{font-family:inherit;font-size:.9rem;padding:.5rem .75rem;border-radius:.375rem;border:1px solid #475569;background:#0f172a;color:#e2e8f0}
  button{background:#2563eb;border-color:#2563eb;color:#fff;cursor:pointer;font-weight:600}
  button:hover{background:#1d4ed8}
  .result{background:#0f172a;border:1px solid #334155;border-radius:.5rem;padding:1rem;margin-top:1rem;white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:.85rem}
  .badge{display:inline-block;font-size:.7rem;padding:.1rem .45rem;border-radius:.25rem;font-weight:700;margin-right:.35rem;vertical-align:middle}
  .get{background:#065f46;color:#6ee7b7}
  .post{background:#7c2d12;color:#fdba74}
  table{width:100%;border-collapse:collapse;margin-top:.75rem}
  th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #334155;font-size:.85rem}
  th{color:#94a3b8}
</style>
</head>
<body>
<div class="container">
${body}
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// 1. GET / -- Homepage with links and forms
// ---------------------------------------------------------------------------

app.get("/", (_req, res) => {
  res.send(
    page(
      "Home",
      `
<h1>WAF Test Target</h1>
<p class="subtitle">Intentionally vulnerable endpoints for testing Web Application Firewalls.</p>

<h2>Endpoints</h2>

<div class="card">
  <h3><span class="badge get">GET</span> /search?q=TERM</h3>
  <p>Reflected XSS &mdash; search term is echoed into the HTML without escaping.</p>
  <form method="get" action="/search">
    <input name="q" placeholder="e.g. &lt;script&gt;alert(1)&lt;/script&gt;" />
    <button type="submit">Search</button>
  </form>
</div>

<div class="card">
  <h3><span class="badge get">GET</span> /user?id=1</h3>
  <p>SQL-injection-style &mdash; the <code>id</code> parameter is reflected as if used in a query.</p>
  <form method="get" action="/user">
    <input name="id" placeholder="e.g. 1 OR 1=1 --" />
    <button type="submit">Lookup</button>
  </form>
</div>

<div class="card">
  <h3><span class="badge post">POST</span> /login</h3>
  <p>Injection via login form &mdash; username &amp; password are reflected back.</p>
  <form method="post" action="/login">
    <input name="username" placeholder="username" />
    <input name="password" type="text" placeholder="password" />
    <button type="submit">Login</button>
  </form>
</div>

<div class="card">
  <h3><span class="badge get">GET</span> /file?name=test.txt</h3>
  <p>Path traversal &mdash; filename is reflected as if it were accessed on disk.</p>
  <form method="get" action="/file">
    <input name="name" placeholder="e.g. ../../../etc/passwd" />
    <button type="submit">Fetch File</button>
  </form>
</div>

<div class="card">
  <h3><span class="badge get">GET</span> /api/data</h3>
  <p>Returns JSON containing all request headers echoed back.</p>
  <a href="/api/data">Try it &rarr;</a>
</div>

<div class="card">
  <h3><span class="badge post">POST</span> /api/submit</h3>
  <p>Accepts a JSON body and echoes it back.</p>
  <form id="json-form" onsubmit="return submitJson()">
    <textarea id="json-body" rows="3" placeholder='{"key": "value"}'></textarea>
    <button type="submit">Submit JSON</button>
  </form>
  <div id="json-result" class="result" style="display:none"></div>
  <script>
  function submitJson(){
    var body = document.getElementById('json-body').value;
    fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:body})
      .then(function(r){return r.text()})
      .then(function(t){var el=document.getElementById('json-result');el.style.display='block';el.textContent=t});
    return false;
  }
  </script>
</div>

<div class="card">
  <h3><span class="badge get">GET</span> /admin</h3>
  <p>Simulated admin panel.</p>
  <a href="/admin">Go to Admin &rarr;</a>
</div>

<div class="card">
  <h3><span class="badge get">GET</span> /health</h3>
  <p>Health-check endpoint.</p>
  <a href="/health">Check Health &rarr;</a>
</div>
`
    )
  );
});

// ---------------------------------------------------------------------------
// 2. GET /search?q=TERM  -- Reflected XSS
// ---------------------------------------------------------------------------

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  // Intentionally unsafe: q is injected raw into the HTML.
  res.send(
    page(
      "Search",
      `
<h1>Search Results</h1>
<p class="subtitle">You searched for: ${q}</p>
<div class="result">Query: ${q}\n\nNo results found.</div>
<p style="margin-top:1rem"><a href="/">&larr; Back</a></p>
`
    )
  );
});

// ---------------------------------------------------------------------------
// 3. GET /user?id=ID  -- SQL injection reflection
// ---------------------------------------------------------------------------

app.get("/user", (req, res) => {
  const id = req.query.id || "1";
  // Intentionally unsafe: id is reflected as if used in a SQL query.
  res.send(
    page(
      "User Lookup",
      `
<h1>User Lookup</h1>
<div class="card">
  <h3>Simulated Query</h3>
  <div class="result">SELECT * FROM users WHERE id = ${id};</div>
</div>
<div class="card">
  <h3>Result</h3>
  <table>
    <tr><th>id</th><th>name</th><th>email</th></tr>
    <tr><td>${id}</td><td>testuser</td><td>test@example.com</td></tr>
  </table>
</div>
<p style="margin-top:1rem"><a href="/">&larr; Back</a></p>
`
    )
  );
});

// ---------------------------------------------------------------------------
// 4. POST /login  -- Credential reflection
// ---------------------------------------------------------------------------

app.post("/login", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";
  // Intentionally unsafe: values echoed without sanitisation.
  res.send(
    page(
      "Login",
      `
<h1>Login Attempt</h1>
<div class="card">
  <h3>Received Credentials</h3>
  <div class="result">Username: ${username}\nPassword: ${password}</div>
</div>
<div class="card">
  <h3>Status</h3>
  <p>Authentication failed (this is a test endpoint; no real auth occurs).</p>
</div>
<p style="margin-top:1rem"><a href="/">&larr; Back</a></p>
`
    )
  );
});

// ---------------------------------------------------------------------------
// 5. GET /file?name=FILE  -- Path traversal reflection
// ---------------------------------------------------------------------------

app.get("/file", (req, res) => {
  const name = req.query.name || "test.txt";
  // Intentionally unsafe: the filename is reflected as if accessed on disk.
  res.send(
    page(
      "File Viewer",
      `
<h1>File Viewer</h1>
<div class="card">
  <h3>Requested File</h3>
  <div class="result">Path: /var/data/${name}</div>
</div>
<div class="card">
  <h3>Contents (simulated)</h3>
  <div class="result">This is simulated content for file: ${name}\n\nNo real file access occurs.</div>
</div>
<p style="margin-top:1rem"><a href="/">&larr; Back</a></p>
`
    )
  );
});

// ---------------------------------------------------------------------------
// 6. GET /api/data  -- Echo request headers as JSON
// ---------------------------------------------------------------------------

app.get("/api/data", (req, res) => {
  res.json({
    message: "Here are your request headers",
    headers: req.headers,
    query: req.query,
    ip: req.ip,
  });
});

// ---------------------------------------------------------------------------
// 7. POST /api/submit  -- Echo JSON body back
// ---------------------------------------------------------------------------

app.post("/api/submit", (req, res) => {
  res.json({
    message: "Received your submission",
    received: req.body,
    headers: req.headers,
  });
});

// ---------------------------------------------------------------------------
// 8. GET /admin  -- Simulated admin panel
// ---------------------------------------------------------------------------

app.get("/admin", (_req, res) => {
  res.send(
    page(
      "Admin Panel",
      `
<h1>Admin Panel</h1>
<p class="subtitle">Restricted area &mdash; simulated admin interface.</p>

<div class="card">
  <h3>System Status</h3>
  <table>
    <tr><th>Service</th><th>Status</th></tr>
    <tr><td>Database</td><td style="color:#4ade80">Online</td></tr>
    <tr><td>Cache</td><td style="color:#4ade80">Online</td></tr>
    <tr><td>Worker Queue</td><td style="color:#facc15">Degraded</td></tr>
  </table>
</div>

<div class="card">
  <h3>Recent Users</h3>
  <table>
    <tr><th>ID</th><th>Username</th><th>Role</th></tr>
    <tr><td>1</td><td>admin</td><td>superadmin</td></tr>
    <tr><td>2</td><td>alice</td><td>editor</td></tr>
    <tr><td>3</td><td>bob</td><td>viewer</td></tr>
  </table>
</div>

<div class="card">
  <h3>Run Command (simulated)</h3>
  <form method="post" action="/api/submit" id="cmd-form" onsubmit="return runCmd()">
    <input id="cmd-input" placeholder="e.g. ls -la /" />
    <button type="submit">Execute</button>
  </form>
  <div id="cmd-result" class="result" style="display:none"></div>
  <script>
  function runCmd(){
    var cmd = document.getElementById('cmd-input').value;
    fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command:cmd})})
      .then(function(r){return r.text()})
      .then(function(t){var el=document.getElementById('cmd-result');el.style.display='block';el.textContent=t});
    return false;
  }
  </script>
</div>

<p style="margin-top:1rem"><a href="/">&larr; Back</a></p>
`
    )
  );
});

// ---------------------------------------------------------------------------
// 9. GET /health  -- Health check
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`WAF Test Target listening on http://0.0.0.0:${PORT}`);
});
