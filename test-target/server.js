const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const http = require("http");

const app = express();
const PORT = 3001;

// ---------------------------------------------------------------------------
// SQLite setup — real DB for real SQL injection
// ---------------------------------------------------------------------------

const db = new Database("/tmp/app.db");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    bio TEXT
  );
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    category TEXT
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    product_id INTEGER,
    author TEXT,
    body TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS secret_keys (
    id INTEGER PRIMARY KEY,
    key_name TEXT NOT NULL,
    key_value TEXT NOT NULL
  );
`);

// Seed data
const userCount = db.prepare("SELECT count(*) as c FROM users").get();
if (userCount.c === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (username, email, password, role, bio) VALUES (?, ?, ?, ?, ?)"
  );
  insertUser.run("admin", "admin@example.com", "Super$ecret123!", "admin", "System administrator");
  insertUser.run("alice", "alice@example.com", "alice2024", "editor", "Content editor");
  insertUser.run("bob", "bob@example.com", "bob_pass!", "user", "Regular user");
  insertUser.run("charlie", "charlie@example.com", "ch4rli3#99", "user", "New member");
  insertUser.run("dave", "dave@example.com", "d4v3Secure", "moderator", "Forum moderator");

  const insertProduct = db.prepare(
    "INSERT INTO products (name, price, description, category) VALUES (?, ?, ?, ?)"
  );
  insertProduct.run("Widget Pro", 29.99, "Professional-grade widget", "electronics");
  insertProduct.run("Gadget X", 49.99, "Next-gen gadget with AI", "electronics");
  insertProduct.run("Secure Lock", 89.99, "Military-grade padlock", "security");
  insertProduct.run("USB Drive 64GB", 12.50, "High-speed USB 3.0", "storage");

  const insertComment = db.prepare(
    "INSERT INTO comments (product_id, author, body) VALUES (?, ?, ?)"
  );
  insertComment.run(1, "alice", "Works great!");
  insertComment.run(1, "bob", "Decent quality for the price");
  insertComment.run(2, "charlie", "The AI features are impressive");

  const insertKey = db.prepare(
    "INSERT INTO secret_keys (key_name, key_value) VALUES (?, ?)"
  );
  insertKey.run("API_KEY", "sk-live-T3stK3y-D0N0tUs3-FAKE12345");
  insertKey.run("DB_PASSWORD", "r00t_p4ss_pr0d!");
  insertKey.run("JWT_SECRET", "super-secret-jwt-signing-key-2024");
}

// ---------------------------------------------------------------------------
// Seed files for path traversal
// ---------------------------------------------------------------------------

const dataDir = "/tmp/data";
fs.mkdirSync(dataDir, { recursive: true });
fs.writeFileSync(path.join(dataDir, "readme.txt"), "Welcome to the file store!\nPublic files are served from /data/.\n");
fs.writeFileSync(path.join(dataDir, "config.ini"), "[database]\nhost=localhost\nport=5432\nuser=admin\npassword=db_secret_pass!\n\n[redis]\nhost=localhost\nauth=redis_s3cret\n");
fs.writeFileSync(path.join(dataDir, "users.csv"), "id,username,email,role\n1,admin,admin@example.com,admin\n2,alice,alice@example.com,editor\n");
fs.writeFileSync(path.join(dataDir, ".env"), "DATABASE_URL=postgres://admin:prod_password@db:5432/myapp\nSECRET_KEY=sk-live-abcdef123456\nSTRIPE_KEY=sk_live_fake_key_here\n");

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, _res, next) => {
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      method: req.method,
      path: req.path,
      query: req.query,
      ip: req.ip,
    })
  );
  next();
});

// ---------------------------------------------------------------------------
// HTML template
// ---------------------------------------------------------------------------

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} - Vuln Shop</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:2rem}
  .container{max-width:900px;margin:0 auto}
  h1{font-size:1.8rem;margin-bottom:.25rem;color:#38bdf8}
  h2{font-size:1.3rem;margin:1.5rem 0 .5rem;color:#7dd3fc}
  p.subtitle{color:#94a3b8;margin-bottom:1.5rem}
  a{color:#38bdf8;text-decoration:none} a:hover{text-decoration:underline}
  nav{display:flex;gap:1rem;padding:.75rem 0;border-bottom:1px solid #334155;margin-bottom:1.5rem}
  .card{background:#1e293b;border:1px solid #334155;border-radius:.5rem;padding:1.25rem;margin-bottom:1rem}
  .card h3{color:#f0abfc;margin-bottom:.5rem;font-size:1rem}
  code{background:#0f172a;padding:.15rem .4rem;border-radius:.25rem;font-size:.85rem;color:#fbbf24}
  form{display:flex;flex-direction:column;gap:.5rem;margin-top:.5rem}
  input,textarea,select,button{font-family:inherit;font-size:.9rem;padding:.5rem .75rem;border-radius:.375rem;border:1px solid #475569;background:#0f172a;color:#e2e8f0}
  button{background:#2563eb;border-color:#2563eb;color:#fff;cursor:pointer;font-weight:600}
  button:hover{background:#1d4ed8}
  .danger{background:#dc2626;border-color:#dc2626}
  .result{background:#0f172a;border:1px solid #334155;border-radius:.5rem;padding:1rem;margin-top:1rem;white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:.85rem}
  .badge{display:inline-block;font-size:.7rem;padding:.1rem .45rem;border-radius:.25rem;font-weight:700;margin-right:.35rem;vertical-align:middle}
  .high{background:#991b1b;color:#fca5a5} .med{background:#92400e;color:#fcd34d} .low{background:#065f46;color:#6ee7b7}
  table{width:100%;border-collapse:collapse;margin-top:.75rem}
  th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #334155;font-size:.85rem}
  th{color:#94a3b8}
  .alert{background:#7f1d1d;border:1px solid #dc2626;color:#fca5a5;padding:.75rem 1rem;border-radius:.375rem;margin:1rem 0}
  .success{background:#064e3b;border:1px solid #059669;color:#6ee7b7;padding:.75rem 1rem;border-radius:.375rem;margin:1rem 0}
</style>
</head>
<body>
<div class="container">
<nav>
  <a href="/">Home</a>
  <a href="/products">Products</a>
  <a href="/search">Search</a>
  <a href="/admin">Admin</a>
  <a href="/files">Files</a>
  <a href="/api/users">API</a>
</nav>
${body}
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// 1. Homepage
// ---------------------------------------------------------------------------

app.get("/", (_req, res) => {
  res.send(page("Home", `
<h1>Vuln Shop</h1>
<p class="subtitle">Intentionally vulnerable e-commerce demo for WAF testing.</p>

<h2>Attack Surface</h2>

<div class="card">
  <h3><span class="badge high">HIGH</span> SQL Injection</h3>
  <p>Product search, user lookup, and login all use raw SQL. Try <code>' OR 1=1 --</code></p>
</div>

<div class="card">
  <h3><span class="badge high">HIGH</span> Reflected XSS</h3>
  <p>Search results reflect user input unescaped into HTML. Try <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></p>
</div>

<div class="card">
  <h3><span class="badge high">HIGH</span> Path Traversal</h3>
  <p>File viewer reads real files from disk. Try <code>../../../etc/passwd</code></p>
</div>

<div class="card">
  <h3><span class="badge med">MED</span> SSRF</h3>
  <p>URL fetcher makes real HTTP requests. Try <code>http://169.254.169.254/latest/meta-data/</code></p>
</div>

<div class="card">
  <h3><span class="badge med">MED</span> IDOR</h3>
  <p>User profiles accessible by ID with no auth check. Try incrementing IDs.</p>
</div>

<div class="card">
  <h3><span class="badge low">LOW</span> Information Disclosure</h3>
  <p>Error pages leak stack traces. API endpoints expose internal data.</p>
</div>
`));
});

// ---------------------------------------------------------------------------
// 2. Search — Reflected XSS + SQL injection
// ---------------------------------------------------------------------------

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  let results = [];
  let error = null;

  if (q) {
    try {
      // VULN: SQL injection — raw string interpolation
      const stmt = db.prepare(`SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`);
      results = stmt.all();
    } catch (e) {
      error = e.message;
    }
  }

  // VULN: XSS — q is reflected unescaped
  res.send(page("Search", `
<h1>Product Search</h1>
<form method="get" action="/search">
  <input name="q" value="${q}" placeholder="Search products..." style="width:100%" />
  <button type="submit">Search</button>
</form>
${error ? `<div class="alert">SQL Error: ${error}</div>` : ""}
${q ? `<p style="margin-top:1rem">Showing results for: <strong>${q}</strong></p>` : ""}
${results.length > 0 ? `
<table>
  <tr><th>ID</th><th>Name</th><th>Price</th><th>Category</th><th>Description</th></tr>
  ${results.map(r => `<tr><td>${r.id}</td><td>${r.name}</td><td>$${r.price}</td><td>${r.category}</td><td>${r.description}</td></tr>`).join("")}
</table>` : q ? `<p style="margin-top:.5rem;color:#94a3b8">No results found.</p>` : ""}
`));
});

// ---------------------------------------------------------------------------
// 3. Products — SQL injection via category filter
// ---------------------------------------------------------------------------

app.get("/products", (req, res) => {
  const category = req.query.category || "";
  let products = [];
  let error = null;

  try {
    if (category) {
      // VULN: SQL injection
      products = db.prepare(`SELECT * FROM products WHERE category = '${category}'`).all();
    } else {
      products = db.prepare("SELECT * FROM products").all();
    }
  } catch (e) {
    error = e.message;
  }

  res.send(page("Products", `
<h1>Products</h1>
<form method="get" style="flex-direction:row;display:flex;gap:.5rem">
  <input name="category" value="${category}" placeholder="Filter by category..." />
  <button type="submit">Filter</button>
</form>
${error ? `<div class="alert">Error: ${error}</div>` : ""}
<table>
  <tr><th>ID</th><th>Name</th><th>Price</th><th>Category</th><th>Description</th></tr>
  ${products.map(p => `<tr><td>${p.id}</td><td><a href="/product/${p.id}">${p.name}</a></td><td>$${p.price}</td><td>${p.category}</td><td>${p.description}</td></tr>`).join("")}
</table>
`));
});

// ---------------------------------------------------------------------------
// 4. Product detail + comments — stored XSS
// ---------------------------------------------------------------------------

app.get("/product/:id", (req, res) => {
  let product, comments;
  try {
    product = db.prepare(`SELECT * FROM products WHERE id = ${req.params.id}`).get();
    comments = db.prepare(`SELECT * FROM comments WHERE product_id = ${req.params.id} ORDER BY created_at DESC`).all();
  } catch (e) {
    return res.status(500).send(page("Error", `<div class="alert">Database error: ${e.message}\n\nStack: ${e.stack}</div>`));
  }

  if (!product) return res.status(404).send(page("Not Found", `<div class="alert">Product not found</div>`));

  // VULN: stored XSS via comment body
  res.send(page(product.name, `
<h1>${product.name}</h1>
<div class="card">
  <p><strong>Price:</strong> $${product.price}</p>
  <p><strong>Category:</strong> ${product.category}</p>
  <p><strong>Description:</strong> ${product.description}</p>
</div>

<h2>Comments</h2>
${comments.map(c => `
<div class="card">
  <p><strong>${c.author}</strong> <span style="color:#64748b;font-size:.8rem">${c.created_at}</span></p>
  <p>${c.body}</p>
</div>
`).join("")}

<h2>Add Comment</h2>
<form method="post" action="/product/${product.id}/comment">
  <input name="author" placeholder="Your name" />
  <textarea name="body" rows="3" placeholder="Write a comment..."></textarea>
  <button type="submit">Post Comment</button>
</form>
`));
});

app.post("/product/:id/comment", (req, res) => {
  const { author, body } = req.body;
  // VULN: stored XSS — no sanitisation
  db.prepare("INSERT INTO comments (product_id, author, body) VALUES (?, ?, ?)").run(req.params.id, author || "anonymous", body || "");
  res.redirect(`/product/${req.params.id}`);
});

// ---------------------------------------------------------------------------
// 5. User lookup — IDOR + SQL injection
// ---------------------------------------------------------------------------

app.get("/api/users", (_req, res) => {
  // VULN: exposes all user data including passwords
  const users = db.prepare("SELECT id, username, email, role, bio FROM users").all();
  res.json(users);
});

app.get("/api/user/:id", (req, res) => {
  try {
    // VULN: SQL injection via id + IDOR (no auth check)
    const user = db.prepare(`SELECT * FROM users WHERE id = ${req.params.id}`).get();
    if (!user) return res.status(404).json({ error: "User not found" });
    // VULN: leaks password
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});

// ---------------------------------------------------------------------------
// 6. Login — SQL injection auth bypass
// ---------------------------------------------------------------------------

app.get("/login", (_req, res) => {
  res.send(page("Login", `
<h1>Login</h1>
<form method="post" action="/login">
  <input name="username" placeholder="Username" />
  <input name="password" type="password" placeholder="Password" />
  <button type="submit">Sign In</button>
</form>
`));
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  try {
    // VULN: SQL injection auth bypass — try: admin' --
    const user = db.prepare(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`).get();
    if (user) {
      res.send(page("Welcome", `
<div class="success">Logged in as <strong>${user.username}</strong> (${user.role})</div>
<div class="card">
  <h3>Profile</h3>
  <table>
    <tr><td>Username</td><td>${user.username}</td></tr>
    <tr><td>Email</td><td>${user.email}</td></tr>
    <tr><td>Role</td><td>${user.role}</td></tr>
    <tr><td>Bio</td><td>${user.bio}</td></tr>
  </table>
</div>
`));
    } else {
      res.send(page("Login Failed", `
<div class="alert">Invalid username or password</div>
<p style="margin-top:1rem"><a href="/login">Try again</a></p>
`));
    }
  } catch (e) {
    res.status(500).send(page("Error", `<div class="alert">SQL Error: ${e.message}\n\n${e.stack}</div>`));
  }
});

// ---------------------------------------------------------------------------
// 7. File viewer — real path traversal
// ---------------------------------------------------------------------------

app.get("/files", (req, res) => {
  const name = req.query.name;

  if (!name) {
    const files = fs.readdirSync(dataDir).filter(f => !f.startsWith("."));
    return res.send(page("Files", `
<h1>File Store</h1>
<p class="subtitle">Browse and download files from the data directory.</p>
<table>
  <tr><th>Name</th><th>Size</th></tr>
  ${files.map(f => {
    const stat = fs.statSync(path.join(dataDir, f));
    return `<tr><td><a href="/files?name=${f}">${f}</a></td><td>${stat.size} bytes</td></tr>`;
  }).join("")}
</table>
<h2>Open File</h2>
<form method="get">
  <input name="name" placeholder="e.g. readme.txt or ../../../etc/passwd" />
  <button type="submit">Open</button>
</form>
`));
  }

  try {
    // VULN: path traversal — no sanitisation of name, resolves relative paths
    const filePath = path.join(dataDir, name);
    const content = fs.readFileSync(filePath, "utf-8");
    res.send(page("File: " + name, `
<h1>File Viewer</h1>
<div class="card">
  <h3>${name}</h3>
  <p style="color:#64748b;font-size:.8rem">Resolved: ${filePath}</p>
</div>
<div class="result">${content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>
<p style="margin-top:1rem"><a href="/files">&larr; Back to files</a></p>
`));
  } catch (e) {
    res.status(404).send(page("Error", `<div class="alert">Could not read file: ${name}\n${e.message}</div>`));
  }
});

// ---------------------------------------------------------------------------
// 8. URL fetcher — SSRF
// ---------------------------------------------------------------------------

app.get("/fetch", (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.send(page("URL Fetcher", `
<h1>URL Fetcher</h1>
<p class="subtitle">Fetch content from any URL (for previews and metadata).</p>
<form method="get">
  <input name="url" placeholder="https://example.com" style="width:100%" />
  <button type="submit">Fetch</button>
</form>
`));
  }

  // VULN: SSRF — makes real HTTP request to user-supplied URL
  try {
    const parsedUrl = new URL(url);
    const proto = parsedUrl.protocol === "https:" ? require("https") : http;
    const fetchReq = proto.get(url, { timeout: 5000 }, (fetchRes) => {
      let body = "";
      fetchRes.on("data", (chunk) => { body += chunk; });
      fetchRes.on("end", () => {
        res.send(page("Fetch Result", `
<h1>Fetch Result</h1>
<div class="card">
  <h3>URL: ${url}</h3>
  <p>Status: ${fetchRes.statusCode}</p>
  <p>Headers:</p>
  <div class="result">${JSON.stringify(fetchRes.headers, null, 2)}</div>
</div>
<div class="card">
  <h3>Response Body</h3>
  <div class="result">${body.replace(/</g, "&lt;").replace(/>/g, "&gt;").substring(0, 10000)}</div>
</div>
`));
      });
    });
    fetchReq.on("error", (e) => {
      res.status(500).send(page("Error", `<div class="alert">Fetch error: ${e.message}</div>`));
    });
    fetchReq.on("timeout", () => {
      fetchReq.destroy();
      res.status(504).send(page("Timeout", `<div class="alert">Request timed out</div>`));
    });
  } catch (e) {
    res.status(400).send(page("Error", `<div class="alert">Invalid URL: ${e.message}</div>`));
  }
});

// ---------------------------------------------------------------------------
// 9. Admin panel — no auth required (broken access control)
// ---------------------------------------------------------------------------

app.get("/admin", (_req, res) => {
  const users = db.prepare("SELECT * FROM users").all();
  const keys = db.prepare("SELECT * FROM secret_keys").all();

  // VULN: no authentication, exposes sensitive data
  res.send(page("Admin", `
<h1>Admin Panel</h1>
<p class="subtitle">System administration dashboard (no auth required!).</p>

<div class="card">
  <h3>All Users (with passwords)</h3>
  <table>
    <tr><th>ID</th><th>Username</th><th>Email</th><th>Password</th><th>Role</th></tr>
    ${users.map(u => `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.email}</td><td><code>${u.password}</code></td><td>${u.role}</td></tr>`).join("")}
  </table>
</div>

<div class="card">
  <h3>Secret Keys</h3>
  <table>
    <tr><th>Name</th><th>Value</th></tr>
    ${keys.map(k => `<tr><td>${k.key_name}</td><td><code>${k.key_value}</code></td></tr>`).join("")}
  </table>
</div>

<div class="card">
  <h3>Delete User</h3>
  <form method="post" action="/admin/delete-user">
    <input name="id" placeholder="User ID to delete" />
    <button type="submit" class="danger">Delete User</button>
  </form>
</div>

<div class="card">
  <h3>Run SQL Query</h3>
  <form method="post" action="/admin/query">
    <textarea name="sql" rows="3" placeholder="SELECT * FROM users"></textarea>
    <button type="submit" class="danger">Execute</button>
  </form>
</div>
`));
});

app.post("/admin/delete-user", (req, res) => {
  const id = req.body.id;
  try {
    // VULN: SQL injection + no auth
    db.prepare(`DELETE FROM users WHERE id = ${id}`).run();
    res.redirect("/admin");
  } catch (e) {
    res.status(500).send(page("Error", `<div class="alert">${e.message}</div>`));
  }
});

app.post("/admin/query", (req, res) => {
  const sql = req.body.sql || "";
  try {
    // VULN: arbitrary SQL execution
    const results = db.prepare(sql).all();
    res.send(page("Query Result", `
<h1>Query Result</h1>
<div class="card"><h3>Query</h3><div class="result">${sql}</div></div>
<div class="result">${JSON.stringify(results, null, 2)}</div>
<p style="margin-top:1rem"><a href="/admin">&larr; Back to admin</a></p>
`));
  } catch (e) {
    res.send(page("Query Error", `
<div class="alert">SQL Error: ${e.message}\n\n${e.stack}</div>
<p style="margin-top:1rem"><a href="/admin">&larr; Back to admin</a></p>
`));
  }
});

// ---------------------------------------------------------------------------
// 10. Error handling — leaks stack traces
// ---------------------------------------------------------------------------

app.get("/error", (_req, _res) => {
  throw new Error("Unhandled test error — this leaks a stack trace!");
});

app.use((err, _req, res, _next) => {
  // VULN: stack trace leakage
  res.status(500).send(page("Server Error", `
<div class="alert">
<strong>Internal Server Error</strong>
<pre>${err.stack}</pre>
</div>
`));
});

// ---------------------------------------------------------------------------
// Health check (safe)
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => res.json({ status: "ok" }));

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`Vuln Shop listening on http://0.0.0.0:${PORT}`);
});
