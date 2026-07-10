const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const fetch = require("node-fetch");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const JWT_SECRET = process.env.JWT_SECRET || "candtgoon_secret_change_me";
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, "uploads");

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(__dirname, "candtgoon.db"));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(receiver_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS cam_permissions (
    granter_id TEXT NOT NULL,
    grantee_id TEXT NOT NULL,
    PRIMARY KEY(granter_id, grantee_id)
  );
`);

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
  }),
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /image|video/.test(file.mimetype);
    cb(ok ? null : new Error("Images and videos only"), ok);
  },
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOAD_DIR));

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

// Auth
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });
  const hash = bcrypt.hashSync(password, 10);
  const id = uuidv4();
  try {
    db.prepare("INSERT INTO users (id, username, password) VALUES (?, ?, ?)").run(id, username.trim(), hash);
    const token = jwt.sign({ id, username: username.trim() }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, username: username.trim() });
  } catch { res.status(400).json({ error: "Username taken" }); }
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Wrong username or password" });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, username: user.username });
});

app.get("/api/users", auth, (req, res) => {
  res.json(db.prepare("SELECT id, username FROM users WHERE id != ?").all(req.user.id));
});

app.get("/api/messages/:userId", auth, (req, res) => {
  const msgs = db.prepare(`
    SELECT m.*, u.username as sender_name FROM messages m
    JOIN users u ON u.id = m.sender_id
    WHERE (m.sender_id = ? AND m.receiver_id = ?)
       OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.created_at ASC
  `).all(req.user.id, req.params.userId, req.params.userId, req.user.id);
  res.json(msgs);
});

app.post("/api/messages/media", auth, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const { receiver_id } = req.body;
  const id = uuidv4();
  const isVideo = req.file.mimetype.startsWith("video");
  const url = `/uploads/${req.file.filename}`;
  db.prepare("INSERT INTO messages (id, sender_id, receiver_id, type, content) VALUES (?, ?, ?, ?, ?)")
    .run(id, req.user.id, receiver_id, isVideo ? "video" : "image", url);
  const msg = { id, sender_id: req.user.id, sender_name: req.user.username, receiver_id, type: isVideo ? "video" : "image", content: url, created_at: Math.floor(Date.now() / 1000) };
  const receiverSocket = onlineUsers[receiver_id];
  if (receiverSocket) io.to(receiverSocket).emit("message", msg);
  res.json(msg);
});

// Delete message — notifies both parties in real-time
app.delete("/api/messages/:id", auth, (req, res) => {
  const msg = db.prepare("SELECT * FROM messages WHERE id=?").get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  if (msg.sender_id !== req.user.id) return res.status(403).json({ error: "Not yours" });
  db.prepare("DELETE FROM messages WHERE id=?").run(req.params.id);
  // Push deletion to both sender and receiver sockets
  const receiverSocket = onlineUsers[msg.receiver_id];
  if (receiverSocket) io.to(receiverSocket).emit("message:deleted", { id: req.params.id });
  const senderSocket = onlineUsers[msg.sender_id];
  if (senderSocket) io.to(senderSocket).emit("message:deleted", { id: req.params.id });
  res.json({ ok: true });
});

// Cam permission — once cece accepts, daddytor can peek silently forever
app.post("/api/cam/grant", auth, (req, res) => {
  const { to_id } = req.body;
  db.prepare("INSERT OR IGNORE INTO cam_permissions (granter_id, grantee_id) VALUES (?, ?)").run(req.user.id, to_id);
  res.json({ ok: true });
});

app.get("/api/cam/check/:userId", auth, (req, res) => {
  const row = db.prepare("SELECT 1 FROM cam_permissions WHERE granter_id=? AND grantee_id=?").get(req.params.userId, req.user.id);
  res.json({ granted: !!row });
});

// Returns list of user IDs that this user has permanently granted cam access to
app.get("/api/cam/granted", auth, (req, res) => {
  const rows = db.prepare("SELECT grantee_id FROM cam_permissions WHERE granter_id=?").all(req.user.id);
  res.json({ granted: rows.map(r => r.grantee_id) });
});

// Redgifs proxy
const RG_BROWSER = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Referer": "https://www.redgifs.com/",
  "Origin": "https://www.redgifs.com"
};
const RG_HEADERS = (t) => ({ ...RG_BROWSER, "Authorization": "Bearer " + t });

let rgTokenCache = null, rgTokenExp = 0;
async function getRgToken(force = false) {
  if (!force && rgTokenCache && Date.now() < rgTokenExp) return rgTokenCache;
  const r = await fetch("https://api.redgifs.com/v2/auth/temporary", { headers: RG_BROWSER });
  const d = await r.json();
  rgTokenCache = d.token;
  rgTokenExp = Date.now() + 55 * 60 * 1000;
  return rgTokenCache;
}

async function rgFetch(url) {
  let t = await getRgToken();
  let r = await fetch(url, { headers: RG_HEADERS(t) });
  let d = await r.json();
  if (d.error?.code === "WrongSender") {
    t = await getRgToken(true);
    r = await fetch(url, { headers: RG_HEADERS(t) });
    d = await r.json();
  }
  if (d.error?.code === "RateLimited") {
    const wait = (d.error.delay || 3000) + 500;
    await new Promise(res => setTimeout(res, wait));
    r = await fetch(url, { headers: RG_HEADERS(t) });
    d = await r.json();
  }
  return d;
}

app.get("/rg/trending", async (req, res) => {
  try {
    const { page = 1 } = req.query;
    const key = `trending|${page}`;
    const cached = cacheGet(key);
    if (cached) return res.json(cached);
    const d = await rgFetch(`https://api.redgifs.com/v2/gifs/trending?page=${page}&count=20`);
    const result = d.gifs?.length ? d : await rgFetch(`https://api.redgifs.com/v2/gifs/search?search_text=&order=trending&page=${page}&count=20`);
    if (result.gifs?.length) cacheSet(key, result);
    res.json(result);
  } catch { res.status(500).json({ error: "fetch failed" }); }
});

// Search result cache — 15 min TTL, avoids hammering Redgifs
const searchCache = new Map();
const CACHE_TTL = 15 * 60 * 1000;
function cacheGet(key) {
  const entry = searchCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { searchCache.delete(key); return null; }
  return entry.data;
}
function cacheSet(key, data) { searchCache.set(key, { data, ts: Date.now() }); }

app.get("/rg/search", async (req, res) => {
  try {
    const { q = "", page = 1, count = 20 } = req.query;
    const key = `${q}|${page}|${count}`;
    const cached = cacheGet(key);
    if (cached) return res.json(cached);
    const data = await rgFetch(`https://api.redgifs.com/v2/gifs/search?search_text=${encodeURIComponent(q)}&page=${page}&count=${count}`);
    if (data.gifs?.length) cacheSet(key, data);
    res.json(data);
  } catch { res.status(500).json({ error: "fetch failed" }); }
});

app.get("/rg/niches", async (req, res) => {
  try {
    res.json(await rgFetch(`https://api.redgifs.com/v2/niches?page=1&count=80`));
  } catch { res.status(500).json({ error: "fetch failed" }); }
});

app.get("/rg/niche/:id", async (req, res) => {
  try {
    const { page = 1, order = "trending" } = req.query;
    res.json(await rgFetch(`https://api.redgifs.com/v2/niches/${req.params.id}/gifs?page=${page}&count=12&order=${order}`));
  } catch { res.status(500).json({ error: "fetch failed" }); }
});

app.get("/rg/gif/:id", async (req, res) => {
  try {
    res.json(await rgFetch(`https://api.redgifs.com/v2/gifs/${req.params.id}`));
  } catch { res.status(500).json({ error: "fetch failed" }); }
});

// Media proxy — streams with correct Referer
app.get("/rg/proxy", async (req, res) => {
  const url = req.query.url;
  const allowed = ["https://media.redgifs.com/", "https://userpic.redgifs.com/", "https://thumbs2.redgifs.com/"];
  if (!url || !allowed.some(p => url.startsWith(p))) return res.status(400).send("bad url");
  try {
    const headers = { ...RG_BROWSER };
    if (req.headers.range) headers["Range"] = req.headers.range;
    const upstream = await fetch(url, { headers });
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type");
    const cl = upstream.headers.get("content-length");
    const cr = upstream.headers.get("content-range");
    if (ct) res.setHeader("Content-Type", ct);
    if (cl) res.setHeader("Content-Length", cl);
    if (cr) res.setHeader("Content-Range", cr);
    res.setHeader("Accept-Ranges", "bytes");
    upstream.body.pipe(res);
  } catch { res.status(500).send("proxy error"); }
});

// Socket.io
const onlineUsers = {};

io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET); next(); }
  catch { next(new Error("Auth failed")); }
});

io.on("connection", (socket) => {
  onlineUsers[socket.user.id] = socket.id;
  io.emit("online", Object.keys(onlineUsers));

  socket.on("message", (data) => {
    const { receiver_id, type, content } = data;
    const id = uuidv4();
    db.prepare("INSERT INTO messages (id, sender_id, receiver_id, type, content) VALUES (?, ?, ?, ?, ?)")
      .run(id, socket.user.id, receiver_id, type, content);
    const msg = { id, sender_id: socket.user.id, sender_name: socket.user.username, receiver_id, type, content, created_at: Math.floor(Date.now() / 1000) };
    const rs = onlineUsers[receiver_id];
    if (rs) io.to(rs).emit("message", msg);
    socket.emit("message", msg);
  });

  // WebRTC signaling
  socket.on("cam:request", ({ to }) => {
    const granted = db.prepare("SELECT 1 FROM cam_permissions WHERE granter_id=? AND grantee_id=?").get(to, socket.user.id);
    const rs = onlineUsers[to];
    if (granted) {
      // Silent — tell cece to start cam, tell daddytor she's accepted
      if (rs) io.to(rs).emit("cam:silent", { from: socket.user.id });
      socket.emit("cam:accepted", { from: to }); // daddytor initiates WebRTC
    } else {
      if (rs) io.to(rs).emit("cam:request", { from: socket.user.id, fromName: socket.user.username });
      else socket.emit("cam:declined", { from: to }); // offline = unavailable
    }
  });
  socket.on("cam:accept", ({ to }) => {
    // Store permission permanently
    db.prepare("INSERT OR IGNORE INTO cam_permissions (granter_id, grantee_id) VALUES (?, ?)").run(socket.user.id, to);
    const rs = onlineUsers[to];
    if (rs) io.to(rs).emit("cam:accepted", { from: socket.user.id });
  });
  socket.on("cam:decline", ({ to }) => {
    const rs = onlineUsers[to];
    if (rs) io.to(rs).emit("cam:declined", { from: socket.user.id });
  });
  socket.on("cam:frame", ({ to, frame }) => {
    const rs = onlineUsers[to];
    if (rs) io.to(rs).emit("cam:frame", { frame });
  });
  socket.on("cam:end", ({ to }) => {
    const rs = onlineUsers[to];
    // Tell cece to stop sending frames; tell daddytor the stream ended
    if (rs) io.to(rs).emit("cam:stop"); // cece stops frameInterval
    socket.emit("cam:ended"); // daddytor closes cam view
  });

  socket.on("disconnect", () => {
    delete onlineUsers[socket.user.id];
    io.emit("online", Object.keys(onlineUsers));
  });
});

const HOME_TAGS = ["doggy","bwc","bbc","ebony couple","fat ass","missionary","cuckold","threesome"];

async function primeCache() {
  console.log("Priming content cache (3s between requests)...");
  for (const tag of HOME_TAGS) {
    for (let page = 1; page <= 3; page++) {
      const key = `${tag}|${page}|20`;
      if (cacheGet(key)) { console.log(`already cached: ${tag} p${page}`); continue; }
      await new Promise(r => setTimeout(r, 3000)); // 3s gap — well under rate limit
      try {
        const data = await rgFetch(`https://api.redgifs.com/v2/gifs/search?search_text=${encodeURIComponent(tag)}&page=${page}&count=20`);
        if (data.gifs?.length) { cacheSet(key, data); console.log(`cached ${tag} p${page}: ${data.gifs.length} gifs`); }
        else console.log(`skip ${tag} p${page}: ${JSON.stringify(data.error||{})}`);
      } catch (e) { console.log(`error ${tag} p${page}: ${e.message}`); }
    }
  }
  console.log("Cache prime complete.");
}

server.listen(PORT, () => {
  console.log(`candtgoon running on :${PORT}`);
  setTimeout(primeCache, 5000); // wait 5s after boot before starting
});
