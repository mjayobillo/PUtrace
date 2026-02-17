const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const multer = require("multer");
const sharp = require("sharp");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

const app = express();
const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const supabase = createClient(process.env.SUPABASE_URL || "", process.env.SUPABASE_SERVICE_ROLE_KEY || "");

const CATEGORIES = ["Electronics", "ID / Cards", "Clothing", "Bags", "Bottles", "Books", "Accessories", "Keys", "Other"];

// Email sending disabled for now
async function sendEmail(to, subject, html) {
  return; // no-op
}

// ── Validation Helpers ──
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function sanitize(str) {
  return (str || "").trim();
}

function isValidEmail(email) {
  return EMAIL_RE.test(email);
}

function isValidName(name) {
  return name.length >= 2 && name.length <= 100;
}

function isValidItemName(name) {
  return name.length >= 1 && name.length <= 150;
}

function isValidMessage(msg) {
  return msg.length >= 3 && msg.length <= 2000;
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "static")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
  })
);

app.use(async (req, res, next) => {
  res.locals.currentUser = null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;

  if (req.session.userId) {
    const { data } = await supabase
      .from("users")
      .select("id, full_name, email")
      .eq("id", req.session.userId)
      .single();

    res.locals.currentUser = data || null;
  }
  next();
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, "error", "Please login first.");
    return res.redirect("/login");
  }
  next();
}

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/signup", (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  const full_name = sanitize(req.body.full_name);
  const email = sanitize(req.body.email);
  const password = req.body.password || "";

  if (!isValidName(full_name)) {
    setFlash(req, "error", "Full name must be 2–100 characters.");
    return res.redirect("/signup");
  }
  if (!isValidEmail(email)) {
    setFlash(req, "error", "Please enter a valid email address.");
    return res.redirect("/signup");
  }
  if (password.length < 8) {
    setFlash(req, "error", "Password must be at least 8 characters.");
    return res.redirect("/signup");
  }

  const { data: exists } = await supabase.from("users").select("id").eq("email", email.toLowerCase()).maybeSingle();
  if (exists) {
    setFlash(req, "error", "Email already registered.");
    return res.redirect("/signup");
  }

  const password_hash = await bcrypt.hash(password, 10);

  const { error } = await supabase.from("users").insert({
    full_name,
    email: email.toLowerCase(),
    password_hash
  });

  if (error) {
    setFlash(req, "error", `Signup failed: ${error.message}`);
    return res.redirect("/signup");
  }

  setFlash(req, "success", "Account created. Please login.");
  return res.redirect("/login");
});

app.get("/login", (req, res) => res.render("login"));

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const { data: user } = await supabase.from("users").select("*").eq("email", (email || "").toLowerCase()).maybeSingle();

  if (!user) {
    setFlash(req, "error", "Invalid email or password.");
    return res.redirect("/login");
  }

  const ok = await bcrypt.compare(password || "", user.password_hash);
  if (!ok) {
    setFlash(req, "error", "Invalid email or password.");
    return res.redirect("/login");
  }

  req.session.userId = user.id;
  setFlash(req, "success", "Welcome back!");
  return res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const search = (req.query.search || "").trim();
  const filterCategory = req.query.category || "";
  const filterStatus = req.query.status || "";

  let query = supabase.from("items").select("*").eq("user_id", req.session.userId).order("created_at", { ascending: false });

  if (filterCategory) query = query.eq("category", filterCategory);
  if (filterStatus) query = query.eq("item_status", filterStatus);

  const { data: items } = await query;

  let filteredItems = items || [];
  if (search) {
    const s = search.toLowerCase();
    filteredItems = filteredItems.filter((i) =>
      i.item_name.toLowerCase().includes(s) ||
      (i.item_description || "").toLowerCase().includes(s) ||
      (i.category || "").toLowerCase().includes(s)
    );
  }

  const itemIds = filteredItems.map((i) => i.id);
  let reports = [];
  if (itemIds.length > 0) {
    const { data } = await supabase
      .from("finder_reports")
      .select("id, item_id, finder_name, finder_email, location_hint, message, status, created_at")
      .in("item_id", itemIds)
      .order("created_at", { ascending: false });
    reports = data || [];
  }

  const itemNameMap = Object.fromEntries(filteredItems.map((i) => [i.id, i.item_name]));
  const openCounts = {};
  for (const report of reports) {
    if (report.status === "open") {
      openCounts[report.item_id] = (openCounts[report.item_id] || 0) + 1;
    }
  }

  const viewItems = filteredItems.map((i) => ({ ...i, open_reports: openCounts[i.id] || 0 }));
  const viewReports = reports.map((r) => ({ ...r, item_name: itemNameMap[r.item_id] || "Unknown item" }));

  res.render("dashboard", {
    items: viewItems,
    reports: viewReports,
    baseUrl: BASE_URL,
    categories: CATEGORIES,
    search,
    filterCategory,
    filterStatus
  });
});

app.post("/dashboard", requireAuth, upload.single("image"), async (req, res) => {
  const item_name = sanitize(req.body.item_name);
  const item_description = sanitize(req.body.item_description);
  const category = req.body.category || "Other";

  if (!isValidItemName(item_name)) {
    setFlash(req, "error", "Item name is required (max 150 characters).");
    return res.redirect("/dashboard");
  }
  if (item_description && item_description.length > 1000) {
    setFlash(req, "error", "Description must be under 1000 characters.");
    return res.redirect("/dashboard");
  }

  const token = cryptoRandomToken();
  const qrUrl = `${BASE_URL}/found/${token}`;
  const qr_data_url = await QRCode.toDataURL(qrUrl);

  let image_url = null;
  if (req.file) {
    // Compress and resize image before uploading
    const compressedBuffer = await sharp(req.file.buffer)
      .resize(800, 800, { fit: "inside", withoutEnlargement: true })
      .jpeg({ quality: 75 })
      .toBuffer();

    const fileName = `${token}.jpg`;
    const { error: uploadErr } = await supabase.storage
      .from("item-images")
      .upload(fileName, compressedBuffer, {
        contentType: "image/jpeg",
        upsert: false
      });
    if (!uploadErr) {
      const { data: urlData } = supabase.storage.from("item-images").getPublicUrl(fileName);
      image_url = urlData.publicUrl;
    }
  }

  const { error } = await supabase.from("items").insert({
    user_id: req.session.userId,
    item_name,
    item_description: item_description || null,
    category: CATEGORIES.includes(category) ? category : "Other",
    item_status: "active",
    image_url,
    token,
    qr_data_url
  });

  if (error) {
    setFlash(req, "error", `Failed to register item: ${error.message}`);
    return res.redirect("/dashboard");
  }

  setFlash(req, "success", "Item registered and QR generated.");
  return res.redirect("/dashboard");
});

// ── Public Lost Board ──

app.get("/lost", async (req, res) => {
  const search = (req.query.search || "").trim();
  const filterCategory = req.query.category || "";

  let query = supabase
    .from("items")
    .select("id, item_name, item_description, category, image_url, created_at, user_id")
    .eq("item_status", "lost")
    .order("created_at", { ascending: false });

  if (filterCategory) query = query.eq("category", filterCategory);

  const { data: items } = await query;
  let filteredItems = items || [];

  if (search) {
    const s = search.toLowerCase();
    filteredItems = filteredItems.filter((i) =>
      i.item_name.toLowerCase().includes(s) ||
      (i.item_description || "").toLowerCase().includes(s) ||
      (i.category || "").toLowerCase().includes(s)
    );
  }

  // Get owner first names only (privacy)
  const userIds = [...new Set(filteredItems.map((i) => i.user_id))];
  let ownerMap = {};
  if (userIds.length > 0) {
    const { data: users } = await supabase.from("users").select("id, full_name").in("id", userIds);
    for (const u of users || []) {
      ownerMap[u.id] = u.full_name.split(" ")[0];
    }
  }

  const viewItems = filteredItems.map((i) => ({
    ...i,
    owner_first_name: ownerMap[i.user_id] || "Someone"
  }));

  res.render("lost", {
    items: viewItems,
    categories: CATEGORIES,
    search,
    filterCategory
  });
});

app.post("/lost/:id/sighting", async (req, res) => {
  const reporter_name = sanitize(req.body.reporter_name);
  const reporter_email = sanitize(req.body.reporter_email);
  const location = sanitize(req.body.location);
  const message = sanitize(req.body.message);

  const { data: item } = await supabase.from("items").select("id, item_name, user_id").eq("id", req.params.id).eq("item_status", "lost").maybeSingle();
  if (!item) {
    setFlash(req, "error", "Item not found.");
    return res.redirect("/lost");
  }

  if (!isValidName(reporter_name)) {
    setFlash(req, "error", "Name must be 2–100 characters.");
    return res.redirect("/lost");
  }
  if (!isValidEmail(reporter_email)) {
    setFlash(req, "error", "Please enter a valid email address.");
    return res.redirect("/lost");
  }
  if (!isValidMessage(message)) {
    setFlash(req, "error", "Message must be 3–2000 characters.");
    return res.redirect("/lost");
  }

  const { error } = await supabase.from("finder_reports").insert({
    item_id: item.id,
    finder_name: reporter_name,
    finder_email: reporter_email,
    location_hint: location || null,
    message: `[Sighting] ${message}`,
    status: "open"
  });

  if (error) {
    setFlash(req, "error", `Failed to submit sighting: ${error.message}`);
  } else {
    setFlash(req, "success", `Sighting reported for "${item.item_name}". The owner has been notified!`);

    // Email the owner (non-blocking)
    const { data: owner } = await supabase.from("users").select("email, full_name").eq("id", item.user_id).single();
    if (owner) {
      sendEmail(
        owner.email,
        `🔔 Sighting report for "${item.item_name}" — PUtrace`,
        `<h2>Hi ${owner.full_name.split(" ")[0]},</h2>
         <p>Someone spotted your lost item <strong>${item.item_name}</strong>!</p>
         <table style="border-collapse:collapse;margin:1rem 0;">
           <tr><td style="padding:6px 12px;font-weight:bold;">Reporter</td><td style="padding:6px 12px;">${reporter_name}</td></tr>
           <tr><td style="padding:6px 12px;font-weight:bold;">Email</td><td style="padding:6px 12px;">${reporter_email}</td></tr>
           ${location ? `<tr><td style="padding:6px 12px;font-weight:bold;">Location</td><td style="padding:6px 12px;">${location}</td></tr>` : ""}
           <tr><td style="padding:6px 12px;font-weight:bold;">Message</td><td style="padding:6px 12px;">${message}</td></tr>
         </table>
         <p><a href="${BASE_URL}/dashboard" style="background:#3a56e4;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;">View in Dashboard</a></p>
         <p style="color:#999;font-size:0.85rem;margin-top:2rem;">— PUtrace Campus Item Recovery</p>`
      ).catch(err => console.error("Failed to email owner:", err.message));
    }
  }
  return res.redirect("/lost");
});

app.get("/found/:token", async (req, res) => {
  const { data: item } = await supabase.from("items").select("*").eq("token", req.params.token).maybeSingle();

  if (!item) return res.status(404).render("not_found");

  const { data: owner } = await supabase.from("users").select("full_name, email").eq("id", item.user_id).single();

  return res.render("found_qr", { item, owner });
});

app.post("/found/:token", async (req, res) => {
  const finder_name = sanitize(req.body.finder_name);
  const finder_email = sanitize(req.body.finder_email);
  const location_hint = sanitize(req.body.location_hint);
  const message = sanitize(req.body.message);

  const { data: item } = await supabase.from("items").select("id, item_name, user_id").eq("token", req.params.token).maybeSingle();
  if (!item) return res.status(404).render("not_found");

  if (!isValidName(finder_name)) {
    setFlash(req, "error", "Name must be 2–100 characters.");
    return res.redirect(`/found/${req.params.token}`);
  }
  if (!isValidEmail(finder_email)) {
    setFlash(req, "error", "Please enter a valid email address.");
    return res.redirect(`/found/${req.params.token}`);
  }
  if (!isValidMessage(message)) {
    setFlash(req, "error", "Message must be 3–2000 characters.");
    return res.redirect(`/found/${req.params.token}`);
  }

  const { error } = await supabase.from("finder_reports").insert({
    item_id: item.id,
    finder_name,
    finder_email,
    location_hint: location_hint || null,
    message,
    status: "open"
  });

  if (error) {
    setFlash(req, "error", `Failed to submit report: ${error.message}`);
    return res.redirect(`/found/${req.params.token}`);
  }

  setFlash(req, "success", "Report submitted to owner.");

  // Email the owner about the found item report (non-blocking)
  const { data: owner } = await supabase.from("users").select("email, full_name").eq("id", item.user_id).single();
  if (owner) {
    sendEmail(
      owner.email,
      `🎉 Someone found your "${item.item_name}"! — PUtrace`,
      `<h2>Hi ${owner.full_name.split(" ")[0]},</h2>
       <p>Great news! Someone scanned the QR code on your item <strong>${item.item_name}</strong> and sent you a report.</p>
       <table style="border-collapse:collapse;margin:1rem 0;">
         <tr><td style="padding:6px 12px;font-weight:bold;">Finder</td><td style="padding:6px 12px;">${finder_name}</td></tr>
         <tr><td style="padding:6px 12px;font-weight:bold;">Email</td><td style="padding:6px 12px;">${finder_email}</td></tr>
         ${location_hint ? `<tr><td style="padding:6px 12px;font-weight:bold;">Location</td><td style="padding:6px 12px;">${location_hint}</td></tr>` : ""}
         <tr><td style="padding:6px 12px;font-weight:bold;">Message</td><td style="padding:6px 12px;">${message}</td></tr>
       </table>
       <p><a href="${BASE_URL}/dashboard" style="background:#3a56e4;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;">View in Dashboard</a></p>
       <p style="color:#999;font-size:0.85rem;margin-top:2rem;">— PUtrace Campus Item Recovery</p>`
    ).catch(err => console.error("Failed to email owner:", err.message));
  }

  return res.redirect(`/found/${req.params.token}`);
});

// ── Public Found Board (finders post items they picked up) ──

app.get("/found-items", async (req, res) => {
  const search = (req.query.search || "").trim();
  const filterCategory = req.query.category || "";

  let query = supabase
    .from("found_posts")
    .select("*")
    .eq("status", "unclaimed")
    .order("created_at", { ascending: false });

  if (filterCategory) query = query.eq("category", filterCategory);

  const { data: posts } = await query;
  let filteredPosts = posts || [];

  if (search) {
    const s = search.toLowerCase();
    filteredPosts = filteredPosts.filter((p) =>
      p.item_name.toLowerCase().includes(s) ||
      (p.item_description || "").toLowerCase().includes(s) ||
      (p.category || "").toLowerCase().includes(s) ||
      (p.location_found || "").toLowerCase().includes(s)
    );
  }

  res.render("found_items", {
    posts: filteredPosts,
    categories: CATEGORIES,
    search,
    filterCategory
  });
});

app.post("/found-items", upload.single("image"), async (req, res) => {
  const finder_name = sanitize(req.body.finder_name);
  const finder_email = sanitize(req.body.finder_email);
  const item_name = sanitize(req.body.item_name);
  const item_description = sanitize(req.body.item_description);
  const category = req.body.category || "Other";
  const location_found = sanitize(req.body.location_found);

  if (!isValidName(finder_name)) {
    setFlash(req, "error", "Name must be 2–100 characters.");
    return res.redirect("/found-items");
  }
  if (!isValidEmail(finder_email)) {
    setFlash(req, "error", "Please enter a valid email address.");
    return res.redirect("/found-items");
  }
  if (!isValidItemName(item_name)) {
    setFlash(req, "error", "Item name is required (max 150 characters).");
    return res.redirect("/found-items");
  }

  let image_url = null;
  if (req.file) {
    const compressedBuffer = await sharp(req.file.buffer)
      .resize(800, 800, { fit: "inside", withoutEnlargement: true })
      .jpeg({ quality: 75 })
      .toBuffer();

    const fileName = `found-${cryptoRandomToken()}.jpg`;
    const { error: uploadErr } = await supabase.storage
      .from("item-images")
      .upload(fileName, compressedBuffer, {
        contentType: "image/jpeg",
        upsert: false
      });
    if (!uploadErr) {
      const { data: urlData } = supabase.storage.from("item-images").getPublicUrl(fileName);
      image_url = urlData.publicUrl;
    }
  }

  const { error } = await supabase.from("found_posts").insert({
    finder_name,
    finder_email,
    item_name,
    item_description: item_description || null,
    category: CATEGORIES.includes(category) ? category : "Other",
    location_found: location_found || null,
    image_url,
    status: "unclaimed"
  });

  if (error) {
    setFlash(req, "error", `Failed to post item: ${error.message}`);
  } else {
    setFlash(req, "success", "Found item posted! The owner can now find it here.");
  }
  return res.redirect("/found-items");
});

app.post("/found-items/:id/claim", requireAuth, async (req, res) => {
  const postId = Number(req.params.id);

  const { data: post } = await supabase
    .from("found_posts")
    .select("*")
    .eq("id", postId)
    .eq("status", "unclaimed")
    .maybeSingle();

  if (!post) {
    setFlash(req, "error", "Post not found or already claimed.");
    return res.redirect("/found-items");
  }

  await supabase.from("found_posts").update({ status: "claimed" }).eq("id", postId);
  setFlash(req, "success", `You claimed "${post.item_name}". Contact the finder at ${post.finder_email} to arrange pickup.`);
  return res.redirect("/found-items");
});

// ── Resolve Reports ──

app.post("/report/:id/resolve", requireAuth, async (req, res) => {
  const reportId = Number(req.params.id);
  const { data: report } = await supabase.from("finder_reports").select("id, item_id").eq("id", reportId).maybeSingle();

  if (!report) return res.status(404).render("not_found");

  const { data: item } = await supabase.from("items").select("id, user_id").eq("id", report.item_id).single();
  if (!item || item.user_id !== req.session.userId) return res.status(403).send("Forbidden");

  await supabase.from("finder_reports").update({ status: "resolved" }).eq("id", reportId);
  setFlash(req, "success", "Report marked as resolved.");
  return res.redirect("/dashboard");
});

// ── Account ──

app.get("/account", requireAuth, async (req, res) => {
  const { data: user } = await supabase
    .from("users")
    .select("created_at")
    .eq("id", req.session.userId)
    .single();

  const { data: items } = await supabase.from("items").select("id").eq("user_id", req.session.userId);
  const itemIds = (items || []).map((i) => i.id);

  let openReports = 0;
  let resolvedReports = 0;
  if (itemIds.length > 0) {
    const { data: reports } = await supabase.from("finder_reports").select("status").in("item_id", itemIds);
    for (const r of reports || []) {
      if (r.status === "open") openReports++;
      else resolvedReports++;
    }
  }

  res.render("account", {
    createdAt: user?.created_at || new Date().toISOString(),
    itemCount: (items || []).length,
    openReports,
    resolvedReports
  });
});

app.post("/account", requireAuth, async (req, res) => {
  const full_name = sanitize(req.body.full_name);

  if (!isValidName(full_name)) {
    setFlash(req, "error", "Full name must be 2–100 characters.");
    return res.redirect("/account");
  }

  const { error } = await supabase
    .from("users")
    .update({ full_name })
    .eq("id", req.session.userId);

  if (error) {
    setFlash(req, "error", `Update failed: ${error.message}`);
  } else {
    setFlash(req, "success", "Profile updated.");
  }
  return res.redirect("/account");
});

app.post("/account/password", requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body;

  if (!new_password || new_password.length < 8) {
    setFlash(req, "error", "New password must be at least 8 characters.");
    return res.redirect("/account");
  }

  const { data: user } = await supabase.from("users").select("password_hash").eq("id", req.session.userId).single();

  const ok = await bcrypt.compare(current_password || "", user.password_hash);
  if (!ok) {
    setFlash(req, "error", "Current password is incorrect.");
    return res.redirect("/account");
  }

  const password_hash = await bcrypt.hash(new_password, 10);
  await supabase.from("users").update({ password_hash }).eq("id", req.session.userId);

  setFlash(req, "success", "Password updated.");
  return res.redirect("/account");
});

// ── Item Status Toggle ──

app.post("/item/:id/status", requireAuth, async (req, res) => {
  const { item_status } = req.body;
  const allowed = ["active", "lost", "recovered"];

  const { data: item } = await supabase
    .from("items")
    .select("id, user_id")
    .eq("id", req.params.id)
    .maybeSingle();

  if (!item || item.user_id !== req.session.userId) {
    setFlash(req, "error", "Item not found.");
    return res.redirect("/dashboard");
  }

  if (!allowed.includes(item_status)) {
    setFlash(req, "error", "Invalid status.");
    return res.redirect("/dashboard");
  }

  await supabase.from("items").update({ item_status }).eq("id", item.id);
  setFlash(req, "success", `Item marked as ${item_status}.`);
  return res.redirect("/dashboard");
});

// ── Delete Item ──

app.post("/item/:id/delete", requireAuth, async (req, res) => {
  const { data: item } = await supabase
    .from("items")
    .select("id, user_id")
    .eq("id", req.params.id)
    .maybeSingle();

  if (!item || item.user_id !== req.session.userId) {
    setFlash(req, "error", "Item not found.");
    return res.redirect("/dashboard");
  }

  await supabase.from("finder_reports").delete().eq("item_id", item.id);
  await supabase.from("items").delete().eq("id", item.id);

  setFlash(req, "success", "Item deleted.");
  return res.redirect("/dashboard");
});

app.get("/download/:token", requireAuth, async (req, res) => {
  const { data: item } = await supabase.from("items").select("*").eq("token", req.params.token).eq("user_id", req.session.userId).maybeSingle();

  if (!item) return res.status(404).render("not_found");

  const dataUrl = item.qr_data_url || "";
  const base64 = dataUrl.split(",")[1];
  if (!base64) return res.status(500).send("QR unavailable");

  const imgBuffer = Buffer.from(base64, "base64");
  res.setHeader("Content-Type", "image/png");
  res.setHeader("Content-Disposition", `attachment; filename=\"${safeFile(item.item_name)}-qr.png\"`);
  res.send(imgBuffer);
});

function cryptoRandomToken() {
  return crypto.randomBytes(16).toString("hex");
}

function safeFile(value) {
  return (value || "item").replace(/[^a-z0-9-_]/gi, "-").toLowerCase();
}

app.listen(PORT, () => {
  console.log(`PUtrace running on port ${PORT}`);
});
